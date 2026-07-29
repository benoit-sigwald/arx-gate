'use strict';
/*
 * arx-gate — porte d'accès + capture de prospects, un schéma Oracle par site.
 *
 * Parcours : visiteur → formulaire (nom, prénom, email, téléphone, société, intérêt, RGPD)
 *   → email de vérification → notification ntfy avec boutons Approuver / Refuser
 *   → si approuvé : lien d'accès par email, cookie signé 90 jours.
 *
 * Sert aussi le beacon du tracker : /t.js et POST /t écrivent dans le schéma du site
 * (VISITS.prospect_id est renseigné quand le visiteur est identifié).
 *
 * Env : ORA_CONNECT, ORA_WALLET_B64, ORA_WALLET_PASSWORD, ORA_WALLET_DIR,
 *       SITES_B64 (json {slug:{user,password}}), GATE_SECRET, ADMIN_KEY,
 *       PUBLIC_URL, NTFY_URL, NTFY_TOPIC, SMTP_USER, SMTP_PASS, BASE_PATH, PORT
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

// ---------- wallet ----------
const WALLET_DIR = process.env.ORA_WALLET_DIR || '/tmp/wallet';
if (process.env.ORA_WALLET_B64 && !fs.existsSync(path.join(WALLET_DIR, 'tnsnames.ora'))) {
  const AdmZip = require('adm-zip');
  fs.mkdirSync(WALLET_DIR, { recursive: true });
  new AdmZip(Buffer.from(process.env.ORA_WALLET_B64, 'base64')).extractAllTo(WALLET_DIR, true);
  console.log('[boot] wallet extrait');
}

// ---------- config ----------
const SITES = JSON.parse(Buffer.from(process.env.SITES_B64 || '', 'base64').toString() || '{}');
const SECRET = process.env.GATE_SECRET || 'dev-secret';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const NTFY_URL = (process.env.NTFY_URL || '').replace(/\/$/, '');
const NTFY_TOPIC = process.env.NTFY_TOPIC || 'arx-prospects';
const EMAIL_ON = !!(process.env.SMTP_USER && process.env.SMTP_PASS);
const SITE_URLS = JSON.parse(Buffer.from(process.env.SITE_URLS_B64 || '', 'base64').toString() || '{}');

// ---------- db : un pool par site ----------
const oracledb = require('oracledb');
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
const pools = {};
async function pool(site) {
  const cfg = SITES[site];
  if (!cfg) throw new Error('site inconnu: ' + site);
  if (!pools[site]) {
    pools[site] = await oracledb.createPool({
      user: cfg.user, password: cfg.password,
      connectString: process.env.ORA_CONNECT,
      configDir: WALLET_DIR, walletLocation: WALLET_DIR,
      walletPassword: process.env.ORA_WALLET_PASSWORD,
      poolMin: 0, poolMax: 3, poolTimeout: 120,
    });
  }
  return pools[site];
}
async function q(site, sql, binds = {}, opts = {}) {
  const c = await (await pool(site)).getConnection();
  try { return await c.execute(sql, binds, { autoCommit: true, ...opts }); }
  finally { await c.close(); }
}

// ---------- helpers ----------
const tok = () => crypto.randomBytes(24).toString('hex');
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
const cut = (s, n) => (s == null || s === '' ? null : String(s).slice(0, n));
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  return xff ? String(xff).split(',')[0].trim() : (req.socket.remoteAddress || '');
}
function parseUa(ua = '') {
  const browser = /edg\//i.test(ua) ? 'Edge' : /opr\//i.test(ua) ? 'Opera' : /chrome|crios/i.test(ua) ? 'Chrome'
    : /firefox|fxios/i.test(ua) ? 'Firefox' : /safari/i.test(ua) ? 'Safari'
    : /curl|wget|bot|crawler|spider|slurp|preview/i.test(ua) ? 'Bot' : 'Other';
  const os = /windows/i.test(ua) ? 'Windows' : /android/i.test(ua) ? 'Android'
    : /iphone|ipad|ios/i.test(ua) ? 'iOS' : /mac os/i.test(ua) ? 'macOS' : /linux/i.test(ua) ? 'Linux' : 'Other';
  return { browser, os, device: /mobile|android|iphone/i.test(ua) ? 'mobile' : 'desktop' };
}
const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fc|fe80)/;
const geoCache = new Map();
async function geo(ip) {
  if (!ip || PRIVATE_IP.test(ip)) return {};
  const hit = geoCache.get(ip);
  if (hit && Date.now() - hit.at < 24 * 3600e3) return hit.data;
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,lat,lon`,
      { signal: AbortSignal.timeout(4000) });
    const j = await r.json();
    const data = j.status === 'success'
      ? { country: j.country, region: j.regionName, city: j.city, isp: j.isp, org: j.org, asn: j.as, lat: j.lat, lon: j.lon }
      : {};
    geoCache.set(ip, { data, at: Date.now() });
    return data;
  } catch { return {}; }
}
const ascii = s => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^ -~]/g, '');
async function ntfy(title, message, actions, priority) {
  if (!NTFY_URL) return;
  try {
    const h = { Title: ascii(title), Priority: priority || 'default', Tags: 'bust_in_silhouette' };
    if (actions) h.Actions = ascii(actions);
    await fetch(`${NTFY_URL}/${NTFY_TOPIC}`, { method: 'POST', headers: h, body: message, signal: AbortSignal.timeout(6000) });
  } catch (e) { console.error('ntfy:', e.message); }
}
let mailer = null;
async function sendMail(to, subject, html) {
  if (!EMAIL_ON) { console.log('[mail off]', to, subject); return false; }
  if (!mailer) {
    const nodemailer = require('nodemailer');
    mailer = nodemailer.createTransport({
      host: 'smtp.gmail.com', port: 465, secure: true,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  }
  try {
    await mailer.sendMail({ from: `"Arx Capital" <${process.env.SMTP_USER}>`, to, subject, html });
    return true;
  } catch (e) { console.error('mail:', e.message); return false; }
}

// site d'une requête protégée : arx-sites.duckdns.org/<site>/... → <site>
function siteFromForward(req) {
  const uri = req.headers['x-forwarded-uri'] || '/';
  const seg = uri.split('?')[0].split('/').filter(Boolean)[0];
  return seg && SITES[seg] ? seg : null;
}
function siteUrl(site) {
  return SITE_URLS[site] || `https://arx-sites.duckdns.org/${site}/`;
}
// duckdns.org est un « public suffix » : impossible de partager un cookie entre sous-domaines.
// Le lien d'accès pointe donc vers la porte servie sur l'hôte du site, qui y pose un cookie d'hôte.
function gateBase(site) {
  try { return new URL(siteUrl(site)).origin + '/gate'; } catch { return PUBLIC_URL; }
}

// ---------- cookie de session ----------
const COOKIE = 'arxgate';
function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  const found = raw.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : null;
}
function makeCookieValue(site, prospectId, token) {
  const body = `${site}.${prospectId}.${token}`;
  return `${body}.${sign(body)}`;
}
function parseCookieValue(v) {
  if (!v) return null;
  const parts = v.split('.');
  if (parts.length !== 4) return null;
  const [site, id, token, sig] = parts;
  if (sign(`${site}.${id}.${token}`) !== sig) return null;
  return { site, id: Number(id), token };
}

// ---------- app ----------
const app = express();
app.set('trust proxy', true);
const router = express.Router();
const form = express.urlencoded({ extended: false, limit: '16kb' });

const PAGE = (title, body) => `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(title)} — Arx Capital</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--navy:#1b354d;--gold:#ae8d57;--border:#e4e8ef;--muted:#5b6472}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f8fb;color:#14202e;line-height:1.6;
 display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.box{background:#fff;border:1px solid var(--border);border-radius:16px;max-width:560px;width:100%;
 padding:36px;box-shadow:0 8px 32px rgba(27,53,77,.10)}
h1{font-family:"Playfair Display",Georgia,serif;font-size:1.6rem;color:var(--navy);margin-bottom:8px}
p.sub{color:var(--muted);font-size:.95rem;margin-bottom:24px}
label{display:block;font-size:.8rem;font-weight:600;color:var(--navy);margin:14px 0 4px}
input,select{width:100%;padding:11px 13px;border:1px solid var(--border);border-radius:9px;font-size:.95rem;font-family:inherit}
input:focus,select:focus{outline:none;border-color:var(--gold)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:520px){.row{grid-template-columns:1fr}}
.consent{display:flex;gap:10px;align-items:flex-start;margin-top:20px;font-size:.82rem;color:var(--muted)}
.consent input{width:auto;margin-top:3px}
button{width:100%;margin-top:22px;padding:13px;border:none;border-radius:9px;background:var(--navy);color:#fff;
 font-weight:700;font-size:.95rem;cursor:pointer;font-family:inherit}
button:hover{background:#2c4a68}
.err{background:#fdecec;border:1px solid #f5c2c2;color:#8a2020;padding:10px 14px;border-radius:9px;font-size:.88rem;margin-bottom:16px}
.ok{font-size:2.4rem;margin-bottom:10px}
a{color:var(--gold)}
small{color:var(--muted);font-size:.76rem;display:block;margin-top:18px}
.lang{position:absolute;top:14px;right:16px;font-size:.78rem;font-weight:600;text-decoration:none;
 color:var(--navy);border:1px solid var(--border);border-radius:8px;padding:4px 10px;background:#fff}
.lang:hover{border-color:var(--gold);color:var(--gold)}
.box{position:relative}
</style></head><body><div class="box">${body}</div></body></html>`;

const BASE_ABS = (process.env.BASE_PATH && process.env.BASE_PATH !== '/') ? process.env.BASE_PATH.replace(/\/$/, '') : '';
// ---------- traductions ----------
const T = {
  fr: {
    title: 'Accès', h1: 'Accès réservé',
    sub: "Cet espace est privé. Présentez-vous en quelques secondes : vous recevrez un email de confirmation, puis votre accès sera activé après validation.",
    first: 'Prénom', last: 'Nom', email: 'Email professionnel', phone: 'Téléphone', company: 'Société',
    interest: 'Objet de votre visite', choose: '— choisir —', submit: "Demander l'accès",
    consent: "J'accepte que mes données (nom, email, téléphone, société) soient conservées par Arx Capital pour gérer mon accès et me recontacter. Elles ne sont ni vendues ni transmises à des tiers. Droit d'accès et de suppression : benoit.p.g.sigwald@gmail.com.",
    foot: 'Arx Capital · Mougins, France · données hébergées en France (Oracle Cloud, Paris)',
    err: 'Merci de remplir tous les champs, un email valide et le consentement.',
    errTech: 'Erreur technique, réessayez dans un instant.',
    waitTitle: 'Demande enregistrée', waitH1: 'Demande enregistrée',
    waitSub: "Votre demande est en cours de validation. Gardez cette page ouverte : elle s'ouvrira automatiquement dès l'accord, en général en quelques minutes.",
    waitPending: 'Validation en attente…', waitGranted: 'Accès accordé, ouverture…', waitRejected: 'Demande refusée.',
    mailTitle: 'Vérifiez vos emails', mailH1: 'Vérifiez vos emails',
    mailSub: 'Un lien de confirmation vient d\'être envoyé à', mailSub2: 'Cliquez dessus pour poursuivre.',
    okTitle: 'Email confirmé', okH1: 'Email confirmé',
    okSub: 'votre accès est en cours de validation ; vous recevrez le lien dès qu\'il est activé.',
    badTitle: 'Lien invalide', badH1: 'Lien invalide ou expiré',
    interests: ['Mission de conseil', 'Recrutement', 'Partenariat', 'Investissement', 'Curiosité / veille'],
    other: 'English',
    rgpd: 'Merci d\'accepter la conservation de vos données pour continuer.',
    rgpdTitle: 'Consentement requis',
  },
  en: {
    title: 'Access', h1: 'Private access',
    sub: 'This area is private. Introduce yourself in a few seconds: you will get a confirmation email, then your access is activated after approval.',
    first: 'First name', last: 'Last name', email: 'Work email', phone: 'Phone', company: 'Company',
    interest: 'Purpose of your visit', choose: '- select -', submit: 'Request access',
    consent: 'I agree that my data (name, email, phone, company) is kept by Arx Capital to manage my access and to contact me. It is never sold or shared with third parties. Access and deletion rights: benoit.p.g.sigwald@gmail.com.',
    foot: 'Arx Capital - Mougins, France - data hosted in France (Oracle Cloud, Paris)',
    err: 'Please fill in every field, a valid email and the consent box.',
    errTech: 'Technical error, please try again in a moment.',
    waitTitle: 'Request received', waitH1: 'Request received',
    waitSub: 'Your request is being reviewed. Keep this page open: it will open automatically once approved, usually within minutes.',
    waitPending: 'Waiting for approval...', waitGranted: 'Access granted, opening...', waitRejected: 'Request declined.',
    mailTitle: 'Check your inbox', mailH1: 'Check your inbox',
    mailSub: 'A confirmation link has just been sent to', mailSub2: 'Click it to continue.',
    okTitle: 'Email confirmed', okH1: 'Email confirmed',
    okSub: 'Your access is being reviewed; you will get the link as soon as it is activated.',
    badTitle: 'Invalid link', badH1: 'Invalid or expired link',
    interests: ['Consulting engagement', 'Recruitment', 'Partnership', 'Investment', 'Curiosity / research'],
    other: 'Français',
    rgpd: 'Please accept the data notice to continue.',
    rgpdTitle: 'Consent required',
  },
};
const lang = req => (String(req.query.lang || '').toLowerCase() === 'en'
  || (!req.query.lang && /^en/i.test(String(req.headers['accept-language'] || '')))) ? 'en' : 'fr';

function waitingPage(site, vtoken) {
  return PAGE('Demande enregistrée', `<div class="ok">⏳</div><h1>Demande enregistrée</h1>
  <p class="sub">Votre demande est en cours de validation. Gardez cette page ouverte :
  elle s'ouvrira automatiquement dès l'accord, en général en quelques minutes.</p>
  <p class="sub" id="st" style="color:var(--gold)">Validation en attente…</p>
  <script>
  (function(){
    var n = 0;
    function check(){
      fetch('${BASE_ABS}/status?site=${encodeURIComponent(site)}&t=${vtoken}')
        .then(function(r){ return r.json(); })
        .then(function(j){
          if (j.link) { document.getElementById('st').textContent = 'Accès accordé, ouverture…'; location.href = j.link; return; }
          if (j.status === 'rejected') { document.getElementById('st').textContent = 'Demande refusée.'; return; }
          if (++n < 240) setTimeout(check, 5000);
        })
        .catch(function(){ if (++n < 240) setTimeout(check, 8000); });
    }
    setTimeout(check, 4000);
  })();
  </script>`);
}

function langLink(l, extra = '') {
  return `<a class="lang" href="?lang=${l === 'fr' ? 'en' : 'fr'}${extra}">${T[l].other}</a>`;
}

function formPage(site, rd, err, prefill = {}, l = 'fr') {
  const t = T[l];
  const opts = t.interests.map(i => `<option${prefill.interest === i ? ' selected' : ''}>${esc(i)}</option>`).join('');
  const extra = `&site=${encodeURIComponent(site)}${rd ? '&rd=' + encodeURIComponent(rd) : ''}`;
  return PAGE(t.title, `
  ${langLink(l, extra)}
  <h1>${esc(t.h1)}</h1>
  <p class="sub">${esc(t.sub)}</p>
  ${err ? `<div class="err">${esc(err)}</div>` : ''}
  <form method="post" action="${BASE_ABS}/register">
    <input type="hidden" name="site" value="${esc(site)}"><input type="hidden" name="rd" value="${esc(rd || '')}">
    <input type="hidden" name="lang" value="${l}">
    <div class="row">
      <div><label>${esc(t.first)} *</label><input name="first_name" required maxlength="80" value="${esc(prefill.first_name || '')}"></div>
      <div><label>${esc(t.last)} *</label><input name="last_name" required maxlength="80" value="${esc(prefill.last_name || '')}"></div>
    </div>
    <label>${esc(t.email)} *</label>
    <input type="email" name="email" required maxlength="160" value="${esc(prefill.email || '')}">
    <div class="row">
      <div><label>${esc(t.phone)} *</label><input type="tel" name="phone" required maxlength="40" placeholder="+33 6 12 34 56 78" value="${esc(prefill.phone || '')}"></div>
      <div><label>${esc(t.company)} *</label><input name="company" required maxlength="160" value="${esc(prefill.company || '')}"></div>
    </div>
    <label>${esc(t.interest)} *</label>
    <select name="interest" required><option value="">${esc(t.choose)}</option>${opts}</select>
    <div class="consent">
      <input type="checkbox" name="consent" id="c" required>
      <label for="c" style="font-weight:400;margin:0;font-size:.82rem;color:var(--muted)">${esc(t.consent)}</label>
    </div>
    <button type="submit">${esc(t.submit)}</button>
  </form>
  <div id="rgpd-modal" hidden style="position:fixed;inset:0;background:rgba(27,53,77,.65);display:flex;
       align-items:center;justify-content:center;padding:24px;z-index:50">
    <div style="background:#fff;border-radius:14px;padding:28px;max-width:420px;text-align:center;
         box-shadow:0 20px 60px rgba(0,0,0,.3)">
      <div style="font-size:2rem;margin-bottom:8px">&#128274;</div>
      <h1 style="font-size:1.15rem;margin-bottom:8px">${esc(t.rgpdTitle)}</h1>
      <p class="sub" style="margin-bottom:18px">${esc(t.rgpd)}</p>
      <button type="button" id="rgpd-ok" style="margin:0">OK</button>
    </div>
  </div>
  <script>
  (function(){
    var f = document.querySelector('form'), c = document.getElementById('c'),
        m = document.getElementById('rgpd-modal');
    c.addEventListener('invalid', function(e){ e.preventDefault(); });
    f.addEventListener('submit', function(e){
      if (!c.checked) { e.preventDefault(); m.hidden = false; }
    });
    document.getElementById('rgpd-ok').addEventListener('click', function(){ m.hidden = true; c.focus(); });
    m.addEventListener('click', function(e){ if (e.target === m) m.hidden = true; });
  })();
  </script>
  <small>${esc(t.foot)}</small>`);
}

function waitingPage(site, vtoken, l = 'fr') {
  const t = T[l];
  return PAGE(t.waitTitle, `<div class="ok">&#9203;</div><h1>${esc(t.waitH1)}</h1>
  <p class="sub">${esc(t.waitSub)}</p>
  <p class="sub" id="st" style="color:var(--gold)">${esc(t.waitPending)}</p>
  <script>
  (function(){
    var n = 0;
    function check(){
      fetch('${BASE_ABS}/status?site=${encodeURIComponent(site)}&t=${vtoken}')
        .then(function(r){ return r.json(); })
        .then(function(j){
          if (j.link) { document.getElementById('st').textContent = ${JSON.stringify(t.waitGranted)}; location.href = j.link; return; }
          if (j.status === 'rejected') { document.getElementById('st').textContent = ${JSON.stringify(t.waitRejected)}; return; }
          if (++n < 240) setTimeout(check, 5000);
        })
        .catch(function(){ if (++n < 240) setTimeout(check, 8000); });
    }
    setTimeout(check, 4000);
  })();
  </script>`);
}

// ---- forwardauth ----
router.get('/auth', async (req, res) => {
  // le site vient du middleware Traefik (?site=…) ; sinon on le déduit du chemin d'origine
  const site = SITES[req.query.site] ? req.query.site : siteFromForward(req);
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || '';
  const uri = req.headers['x-forwarded-uri'] || '/';
  // page exacte demandee : soit /<site>/…, soit n'importe quel chemin sur l'hote propre du site
  let rd = siteUrl(site);
  if (site) {
    let sameHost = false;
    try { sameHost = new URL(siteUrl(site)).host === host; } catch {}
    if (uri.startsWith('/' + site) || sameHost) rd = `${proto}://${host}${uri}`;
  }
  if (!site) return res.sendStatus(200); // chemin non protégé
  const c = parseCookieValue(readCookie(req, COOKIE));
  if (c && c.site === site) {
    try {
      const r = await q(site, `SELECT p.id, p.status FROM sessions s JOIN prospects p ON p.id = s.prospect_id
        WHERE s.token = :t AND s.revoked = 0 AND s.expires_at > SYSTIMESTAMP`, { t: c.token });
      if (r.rows.length && r.rows[0].STATUS === 'approved') {
        res.set('X-Prospect-Id', String(r.rows[0].ID));
        return res.sendStatus(200);
      }
    } catch (e) { console.error('auth:', e.message); }
  }
  res.redirect(302, `${PUBLIC_URL}/?site=${encodeURIComponent(site)}&rd=${encodeURIComponent(rd)}`);
});

// ---- formulaire ----
router.get('/', (req, res) => {
  const site = SITES[req.query.site] ? req.query.site : Object.keys(SITES)[0];
  res.type('html').send(formPage(site, req.query.rd, null, {}, lang(req)));
});

// ---- inscription ----
router.post('/register', form, async (req, res) => {
  const b = req.body || {};
  const site = SITES[b.site] ? b.site : null;
  if (!site) return res.status(400).send('site inconnu');
  const l = (String(b.lang || '').toLowerCase() === 'en') ? 'en' : 'fr';
  const email = String(b.email || '').trim().toLowerCase();
  const need = ['first_name', 'last_name', 'phone', 'company', 'interest'];
  const missing = need.some(k => !String(b[k] || '').trim());
  if (!b.consent) {
    return res.type('html').send(formPage(site, b.rd, T[l].rgpd, b, l));
  }
  if (missing || !/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(email)) {
    return res.type('html').send(formPage(site, b.rd, T[l].err, b, l));
  }
  try {
    const ip = clientIp(req), ua = req.headers['user-agent'] || '';
    const { browser, os, device } = parseUa(ua);
    const g = await geo(ip);
    const vtoken = tok(), dtoken = tok();
    const existing = await q(site, 'SELECT id, status FROM prospects WHERE email = :e', { e: email });
    let id;
    if (existing.rows.length) {
      id = existing.rows[0].ID;
      if (existing.rows[0].STATUS === 'approved') {
        // deja approuve : on rouvre l'acces immediatement, sans repasser par la validation
        const t2 = tok();
        await q(site, `INSERT INTO sessions (prospect_id, token, expires_at) VALUES (:id, :t, SYSTIMESTAMP + INTERVAL '90' DAY)`,
          { id, t: t2 });
        if (b.rd) await q(site, 'UPDATE prospects SET landing = :l WHERE id = :id', { l: cut(b.rd, 512), id });
        return res.redirect(302, `${gateBase(site)}/access?t=${t2}&site=${encodeURIComponent(site)}`);
      }
      await q(site, `UPDATE prospects SET first_name=:f, last_name=:l, phone=:p, company=:c, interest=:i,
        verify_token=:v, decision_token=:d, status='pending',
        signup_ip=:ip, country=:country, region=:region, city=:city, org=:org, isp=:isp, asn=:asn,
        lat=:lat, lon=:lon, browser=:browser, os=:os, device=:device WHERE id=:id`,
        { f: cut(b.first_name, 80), l: cut(b.last_name, 80), p: cut(b.phone, 40), c: cut(b.company, 160),
          i: cut(b.interest, 60), v: vtoken, d: dtoken,
          ip: cut(ip, 64), country: cut(g.country, 64), region: cut(g.region, 64), city: cut(g.city, 64),
          org: cut(g.org, 160), isp: cut(g.isp, 160), asn: cut(g.asn, 64),
          lat: g.lat ?? null, lon: g.lon ?? null, browser, os, device, id });
    } else {
      const r = await q(site, `INSERT INTO prospects
        (first_name,last_name,email,phone,company,interest,status,consent_rgpd,consent_at,verify_token,decision_token,
         site,signup_ip,country,region,city,org,isp,asn,browser,os,device,lang,referrer,landing,utm_source,utm_medium,utm_campaign,lat,lon)
        VALUES (:f,:l,:e,:p,:c,:i,'pending',1,SYSTIMESTAMP,:v,:d,:site,:ip,:country,:region,:city,:org,:isp,:asn,
                :browser,:os,:device,:lang,:ref,:landing,:us,:um,:uc,:lat,:lon)
        RETURNING id INTO :id`,
        { f: cut(b.first_name, 80), l: cut(b.last_name, 80), e: cut(email, 160), p: cut(b.phone, 40),
          c: cut(b.company, 160), i: cut(b.interest, 60), v: vtoken, d: dtoken, site,
          ip: cut(ip, 64), country: cut(g.country, 64), region: cut(g.region, 64), city: cut(g.city, 64),
          org: cut(g.org, 160), isp: cut(g.isp, 160), asn: cut(g.asn, 64),
          browser, os, device, lang: cut((req.headers['accept-language'] || '').split(',')[0], 32),
          ref: cut(req.headers.referer, 512), landing: cut(b.rd, 512),
          us: cut(b.utm_source, 80), um: cut(b.utm_medium, 80), uc: cut(b.utm_campaign, 80),
          lat: g.lat ?? null, lon: g.lon ?? null,
          id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER } });
      id = r.outBinds.id[0];
    }
    await q(site, `INSERT INTO access_log (prospect_id, event, path, ip, ua) VALUES (:id,'signup',:p,:ip,:ua)`,
      { id, p: cut(b.rd, 512), ip: cut(ip, 64), ua: cut(ua, 512) });

    const who = `${b.first_name} ${b.last_name} · ${b.company}\n${email} · ${b.phone}\nObjet : ${b.interest}\nSite : ${site} · ${g.city || '?'}, ${g.country || '?'} · ${g.org || g.isp || '?'}`;

    if (EMAIL_ON) {
      const link = `${PUBLIC_URL}/verify?t=${vtoken}&site=${encodeURIComponent(site)}`;
      await sendMail(email, 'Confirmez votre demande d\'accès — Arx Capital',
        `<p>Bonjour ${esc(b.first_name)},</p><p>Merci de votre intérêt. Confirmez votre adresse en cliquant ici :</p>
         <p><a href="${link}" style="background:#1b354d;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none">Confirmer mon email</a></p>
         <p style="color:#666;font-size:13px">Votre accès sera activé après validation manuelle. Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.</p>`);
      await ntfy('Nouvelle demande (email à confirmer)', who);
      return res.type('html').send(PAGE(T[l].mailTitle, `<div class="ok">&#128233;</div><h1>${esc(T[l].mailH1)}</h1>
        <p class="sub">${esc(T[l].mailSub)} <b>${esc(email)}</b>. ${esc(T[l].mailSub2)}</p>`));
    }
    // sans SMTP : on passe directement à la validation manuelle
    await q(site, `UPDATE prospects SET status='email_verified', verified_at=SYSTIMESTAMP WHERE id=:id`, { id });
    await ntfy('Nouvelle demande d\'accès', who,
      `http, Approuver, ${PUBLIC_URL}/approve?t=${dtoken}&site=${site}, method=POST, clear=true; http, Refuser, ${PUBLIC_URL}/reject?t=${dtoken}&site=${site}, method=POST, clear=true`,
      'high');
    return res.type('html').send(waitingPage(site, vtoken, l));
  } catch (e) {
    console.error('register:', e);
    res.status(500).type('html').send(formPage(site, b.rd, T[l].errTech, b, l));
  }
});

// ---- vérification email ----
router.get('/verify', async (req, res) => {
  const site = SITES[req.query.site] ? req.query.site : null;
  if (!site || !req.query.t) return res.status(400).send('lien invalide');
  try {
    const r = await q(site, `SELECT id, first_name, last_name, email, phone, company, interest, city, country, org, isp, decision_token, status
      FROM prospects WHERE verify_token = :t`, { t: req.query.t });
    const lv = lang(req);
    if (!r.rows.length) return res.status(400).type('html').send(PAGE(T[lv].badTitle, `<h1>${esc(T[lv].badH1)}</h1>`));
    const p = r.rows[0];
    if (p.STATUS === 'pending') {
      await q(site, `UPDATE prospects SET status='email_verified', verified_at=SYSTIMESTAMP WHERE id=:id`, { id: p.ID });
      await ntfy('Email confirmé — à valider',
        `${p.FIRST_NAME} ${p.LAST_NAME} · ${p.COMPANY}\n${p.EMAIL} · ${p.PHONE}\nObjet : ${p.INTEREST}\nSite : ${site} · ${p.CITY || '?'}, ${p.COUNTRY || '?'} · ${p.ORG || p.ISP || '?'}`,
        `http, Approuver, ${PUBLIC_URL}/approve?t=${p.DECISION_TOKEN}&site=${site}, method=POST, clear=true; http, Refuser, ${PUBLIC_URL}/reject?t=${p.DECISION_TOKEN}&site=${site}, method=POST, clear=true`,
        'high');
    }
    res.type('html').send(PAGE(T[lv].okTitle, `<div class="ok">&#9989;</div><h1>${esc(T[lv].okH1)}</h1>
      <p class="sub">${esc(p.FIRST_NAME)} - ${esc(T[lv].okSub)}</p>`));
  } catch (e) { console.error('verify:', e); res.status(500).send('erreur'); }
});

// ---- statut (sondage depuis la page d'attente) ----
router.get('/status', async (req, res) => {
  const site = SITES[req.query.site] ? req.query.site : null;
  if (!site || !req.query.t) return res.json({ status: 'unknown' });
  try {
    const r = await q(site, 'SELECT id, status FROM prospects WHERE verify_token = :t', { t: req.query.t });
    if (!r.rows.length) return res.json({ status: 'unknown' });
    const p = r.rows[0];
    if (p.STATUS !== 'approved') return res.json({ status: p.STATUS });
    const sess = await q(site, `SELECT token FROM sessions WHERE prospect_id = :id AND revoked = 0
      AND expires_at > SYSTIMESTAMP ORDER BY created_at DESC FETCH FIRST 1 ROWS ONLY`, { id: p.ID });
    let t = sess.rows.length ? sess.rows[0].TOKEN : null;
    if (!t) {
      t = tok();
      await q(site, `INSERT INTO sessions (prospect_id, token, expires_at) VALUES (:id, :t, SYSTIMESTAMP + INTERVAL '90' DAY)`, { id: p.ID, t });
    }
    res.json({ status: 'approved', link: `${gateBase(site)}/access?t=${t}&site=${encodeURIComponent(site)}` });
  } catch (e) { console.error('status:', e.message); res.json({ status: 'error' }); }
});

// ---- décision (boutons ntfy) ----
async function decide(req, res, approve) {
  const site = SITES[req.query.site] ? req.query.site : null;
  if (!site || !req.query.t) return res.status(400).send('lien invalide');
  try {
    const r = await q(site, 'SELECT id, first_name, email, status FROM prospects WHERE decision_token = :t', { t: req.query.t });
    if (!r.rows.length) {
      console.log(`[decision] jeton inconnu (site ${site}) — deja traite ou prospect supprime`);
      return res.status(200).send('deja traite ou expire');
    }
    const p = r.rows[0];
    console.log(`[decision] ${approve ? 'APPROUVE' : 'REFUSE'} — ${p.EMAIL} (site ${site}, statut ${p.STATUS})`);
    if (!approve) {
      await q(site, `UPDATE prospects SET status='rejected', decided_at=SYSTIMESTAMP WHERE id=:id`, { id: p.ID });
      return res.send('refuse');
    }
    await q(site, `UPDATE prospects SET status='approved', decided_at=SYSTIMESTAMP WHERE id=:id`, { id: p.ID });
    const t = tok();
    await q(site, `INSERT INTO sessions (prospect_id, token, expires_at) VALUES (:id, :t, SYSTIMESTAMP + INTERVAL '90' DAY)`,
      { id: p.ID, t });
    const link = `${gateBase(site)}/access?t=${t}&site=${encodeURIComponent(site)}`;
    const sent = await sendMail(p.EMAIL, 'Votre accès est activé — Arx Capital',
      `<p>Bonjour ${esc(p.FIRST_NAME)},</p><p>Votre accès est activé. Cliquez pour entrer :</p>
       <p><a href="${link}" style="background:#1b354d;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none">Accéder au site</a></p>
       <p style="color:#666;font-size:13px">Ce lien ouvre votre accès pour 90 jours sur cet appareil.</p>`);
    if (!sent) await ntfy('Accès approuvé — lien à transmettre', `${p.EMAIL}\n${link}`);
    res.send('approuve');
  } catch (e) { console.error('decide:', e); res.status(500).send('erreur'); }
}
router.post('/approve', (req, res) => decide(req, res, true));
router.post('/reject', (req, res) => decide(req, res, false));
router.get('/approve', (req, res) => decide(req, res, true));
router.get('/reject', (req, res) => decide(req, res, false));

// ---- activation du cookie ----
router.get('/access', async (req, res) => {
  const site = SITES[req.query.site] ? req.query.site : null;
  if (!site || !req.query.t) return res.status(400).send('lien invalide');
  try {
    const r = await q(site, `SELECT s.prospect_id, p.status, p.landing FROM sessions s JOIN prospects p ON p.id = s.prospect_id
      WHERE s.token = :t AND s.revoked = 0 AND s.expires_at > SYSTIMESTAMP`, { t: req.query.t });
    if (!r.rows.length || r.rows[0].STATUS !== 'approved')
      return res.status(403).type('html').send(PAGE(T[lang(req)].badTitle, `<h1>${esc(T[lang(req)].badH1)}</h1>`));
    const id = r.rows[0].PROSPECT_ID;
    await q(site, `INSERT INTO access_log (prospect_id, event, path, ip, ua) VALUES (:id,'login',:p,:ip,:ua)`,
      { id, p: cut(req.originalUrl, 512), ip: cut(clientIp(req), 64), ua: cut(req.headers['user-agent'], 512) });
    // on renvoie le visiteur sur la page exacte qu'il demandait, si elle appartient bien au site
    let dest = siteUrl(site);
    const landing = r.rows[0].LANDING;
    if (landing) {
      try {
        const l = new URL(landing), base = new URL(siteUrl(site));
        if (l.origin === base.origin && l.pathname.startsWith(base.pathname.replace(/\/$/, ''))) dest = l.href;
      } catch {}
    }
    res.set('Set-Cookie', `${COOKIE}=${encodeURIComponent(makeCookieValue(site, id, req.query.t))}; Path=/; Max-Age=7776000; HttpOnly; Secure; SameSite=Lax`);
    res.redirect(302, dest);
  } catch (e) { console.error('access:', e); res.status(500).send('erreur'); }
});

// ---- beacon tracker (par site) ----
const BEACON = `(function(){
  var s=document.currentScript,site=(s&&s.getAttribute('data-site'))||location.hostname;
  var ep=(s&&s.src)?s.src.replace(/t\\.js.*$/,'t'):'/t';
  var p={site:site,page:location.pathname+location.search,ref:document.referrer||'',
         lang:navigator.language||'',screen:screen.width+'x'+screen.height};
  try{
    if(navigator.sendBeacon){navigator.sendBeacon(ep,JSON.stringify(p));}
    else{fetch(ep,{method:'POST',body:JSON.stringify(p),keepalive:true,credentials:'include'});}
  }catch(e){}
})();`;
router.get('/t.js', (req, res) => res.type('application/javascript').send(BEACON));
router.post('/t', express.text({ type: '*/*', limit: '2kb' }), async (req, res) => {
  res.sendStatus(204);
  try {
    let b = req.body;
    if (typeof b === 'string') { try { b = JSON.parse(b || '{}'); } catch { b = {}; } }
    if (!b || typeof b !== 'object') b = {};
    // corps envoye en x-www-form-urlencoded contenant du JSON (clef unique)
    if (!b.site && Object.keys(b).length === 1) {
      try { b = JSON.parse(Object.keys(b)[0]); } catch {}
    }
    const site = SITES[b.site] ? b.site : null;
    if (!site) return;
    const ip = clientIp(req), ua = req.headers['user-agent'] || '';
    const { browser, os, device } = parseUa(ua);
    const g = await geo(ip);
    const c = parseCookieValue(readCookie(req, COOKIE));
    await q(site, `INSERT INTO visits (site,page,referrer,ip,ua,browser,os,device,country,region,city,org,isp,asn,lang,screen,lat,lon,prospect_id)
      VALUES (:site,:page,:referrer,:ip,:ua,:browser,:os,:device,:country,:region,:city,:org,:isp,:asn,:lang,:screen,:lat,:lon,:pid)`, {
      site: cut(b.site, 64), page: cut(b.page, 512), referrer: cut(b.ref, 512), ip: cut(ip, 64), ua: cut(ua, 512),
      browser, os, device, country: cut(g.country, 64), region: cut(g.region, 64), city: cut(g.city, 64),
      org: cut(g.org, 160), isp: cut(g.isp, 160), asn: cut(g.asn, 64),
      lang: cut(b.lang, 32), screen: cut(b.screen, 16), lat: g.lat ?? null, lon: g.lon ?? null,
      pid: (c && c.site === site) ? c.id : null,
    });
  } catch (e) { console.error('beacon:', e.message); }
});

// ---- dashboard ----
function authed(req, res) {
  if (!ADMIN_KEY) { res.status(500).send('ADMIN_KEY absente'); return false; }
  const k = req.query.key || readCookie(req, 'agk');
  if (k === ADMIN_KEY) { res.set('Set-Cookie', `agk=${ADMIN_KEY}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`); return true; }
  res.status(401).send('Unauthorized — ajoutez ?key=…');
  return false;
}
router.get('/admin', async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.query.site] ? req.query.site : Object.keys(SITES)[0];
  try {
    const [pros, stats, last] = await Promise.all([
      q(site, `SELECT p.*, (SELECT COUNT(*) FROM visits v WHERE v.prospect_id = p.id) nb,
                (SELECT MAX(ts) FROM visits v WHERE v.prospect_id = p.id) last_seen,
                (SELECT page FROM (SELECT page FROM visits v WHERE v.prospect_id = p.id ORDER BY ts DESC) WHERE ROWNUM = 1) last_page
               FROM prospects p ORDER BY p.created_at DESC FETCH FIRST 200 ROWS ONLY`),
      q(site, `SELECT COUNT(*) total,
                SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved,
                SUM(CASE WHEN status='email_verified' THEN 1 ELSE 0 END) waiting,
                SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending FROM prospects`),
      q(site, `SELECT COUNT(*) c FROM visits WHERE ts >= SYSTIMESTAMP - INTERVAL '7' DAY`),
    ]);
    const s = stats.rows[0];
    const fmt = t => t ? new Date(t).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—';
    const badge = st => ({ approved: '#1d7a4f', email_verified: '#ae8d57', pending: '#8a8f98', rejected: '#a32d2d' }[st] || '#8a8f98');
    const tabs = Object.keys(SITES).map(x =>
      `<a href="${BASE_ABS}/admin?site=${x}" style="padding:6px 14px;border:1px solid #e4e8ef;border-radius:8px;text-decoration:none;
        color:${x === site ? '#fff' : '#1b354d'};background:${x === site ? '#1b354d' : '#fff'};font-size:.85rem">${esc(x)}</a>`).join(' ');
    const rows = pros.rows.map(p => `<tr onclick="location.href='${BASE_ABS}/prospect?site=${site}&id=${p.ID}'" style="cursor:pointer">
      <td>${fmt(p.CREATED_AT)}</td>
      <td><b>${esc(p.FIRST_NAME)} ${esc(p.LAST_NAME)}</b><br><span class="m">${esc(p.COMPANY || '')}</span></td>
      <td>${esc(p.EMAIL)}<br><span class="m">${esc(p.PHONE || '')}</span></td>
      <td>${esc(p.INTEREST || '')}</td>
      <td>${esc(p.CITY || '')} ${esc(p.COUNTRY || '')}<br><span class="m">${esc(p.ORG || p.ISP || '')}</span></td>
      <td><span style="color:${badge(p.STATUS)};font-weight:600">${esc(p.STATUS)}</span></td>
      <td><b>${p.NB || 0}</b> visite(s)<br><span class="m">${p.NB ? 'derniere ' + fmt(p.LAST_SEEN) : '-'}</span></td>
      <td class="m">${esc(p.LAST_PAGE || '-')}<br><span class="m">${esc(p.BROWSER || '')} ${esc(p.DEVICE || '')}</span></td>
      <td onclick="event.stopPropagation()">${p.LAT != null ? `<a href="https://maps.google.com/?q=${p.LAT},${p.LON}" target="_blank" rel="noopener" title="${esc(p.LAT + ', ' + p.LON)}">carte</a>` : '-'}</td></tr>`).join('');
    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Prospects — ${esc(site)}</title><style>
body{font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f8fb;color:#14202e;padding:28px 20px;margin:0}
.w{max-width:1200px;margin:0 auto}h1{font-size:1.4rem;margin:0 0 4px;color:#1b354d}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.tile{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:16px}
.tile b{display:block;font-size:1.6rem;color:#1b354d}.tile span{color:#5b6472;font-size:.8rem}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;border-radius:12px;overflow:hidden;font-size:.85rem}
th{text-align:left;padding:10px 12px;background:#f2f5f9;color:#1b354d;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
td{padding:10px 12px;border-top:1px solid #e4e8ef;vertical-align:top}
.m{color:#5b6472;font-size:.78rem}a{color:#ae8d57}
</style></head><body><div class="w">
<h1>Prospects</h1><p class="m">Schéma Oracle dédié par site · <a href="${BASE_ABS}/export.csv?site=${site}&key=${encodeURIComponent(req.query.key || ADMIN_KEY)}">export CSV</a></p>
<div style="margin:14px 0">${tabs}</div>
<div class="tiles">
  <div class="tile"><b>${s.TOTAL || 0}</b><span>prospects</span></div>
  <div class="tile"><b>${s.APPROVED || 0}</b><span>approuvés</span></div>
  <div class="tile"><b>${s.WAITING || 0}</b><span>en attente de validation</span></div>
  <div class="tile"><b>${s.PENDING || 0}</b><span>email non confirmé</span></div>
  <div class="tile"><b>${last.rows[0].C}</b><span>visites 7 jours</span></div>
</div>
<table><thead><tr><th>Inscrit</th><th>Personne</th><th>Contact</th><th>Objet</th><th>Lieu / organisation</th><th>Statut</th><th>Visites</th><th>Derniere page</th><th>Geo</th></tr></thead>
<tbody>${rows || '<tr><td colspan="9">Aucun prospect pour ce site.</td></tr>'}</tbody></table>
<p class="m" style="margin-top:10px">Cliquez une ligne pour voir tout le parcours de visite du prospect.</p>
</div></body></html>`);
  } catch (e) { console.error('admin:', e); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.get('/prospect', async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.query.site] ? req.query.site : null;
  const id = Number(req.query.id);
  if (!site || !id) return res.status(400).send('parametres manquants');
  try {
    const [pr, vis, acc, agg] = await Promise.all([
      q(site, 'SELECT * FROM prospects WHERE id = :id', { id }),
      q(site, 'SELECT * FROM visits WHERE prospect_id = :id ORDER BY ts DESC FETCH FIRST 300 ROWS ONLY', { id }),
      q(site, 'SELECT * FROM access_log WHERE prospect_id = :id ORDER BY ts DESC FETCH FIRST 50 ROWS ONLY', { id }),
      q(site, `SELECT page, COUNT(*) c, MAX(ts) last_ts FROM visits WHERE prospect_id = :id
               GROUP BY page ORDER BY COUNT(*) DESC FETCH FIRST 15 ROWS ONLY`, { id }),
    ]);
    if (!pr.rows.length) return res.status(404).send('prospect inconnu');
    const p = pr.rows[0];
    const fmt = t => t ? new Date(t).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-';
    const first = vis.rows.length ? vis.rows[vis.rows.length - 1].TS : null;
    const last = vis.rows.length ? vis.rows[0].TS : null;
    const ll = (p.LAT != null && p.LON != null) ? { LAT: p.LAT, LON: p.LON } : vis.rows.find(v => v.LAT != null);
    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(p.FIRST_NAME)} ${esc(p.LAST_NAME)} - prospect</title><style>
body{font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f8fb;color:#14202e;padding:28px 20px;margin:0}
.w{max-width:1100px;margin:0 auto}h1{font-size:1.4rem;margin:0 0 4px;color:#1b354d}
h2{font-size:1rem;color:#1b354d;margin:26px 0 10px}
.card{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:18px}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.kv div span{display:block;color:#5b6472;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
.kv div b{font-weight:600;font-size:.95rem}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;border-radius:12px;overflow:hidden;font-size:.85rem}
th{text-align:left;padding:9px 12px;background:#f2f5f9;color:#1b354d;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
td{padding:9px 12px;border-top:1px solid #e4e8ef}
.m{color:#5b6472;font-size:.8rem}a{color:#ae8d57}
iframe{width:100%;height:280px;border:0;border-radius:10px}
</style></head><body><div class="w">
<p><a href="${BASE_ABS}/admin?site=${site}">&larr; retour aux prospects (${esc(site)})</a></p>
<h1>${esc(p.FIRST_NAME)} ${esc(p.LAST_NAME)}</h1>
<p class="m">${esc(p.COMPANY || '')} &middot; ${esc(p.INTEREST || '')} &middot; statut <b>${esc(p.STATUS)}</b></p>

<h2>Identite declaree</h2>
<div class="card kv">
  <div><span>Email</span><b>${esc(p.EMAIL)}</b></div>
  <div><span>Telephone</span><b>${esc(p.PHONE || '-')}</b></div>
  <div><span>Societe</span><b>${esc(p.COMPANY || '-')}</b></div>
  <div><span>Inscrit le</span><b>${fmt(p.CREATED_AT)}</b></div>
  <div><span>Email confirme</span><b>${fmt(p.VERIFIED_AT)}</b></div>
  <div><span>Decision</span><b>${fmt(p.DECIDED_AT)}</b></div>
  <div><span>Consentement RGPD</span><b>${p.CONSENT_RGPD ? 'oui - ' + fmt(p.CONSENT_AT) : 'non'}</b></div>
</div>

<h2>Donnees du tracker</h2>
<div class="card kv">
  <div><span>Visites</span><b>${vis.rows.length}</b></div>
  <div><span>Premiere visite</span><b>${fmt(first)}</b></div>
  <div><span>Derniere visite</span><b>${fmt(last)}</b></div>
  <div><span>Ville / pays</span><b>${esc(p.CITY || '-')}, ${esc(p.COUNTRY || '-')}</b></div>
  <div><span>Organisation / FAI</span><b>${esc(p.ORG || p.ISP || '-')}</b></div>
  <div><span>Reseau (ASN)</span><b>${esc(p.ASN || '-')}</b></div>
  <div><span>Coordonnees GPS</span><b>${p.LAT != null ? p.LAT + ', ' + p.LON : (ll ? ll.LAT + ', ' + ll.LON : '-')}</b></div>
  <div><span>IP d'inscription</span><b>${esc(p.SIGNUP_IP || '-')}</b></div>
  <div><span>Appareil</span><b>${esc(p.BROWSER || '')} &middot; ${esc(p.OS || '')} &middot; ${esc(p.DEVICE || '')}</b></div>
  <div><span>Langue</span><b>${esc(p.LANG || '-')}</b></div>
  <div><span>Venu de</span><b>${esc(p.REFERRER || 'acces direct')}</b></div>
  <div><span>Page d'entree</span><b>${esc(p.LANDING || '-')}</b></div>
  <div><span>Campagne</span><b>${esc([p.UTM_SOURCE, p.UTM_MEDIUM, p.UTM_CAMPAIGN].filter(Boolean).join(' / ') || '-')}</b></div>
</div>

${ll ? `<h2>Localisation approximative</h2><div class="card"><iframe loading="lazy" referrerpolicy="no-referrer-when-downgrade"
  src="https://maps.google.com/maps?q=${ll.LAT},${ll.LON}&z=11&output=embed"></iframe></div>` : ''}

<h2>Pages les plus consultees</h2>
<table><thead><tr><th>Page</th><th>Vues</th><th>Derniere</th></tr></thead><tbody>
${agg.rows.map(a => `<tr><td>${esc(a.PAGE)}</td><td>${a.C}</td><td class="m">${fmt(a.LAST_TS)}</td></tr>`).join('') || '<tr><td colspan="3">Aucune visite tracee.</td></tr>'}
</tbody></table>

<h2>Parcours detaille</h2>
<table><thead><tr><th>Quand</th><th>Page</th><th>Venu de</th><th>Appareil</th><th>Ville</th><th>IP</th></tr></thead><tbody>
${vis.rows.map(v => `<tr><td>${fmt(v.TS)}</td><td>${esc(v.PAGE)}</td><td class="m">${esc(v.REFERRER || '-')}</td>
  <td class="m">${esc(v.BROWSER)} ${esc(v.OS)} ${esc(v.DEVICE)}</td><td class="m">${esc(v.CITY || '')}</td>
  <td class="m">${esc(v.IP)}</td></tr>`).join('') || '<tr><td colspan="6">Aucune visite tracee.</td></tr>'}
</tbody></table>

<h2>Journal d'acces</h2>
<table><thead><tr><th>Quand</th><th>Evenement</th><th>Depuis</th></tr></thead><tbody>
${acc.rows.map(a => `<tr><td>${fmt(a.TS)}</td><td>${esc(a.EVENT)}</td><td class="m">${esc(a.IP)}</td></tr>`).join('') || '<tr><td colspan="3">-</td></tr>'}
</tbody></table>
</div></body></html>`);
  } catch (e) { console.error('prospect:', e); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.get('/export.csv', async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.query.site] ? req.query.site : Object.keys(SITES)[0];
  const r = await q(site, `SELECT p.*, (SELECT COUNT(*) FROM visits v WHERE v.prospect_id = p.id) nb_visites,
      (SELECT MIN(ts) FROM visits v WHERE v.prospect_id = p.id) premiere_visite,
      (SELECT MAX(ts) FROM visits v WHERE v.prospect_id = p.id) derniere_visite
    FROM prospects p ORDER BY p.created_at DESC`);
  const cols = ['CREATED_AT', 'FIRST_NAME', 'LAST_NAME', 'EMAIL', 'PHONE', 'COMPANY', 'INTEREST', 'STATUS',
    'CITY', 'COUNTRY', 'ORG', 'ISP', 'ASN', 'BROWSER', 'OS', 'DEVICE', 'LANG', 'REFERRER', 'LANDING',
    'UTM_SOURCE', 'UTM_MEDIUM', 'UTM_CAMPAIGN', 'SIGNUP_IP', 'LAT', 'LON', 'NB_VISITES', 'PREMIERE_VISITE', 'DERNIERE_VISITE', 'SITE'];
  const csv = [cols.join(';')].concat(r.rows.map(x => cols.map(c => `"${String(x[c] ?? '').replace(/"/g, '""')}"`).join(';'))).join('\n');
  res.type('text/csv').set('Content-Disposition', `attachment; filename="prospects-${site}.csv"`).send(csv);
});

router.get('/health', (req, res) => res.send('ok'));

app.use('/', router);
const BASE = process.env.BASE_PATH;
if (BASE && BASE !== '/') app.use(BASE, router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(
  `arx-gate :${PORT} base «${BASE || '/'}» · sites: ${Object.keys(SITES).join(', ')} · email ${EMAIL_ON ? 'ON' : 'OFF'} · ntfy ${NTFY_URL ? 'ON' : 'OFF'}`));
