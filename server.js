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
// L Autonomous Database « Always Free » accepte 21 sessions simultanees (mesure).
// Avec un schema par site, garder un pool ouvert par site depasse la limite des que le
// nombre de sites grandit : on plafonne le nombre de pools et on ferme le moins recemment
// utilise. MAX_POOLS x poolMax doit rester sous 21.
const MAX_POOLS = Number(process.env.MAX_POOLS || 10);
const pools = {};
const lastUsed = {};
const busy = {};   // requetes en cours par site : on ne ferme jamais un pool occupe
async function closePool(site) {
  const p = pools[site];
  if (!p) return;
  delete pools[site];
  delete lastUsed[site];
  try { await p.close(5); } catch { /* deja ferme */ }
}
async function pool(site) {
  const cfg = SITES[site];
  if (!cfg) throw new Error('site inconnu: ' + site);
  if (!pools[site]) {
    // Eviction du pool inactif le plus ancien. Fermer un pool occupe couperait la
    // requete en cours : la page repartait alors en reessai et pouvait mettre 25 s.
    const idle = Object.keys(pools).filter(s => !busy[s]);
    if (Object.keys(pools).length >= MAX_POOLS && idle.length) {
      const oldest = idle.sort((a, b) => (lastUsed[a] || 0) - (lastUsed[b] || 0))[0];
      await closePool(oldest);
    }
    pools[site] = await oracledb.createPool({
      user: cfg.user, password: cfg.password,
      connectString: process.env.ORA_CONNECT,
      configDir: WALLET_DIR, walletLocation: WALLET_DIR,
      walletPassword: process.env.ORA_WALLET_PASSWORD,
      poolMin: 0, poolMax: 1, poolTimeout: 5,
    });
  }
  lastUsed[site] = process.hrtime.bigint ? Number(process.hrtime.bigint() / 1000000n) : 0;
  return pools[site];
}
// L Autonomous Database « Always Free » plafonne les sessions simultanees : avec 20 sites
// declares, les pages qui parcourent tous les schemas (funnel, threats, share) doivent
// refermer les pools qu elles ont ouverts au passage, sinon la connexion est coupee.
async function withEachSite(fn) {
  for (const site of Object.keys(SITES)) {
    const reused = !!pools[site];
    try { await fn(site); }
    finally { if (!reused) await closePool(site); }
  }
}
async function q(site, sql, binds = {}, opts = {}, retry = true) {
  let c;
  busy[site] = (busy[site] || 0) + 1;
  try {
    c = await (await pool(site)).getConnection();
    return await c.execute(sql, binds, { autoCommit: true, ...opts });
  } catch (e) {
    // NJS-500/NJS-521 : session coupee par l ADB (limite atteinte, pool perime).
    // On jette le pool et on retente une fois, le temps que les sessions se liberent.
    if (retry && /NJS-5\d\d/.test(e.message || '')) {
      await closePool(site);
      await new Promise(r => setTimeout(r, 400));
      return q(site, sql, binds, opts, false);
    }
    throw e;
  } finally {
    busy[site] = Math.max(0, (busy[site] || 1) - 1);
    if (c) { try { await c.close(); } catch { /* deja fermee */ } }
  }
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
// URL reelle des services qui ne vivent pas sur arx-sites.duckdns.org.
// Sans cette table, siteUrl() renvoyait https://arx-sites.duckdns.org/<slug>/ pour
// tous les MCP et toutes les bases : des liens morts dans le tableau de bord.
// SITE_URLS (variable d env) reste prioritaire : rien de configure cote Coolify n est ecrase.
const MCP_HOST = 'https://arx-mcp.duckdns.org';
const SVC_URLS = {
  'mcp-root':        MCP_HOST + '/',
  'mcp-einstein':    MCP_HOST + '/einstein/mcp',
  'mcp-prisme':      MCP_HOST + '/prisme/mcp',
  'mcp-immo-rapido': MCP_HOST + '/immo-rapido/mcp',
  'mcp-hilde':       MCP_HOST + '/hilde/mcp',
  'mcp-saul':        MCP_HOST + '/saul/mcp',
  omni:              MCP_HOST + '/omni/mcp',
  'data-api':        MCP_HOST + '/rest/v1/',
  'db-prisme':       MCP_HOST + '/db-prisme/rest/v1/',
  'db-cv':           MCP_HOST + '/db-cv/rest/v1/',
  'db-saul':         MCP_HOST + '/db-saul/rest/v1/',
  'db-tcm':          MCP_HOST + '/db-tcm/rest/v1/',
  'db-dossier':      MCP_HOST + '/db-dossier/rest/v1/',
};
// Ce que fait chaque service, en une phrase : contenu de la pastille « i » de chaque onglet.
const DESC = {
  arxcapital:        'Site vitrine Arx Consulting, en francais et en anglais.',
  training:          'AI Training : offre de formation, sous-site de arxweb.',
  axperience:        'AXperience : proposition de valeur, sous-site de arxweb.',
  nice:              'Pacte Nice IA : plan metropolitain d efficience budgetaire et de securite urbaine.',
  nissai:            'Nissa IA, sous-site de arxweb.',
  'chef-jason':      'Assistant culinaire gastronomique : trois recettes par demande, LLM open-source gratuits.',
  antonweb:          'Site statique personnel.',
  'mcp-root':        'Page racine du domaine MCP : liste des serveurs exposes.',
  gate:              'Formulaire de demande d acces : capture du prospect, verification email, validation ntfy.',
  '50':              'Dossier prive 50 : porte a prospects, acces sur validation manuelle.',
  '877':             'Dossier prive 877 Super Cannes : porte a prospects, acces sur validation manuelle.',
  cactus:            'Dossier prive Cactus / Lindenhof : porte a prospects, acces sur validation manuelle.',
  '3point':          'Espace onboarding client 3Point.',
  blackstone:        'Tableau de bord trading : strategies, backtests, journal des ordres.',
  candidatures:      'Tableau de bord des candidatures : CV, lettres, scores ATS.',
  prospects:         'Base des prospects captures par la porte, tous sites confondus.',
  tracker:           'Ancien tableau de bord tracker, remplace par celui-ci.',
  'mcp-einstein':    'Recherche multi-angles : web, lecture de pages, archivage des recherches.',
  'mcp-prisme':      'Analyse psycho-symbolique multi-agent : profils nuances, jamais deterministes.',
  'mcp-immo-rapido': 'Analyse immobiliere PACA : DVF, PLU, foncier, rapports de deal.',
  'mcp-hilde':       'Sante holistique : dossier personnel indexe, referentiel MTC, interactions plante-medicament.',
  'mcp-saul':        'Juridique et fiscal : Legifrance et BOFiP cote France, Fedlex cote Suisse.',
  omni:              'Passerelle MCP unifiee : Behavioral Profiler v3, moteur Prisme, Meta-Skills.',
  'data-api':        'PostgREST, schema einstein : archives de recherche interrogeables en SQL.',
  'db-prisme':       'PostgREST, schema prisme : sujets, calculs, placements astro, rapports.',
  'db-cv':           'PostgREST, schema cv : master CV, skills bank, historique, contraintes.',
  'db-saul':         'PostgREST, schema saul : corpus juridique indexe.',
  'db-tcm':          'PostgREST, schema tcm : medecine chinoise, plantes et symptomes.',
  'db-dossier':      'PostgREST, schema dossier : pieces et documents de dossier.',
  minio:             'Stockage S3 MinIO : bucket rapports, lecture publique.',
  coolify:           'Tableau de bord Coolify : deploiement continu de toutes les applications.',
  'mail-review':     'Quarantaine email : revue des messages requalifies, restauration ou corbeille.',
  whatsapp:          'Pont WhatsApp : tri des messages, assistant omni, envoi.',
  'mailbot-api':     'Tri du spam en cascade : modele local puis Mistral, jamais de suppression.',
  n8n:               'Automatisation des flux entre services.',
};
function siteUrl(site) {
  return SITE_URLS[site] || SVC_URLS[site] || `https://arx-sites.duckdns.org/${site}/`;
}
// duckdns.org est un « public suffix » : impossible de partager un cookie entre sous-domaines.
// Le lien d'accès pointe donc vers la porte servie sur l'hôte du site, qui y pose un cookie d'hôte.
// petit lien « ouvrir l'element dans un nouvel onglet », affiche a cote de chaque site
// pastille « i » : au survol, ce que fait le service, son niveau d acces et son URL
function infoDot(site) {
  const s = SECURITY[site];
  const d = DESC[site] || (s && s.detail) || '';
  if (!d && !s) return '';
  // DESC fait autorite : ne repeter le detail de SECURITY que faute de description
  const detail = !DESC[site] && s && s.detail ? ' (' + s.detail + ')' : '';
  const tip = [d, s ? 'Acces : ' + s.label + detail : '', siteUrl(site)].filter(Boolean).join('\n');
  return '<i class="info" tabindex="0" role="button" aria-label="' + esc(site) +
         ' : description" data-tip="' + esc(tip) + '">i</i>';
}
function openLink(site, style = '') {
  return `<a href="${siteUrl(site)}" target="_blank" rel="noopener" title="ouvrir ${site} : ${siteUrl(site)}"
    style="text-decoration:none;font-size:.9em;${style}">&#8599;</a>`;
}
/* ---------- feuille commune du back-office ----------
 * Les cinq pages partageaient le meme bloc de style recopie a chaque fois, ce qui
 * rendait impossible de les rendre lisibles au telephone d un seul geste. Tout ce
 * qui est commun vit ici ; chaque page n ajoute que ses specificites.
 *
 * Au telephone, un tableau de sept colonnes ne se lit pas : sous 720 px chaque
 * ligne devient une carte, et l en-tete de colonne est repris devant la valeur
 * grace a l attribut data-l pose sur chaque <td>.
 */
const BO_CSS = `
*{box-sizing:border-box}
body{font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f8fb;color:#14202e;
 padding:28px 20px;margin:0;-webkit-text-size-adjust:100%}
.w{max-width:1200px;margin:0 auto}
h1{font-size:1.4rem;margin:0 0 4px;color:#1b354d}
.m{color:#5b6472;font-size:.85rem}
a{color:#ae8d57}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.tile{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:16px}
.tile b{display:block;font-size:1.6rem;color:#1b354d}
.tile span{color:#5b6472;font-size:.8rem}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;
 border-radius:12px;overflow:hidden;font-size:.85rem}
th{text-align:left;padding:10px 12px;background:#f2f5f9;color:#1b354d;font-size:.72rem;
 text-transform:uppercase;letter-spacing:.08em}
td{padding:10px 12px;border-top:1px solid #e4e8ef;vertical-align:top}
/* pastille « i » : description du service au survol. Doit vivre ICI, dans la feuille
 * commune — placee dans le <style> d une page precise, elle ne s applique qu a celle-la
 * et les points i s affichent nus sur toutes les autres. */
.info{display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;flex:none;
 border:1px solid #c8d0dc;border-radius:50%;background:#fff;color:#5b6b80;cursor:help;position:relative;
 font:600 10px/1 Inter,-apple-system,sans-serif;font-style:normal;vertical-align:middle}
.info:hover,.info:focus{background:#1b354d;color:#fff;border-color:#1b354d;outline:none}
.info::after{content:attr(data-tip);position:absolute;left:50%;top:calc(100% + 9px);transform:translateX(-50%);
 width:max-content;max-width:min(300px,74vw);background:#14202e;color:#fff;padding:9px 11px;border-radius:8px;
 font:400 12px/1.5 Inter,-apple-system,sans-serif;white-space:pre-line;text-align:left;
 opacity:0;visibility:hidden;transition:opacity .12s ease;z-index:60;
 box-shadow:0 8px 24px rgba(0,0,0,.28);pointer-events:none}
.info::before{content:"";position:absolute;left:50%;top:calc(100% + 4px);transform:translateX(-50%);
 border:5px solid transparent;border-bottom-color:#14202e;opacity:0;visibility:hidden;z-index:61;pointer-events:none}
.info:hover::after,.info:focus::after,.info:hover::before,.info:focus::before{opacity:1;visibility:visible}
@media(max-width:720px){.info::after{left:auto;right:0;transform:none;max-width:78vw}
 .info::before{left:auto;right:4px;transform:none}}
`;

/* La partie telephone est posee *apres* les regles propres a chaque page, sinon
 * celles-ci (meme specificite, declarees plus bas) reprendraient la main sur la
 * mise en cartes. */
const BO_MOBILE = `
@media(max-width:720px){
  body{padding:14px 12px}
  h1{font-size:1.2rem}
  .tiles{grid-template-columns:repeat(2,1fr);gap:10px;margin:14px 0}
  .tile{padding:12px}
  .tile b{font-size:1.35rem}

  /* Tableau -> liste de cartes : plus de defilement lateral. */
  table{border:none;background:none;border-radius:0}
  thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
  tr{display:block;background:#fff;border:1px solid #e4e8ef;border-radius:12px;
     padding:4px 12px 8px;margin-bottom:10px}
  /* max-width:none : la page tracker tronque ses cellules a 220 px, ce qui n a
     plus de sens une fois la ligne depliee en carte. */
  td{display:flex;gap:10px;border-top:1px solid #eef1f5;padding:7px 0;
     align-items:baseline;max-width:none;overflow:visible;
     /* URLs de referrer et adresses IP n ont aucun point de coupure : sans
        cela elles imposent leur longueur a toute la table. */
     overflow-wrap:anywhere;word-break:break-word}
  td>*{min-width:0;overflow-wrap:anywhere}
  tr td:first-child{border-top:none}
  td:empty{display:none}
  td::before{content:attr(data-l);flex:0 0 34%;color:#93a1b0;font-size:.7rem;font-weight:700;
    text-transform:uppercase;letter-spacing:.04em;padding-top:2px}
  td:not([data-l])::before{content:none}

  /* Etapes du tunnel : la barre de progression passe sous le libelle. */
  .step{flex-wrap:wrap;gap:6px 12px;padding:14px}
  .step .lbl{min-width:0;flex:1 1 100%}
  .step .bar{flex:1 1 100%;max-width:none;order:3}
  .step b{min-width:0;font-size:1.3rem;text-align:left}
  .step .cv{min-width:0}

  /* Colonnes et fiches : une seule colonne.
     min-width:0 sur les enfants : un element de grille ou de flex vaut par
     defaut la largeur de son contenu, et les libelles en white-space:nowrap
     des cartes elargissaient la colonne au-dela de l ecran. */
  .cols,.kv,.prev{grid-template-columns:1fr}
  .cols>*,.kv>*,.prev>*{min-width:0}
  .card li>*{min-width:0}
  .card li span{flex:1 1 auto}
  .card{padding:14px}
  iframe{height:260px}

  /* 16 px sur les champs : en dessous, iOS zoome a chaque mise au point. */
  input,select,textarea{font-size:16px}
  button,.actions button{min-height:44px}
  .actions{gap:8px}
  .actions button{flex:1 1 auto}
}
`;

// ---------- barre de menu du back-office ----------
// Une seule definition des sections : titre, chemin et ce que la page montre.
const MENU = [
  ['tracker', 'Tracker',   'Visites, pages vues, provenance et carte'],
  ['admin',   'Prospects', 'Fiches, parcours et statut de chaque inscrit'],
  ['recherche', 'Recherche', 'Retrouver un email ou un nom dans tous les sites a la fois'],
  ['funnel',  'Tunnel',    'Visiteurs uniques, clics CTA, inscrits, approuves'],
  ['threats', 'Menaces',   'IP suspectes, scans de vulnerabilites, robots'],
  ['share',   'Partages',  'Titre, description et image des liens partages'],
];
// Documentation de reference : ouvrir l architecture sans la chercher sur le Drive.
const DOCS_REPO = 'https://github.com/benoit-sigwald/OCI-Migration/blob/main';
const DOCS = [
  ['Comprendre l infra', [
    ['INFRASTRUCTURE.md',           'Architecture complete : serveur, reseau, Coolify, DNS, HTTPS'],
    ['STATUS.md',                   'Etat reel : URLs live, apps deployees, phases terminees'],
    ['REFERENCE.md',                'Identifiants, UUID, chemins et commandes utiles'],
    ['STACK.md',                    'Briques techniques et versions'],
  ]],
  ['Operations OCI', [
    ['OCI-API-RESIZE-PROCEDURE.md', 'Cle API OCI et agrandissement du disque a chaud'],
    ['PLAN-everything-on-oci.md',   'Plan de migration de tous les workloads'],
    ['RECAP.md',                    'Recapitulatif et garde-fous free tier'],
  ]],
  ['Projets', [
    ['BLACKSTONE-ARCHITECTURE.md',  'Architecture du module trading'],
    ['SERVICE-BRIEFS.md',           'Fiches par service'],
    ['OFFERS.md',                   'Offres commercialisables a partir de la stack'],
  ]],
];
const REPOS = [
  ['arx-gate',        'Porte d acces, tracker et prospects (cette application)'],
  ['mail-review',     'Quarantaine email : revue, restauration, corbeille'],
  ['mailbot-api',     'Tri spam en cascade : modele local puis Mistral'],
  ['whatsapp-bridge', 'WhatsApp : tri, assistant omni, envoi'],
  ['OCI-Migration',   'Documentation complete de l infrastructure'],
];

function docsMenu() {
  const group = (title, items) =>
    `<div class="gdoc-g"><span class="gdoc-t">${esc(title)}</span>` +
    items.map(([file, detail]) =>
      `<a href="${DOCS_REPO}/${encodeURIComponent(file)}" target="_blank" rel="noopener"
         title="${esc(detail)}">${esc(file.replace(/\.md$/, ''))}</a>`).join('') + '</div>';

  const repos = `<div class="gdoc-g"><span class="gdoc-t">Depots</span>` +
    REPOS.map(([name, detail]) =>
      `<a href="https://github.com/benoit-sigwald/${name}" target="_blank" rel="noopener"
         title="${esc(detail)}">${esc(name)}</a>`).join('') + '</div>';

  return `<details class="gdoc"><summary>Documents</summary>
<div class="gdoc-p">${DOCS.map(([t, items]) => group(t, items)).join('')}${repos}</div></details>`;
}

function navBar(current, { site = '', key = '' } = {}) {
  const qs = (path) => {
    const p = [];
    if (site && (path === 'admin' || path === 'tracker')) p.push('site=' + encodeURIComponent(site));
    if (key) p.push('key=' + encodeURIComponent(key));
    return p.length ? '?' + p.join('&') : '';
  };
  // « tracker » est la racine du back-office : /tracker, pas /tracker/tracker
  const href = (path) => `${ADMIN_ABS}${path === 'tracker' ? '' : '/' + path}${qs(path)}`;
  const links = MENU.map(([path, label, detail]) =>
    `<a href="${href(path)}" title="${esc(detail)}"
       class="gnav-l${path === current ? ' on' : ''}">${esc(label)}</a>`).join('');
  const detail = (MENU.find(m => m[0] === current) || [, , ''])[2];
  return `<style>
.gnav{display:flex;align-items:center;gap:18px;flex-wrap:wrap;background:#fff;border:1px solid #e4e8ef;
 border-radius:14px;padding:10px 18px;margin-bottom:6px}
.gnav .brand{display:flex;align-items:center;gap:10px;font-weight:700;color:#1b354d;font-size:1.05rem;margin-right:auto}
.gnav .brand img{height:30px;width:auto;display:block}
.gnav-l{color:#415060;text-decoration:none;font-size:.88rem;padding:6px 2px;border-bottom:2px solid transparent}
.gnav-l:hover{color:#1b354d}
.gnav-l.on{color:#1b354d;font-weight:600;border-bottom-color:#ae8d57}
.gnav .cta{background:#1b354d;color:#fff;border-radius:9px;padding:8px 16px;font-size:.85rem;font-weight:600;
 text-decoration:none;border-bottom:none}
.gnav-sub{color:#5b6472;font-size:.8rem;margin:0 0 16px;padding-left:4px}
.gdoc{position:relative}
.gdoc summary{list-style:none;cursor:pointer;color:#415060;font-size:.88rem;padding:6px 2px;
 border-bottom:2px solid transparent}
.gdoc summary::-webkit-details-marker{display:none}
.gdoc summary::after{content:" \\25BE";color:#93a1b0}
.gdoc[open] summary{color:#1b354d;font-weight:600;border-bottom-color:#ae8d57}
.gdoc-p{position:absolute;right:0;top:calc(100% + 10px);z-index:40;background:#fff;
 border:1px solid #e4e8ef;border-radius:12px;box-shadow:0 10px 30px rgba(27,53,77,.13);
 padding:12px 6px;min-width:260px;max-height:70vh;overflow:auto}
.gdoc-g{padding:4px 0}
.gdoc-g+.gdoc-g{border-top:1px solid #eef1f5;margin-top:6px;padding-top:8px}
.gdoc-t{display:block;padding:2px 14px 6px;color:#93a1b0;font-size:.72rem;font-weight:700;
 text-transform:uppercase;letter-spacing:.04em}
.gdoc-p a{display:block;padding:6px 14px;color:#1b354d;text-decoration:none;font-size:.85rem;
 border-radius:7px;border-bottom:none}
.gdoc-p a:hover{background:#f2f5f9}
/* Telephone : ces regles vivent ici et pas dans BO_MOBILE, parce que la barre
   ecrit son <style> dans le corps de page, donc apres celui de l en-tete —
   place ailleurs, le min-width du panneau reprendrait la main et deborderait. */
@media(max-width:720px){
 .gnav{gap:8px 12px;padding:10px 12px}
 .gnav .brand{flex:1 1 100%;margin-right:0;font-size:1rem}
 .gnav-l,.gdoc summary{padding:11px 2px;font-size:.92rem}
 .gnav .cta{padding:11px 16px;margin-left:auto}
 .gdoc{position:static}
 .gdoc-p{position:static;min-width:0;width:100%;margin-top:8px;box-shadow:none;max-height:none}
 .gdoc-p a{padding:11px 14px}
}
</style>
<div class="gnav"><span class="brand"><img src="${ADMIN_ABS}/p/arx-logo.png" alt="Arx"> Arx Tracker</span>${links}
${docsMenu()}
<a class="cta" href="https://arx-consulting.com" target="_blank" rel="noopener">Arx Consulting</a></div>
<p class="gnav-sub">${esc(detail)}</p>`;
}
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

const PAGE = (title, body, og) => `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(og ? og.title : title + ' — Arx Capital')}</title>
${og ? `<meta name="description" content="${esc(og.desc)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Arx Capital">
<meta property="og:title" content="${esc(og.title)}">
<meta property="og:description" content="${esc(og.desc)}">
<meta property="og:image" content="${PUBLIC_URL}/img?site=${encodeURIComponent(og.site)}">
<meta property="og:image:width" content="1200">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(og.title)}">
<meta name="twitter:description" content="${esc(og.desc)}">
<meta name="twitter:image" content="${PUBLIC_URL}/img?site=${encodeURIComponent(og.site)}">` : ''}
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
#rgpd-modal{position:fixed;inset:0;background:rgba(27,53,77,.65);display:flex;align-items:center;
 justify-content:center;padding:24px;z-index:50}
#rgpd-modal[hidden]{display:none}
#rgpd-modal .inner{background:#fff;border-radius:14px;padding:28px;max-width:420px;text-align:center;
 box-shadow:0 20px 60px rgba(0,0,0,.3)}
#rgpd-modal .row2{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
#rgpd-modal button{margin:0}
#rgpd-cancel{background:#fff;color:var(--navy);border:1px solid var(--border)}
</style></head><body><div class="box">${body}</div></body></html>`;

const BASE_ABS = (process.env.BASE_PATH && process.env.BASE_PATH !== '/') ? process.env.BASE_PATH.replace(/\/$/, '') : '';
// La porte publique reste sous BASE_PATH (/gate) ; le back-office est servi sous ADMIN_ABS
// (/tracker), sans reecriture de prefixe cote Traefik pour que les liens restent valides.
const ADMIN_ABS = (process.env.ADMIN_BASE_PATH || '/tracker').replace(/\/$/, '');
// ---------- metadonnees de partage, lues automatiquement sur le site protege ----------
// Toute nouvelle porte herite du comportement : la porte va chercher <title>,
// la description et l'image du site lui-meme, sans configuration.
const META_OVERRIDE = JSON.parse(Buffer.from(process.env.SITE_META_B64 || '', 'base64').toString() || '{}');
const metaCache = new Map();          // site -> { title, desc, img, at }
const META_TTL = 6 * 3600e3;

// jeton interne : permet a la porte de lire le site protege sans passer par le formulaire
const botToken = site => sign('bot:' + site);

function absolute(base, url) {
  try { return new URL(url, base).href; } catch { return null; }
}
function extractMeta(html, base) {
  const pick = re => { const m = html.match(re); return m ? m[1].trim() : null; };
  const title = pick(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)/i)
             || pick(/<title[^>]*>([^<]+)</i);
  const desc = pick(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)/i)
            || pick(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)/i);
  let img = pick(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)/i)
         || pick(/<img[^>]+src=["']([^"']+\.(?:jpe?g|png|webp))/i)
         || pick(/url\(['"]?([^'")]+\.(?:jpe?g|png|webp))/i);
  return { title, desc, img: img ? absolute(base, img) : null };
}
// table SHARE_META (1 ligne par site, dans le schema du site)
async function ensureShareTable(site) {
  try { await q(site, 'SELECT 1 FROM share_meta FETCH FIRST 1 ROWS ONLY'); }
  catch (e) {
    if (!String(e.message).includes('ORA-00942')) throw e;
    await q(site, `CREATE TABLE share_meta (
      id NUMBER DEFAULT 1 PRIMARY KEY,
      title VARCHAR2(300), descr VARCHAR2(600), img VARCHAR2(600),
      updated_at TIMESTAMP DEFAULT SYSTIMESTAMP)`);
  }
}
async function dbMeta(site) {
  try {
    await ensureShareTable(site);
    const r = await q(site, 'SELECT title, descr, img FROM share_meta WHERE id = 1');
    if (r.rows.length) return { title: r.rows[0].TITLE, desc: r.rows[0].DESCR, img: r.rows[0].IMG };
  } catch (e) { console.error('dbMeta', site + ':', e.message); }
  return null;
}

async function siteMeta(site) {
  const over = META_OVERRIDE[site];
  const hit = metaCache.get(site);
  if (hit && Date.now() - hit.at < META_TTL) return hit;
  // 1) fiche enregistree en base : elle a la priorite
  const fromDb = await dbMeta(site);
  if (fromDb && (fromDb.title || fromDb.desc || fromDb.img)) {
    const m = { title: fromDb.title || 'Arx Capital', desc: fromDb.desc || '', img: fromDb.img || null,
                source: 'base', at: Date.now() };
    metaCache.set(site, m);
    return m;
  }
  let m = { title: 'Arx Capital', desc: 'Acces reserve.', img: null };
  try {
    const url = siteUrl(site);
    const r = await fetch(url, {
      headers: { 'X-Gate-Bot': botToken(site), 'User-Agent': 'arx-gate/1.0' },
      redirect: 'follow', signal: AbortSignal.timeout(6000),
    });
    if (r.ok) {
      const html = (await r.text()).slice(0, 200000);
      const x = extractMeta(html, url);
      if (x.title) m = { title: x.title, desc: x.desc || m.desc, img: x.img };
    }
  } catch (e) { console.error('meta', site + ':', e.message); }
  if (over) m = { ...m, ...over };
  m.source = 'automatique';
  m.at = Date.now();
  metaCache.set(site, m);
  return m;
}
// ---------- niveau de securite par site / page ----------
// Ce qui protege reellement la ressource visitee : sert a lire le tracker
// sans avoir a se souvenir de la configuration de chaque application.
const SECURITY = {
  arxcapital:        { label: 'Public',            kind: 'public',  detail: 'Site vitrine, ouvert a tous' },
  'chef-jason':      { label: 'Public',            kind: 'public',  detail: 'Application web ouverte' },
  training:          { label: 'Public',            kind: 'public',  detail: 'AI Training, sous-site de arxweb' },
  axperience:        { label: 'Public',            kind: 'public',  detail: 'AXperience, sous-site de arxweb' },
  nice:              { label: 'Public',            kind: 'public',  detail: 'Pacte Nice IA, sous-site de arxweb' },
  nissai:            { label: 'Public',            kind: 'public',  detail: 'Nissa IA, sous-site de arxweb' },
  'mcp-root':        { label: 'Public',            kind: 'public',  detail: 'Page racine du domaine MCP' },
  gate:              { label: 'Public',            kind: 'public',  detail: 'Formulaire de demande d acces' },
  '50':              { label: 'Porte prospects',   kind: 'gate',    detail: 'forwardAuth + cookie signe 90 j, validation manuelle' },
  '877':             { label: 'Porte prospects',   kind: 'gate',    detail: 'forwardAuth + cookie signe 90 j, validation manuelle' },
  cactus:            { label: 'Porte prospects',   kind: 'gate',    detail: 'forwardAuth + cookie signe 90 j, validation manuelle' },
  '3point':          { label: 'Basic auth',        kind: 'key',     detail: 'HTTP Basic au niveau du proxy, realm 3Point - espace onboarding' },
  blackstone:        { label: 'Cle admin',         kind: 'key',     detail: 'Tableau de bord interne, cle de session' },
  candidatures:      { label: 'Cle admin',         kind: 'key',     detail: 'Tableau de bord interne, cle de session' },
  prospects:         { label: 'Cle admin',         kind: 'key',     detail: 'DASH_TOKEN' },
  'mcp-einstein':    { label: 'Jeton Bearer',      kind: 'token',   detail: 'Authorization: Bearer, ou prefixe /t/<jeton>' },
  'mcp-prisme':      { label: 'Jeton Bearer',      kind: 'token',   detail: 'Authorization: Bearer, ou prefixe /t/<jeton>' },
  'mcp-immo-rapido': { label: 'Jeton Bearer',      kind: 'token',   detail: 'Authorization: Bearer + portail web protege' },
  'mcp-hilde':       { label: 'Jeton Bearer',      kind: 'token',   detail: 'Sante holistique : dossier personnel + referentiel MTC' },
  'mcp-saul':        { label: 'Jeton Bearer',      kind: 'token',   detail: 'Juridique FR/CH : Legifrance, BOFiP, Fedlex' },
  'data-api':        { label: 'Jeton API',         kind: 'token',   detail: 'PostgREST schema einstein, cle de service' },
  omni:              { label: 'Jeton Bearer',      kind: 'token',   detail: 'Serveur MCP omni, Authorization: Bearer' },
  tracker:           { label: 'Cle admin',         kind: 'key',     detail: 'Ancien tableau de bord tracker, cle de session' },
  minio:             { label: 'Cle S3',            kind: 'key',     detail: 'MinIO, bucket rapports en lecture publique' },
  coolify:           { label: 'Compte Coolify',    kind: 'key',     detail: 'Tableau de bord Coolify, mot de passe ou Google OAuth' },
  'db-prisme':       { label: 'Jeton API',         kind: 'token',   detail: 'PostgREST schema prisme, cle de service' },
  'db-cv':           { label: 'Jeton API',         kind: 'token',   detail: 'PostgREST schema cv, cle de service' },
  'db-saul':         { label: 'Jeton API',         kind: 'token',   detail: 'PostgREST schema saul, cle de service' },
  'db-tcm':          { label: 'Jeton API',         kind: 'token',   detail: 'PostgREST schema tcm (medecine chinoise), cle de service' },
  'mail-review':     { label: 'Google OAuth',      kind: 'key',     detail: 'Revue de la quarantaine email, liste d adresses autorisees' },
  whatsapp:          { label: 'Google OAuth',      kind: 'key',     detail: 'Tri WhatsApp et assistant omni, liste d adresses autorisees' },
  'mailbot-api':     { label: 'Jeton API',         kind: 'token',   detail: 'Tri spam en cascade, en-tete X-API-Token' },
  n8n:               { label: 'Compte n8n',        kind: 'key',     detail: 'Automatisation des flux, compte proprietaire n8n' },
  antonweb:          { label: 'Public',            kind: 'public',  detail: 'Site statique, ouvert a tous' },
};
const SEC_COLORS = {
  public:  ['#1d7a4f', '#e6f4ec', '#b7e0c8'],
  gate:    ['#8a6d3b', '#f4ede0', '#e6d9c2'],
  key:     ['#1b354d', '#eef1f6', '#dde5ee'],
  token:   ['#5b3fa0', '#efeafa', '#ddd2f3'],
  denied:  ['#a32d2d', '#fdecec', '#f5c2c2'],
};
function security(site, page, referrer) {
  const base = SECURITY[site] || { label: 'Inconnu', kind: 'key', detail: '' };
  const p = String(page || ''), r = String(referrer || '');
  // un appel MCP reste protege par jeton, quel que soit le site sous lequel il a ete journalise
  if (/^\/(mcp|t\/)|\/mcp(\/|$)/.test(p))
    return { label: 'Jeton Bearer', kind: 'token', detail: 'Appel MCP : Authorization Bearer ou prefixe /t/<jeton>' };
  // les pages d administration sont protegees par la cle, quel que soit le site
  if (/^\/(gate\/)?(admin|visits|funnel|share|prospect)/.test(p))
    return { label: 'Cle admin', kind: 'key', detail: 'Back-office, cle ADMIN_KEY' };
  // le middleware MCP journalise le resultat dans le champ referrer
  if (/refus|denied|401|403/i.test(r)) return { label: base.label + ' - refuse', kind: 'denied', detail: base.detail };
  return base;
}
function secDot(site) {
  const s = SECURITY[site];
  if (!s) return '';
  const [fg] = SEC_COLORS[s.kind] || SEC_COLORS.key;
  return `<i class="dot" style="background:${fg}" title="${esc(s.label)}"></i>`;
}
function secBadge(site, page, referrer) {
  const s = security(site, page, referrer);
  const [fg, bg, bd] = SEC_COLORS[s.kind] || SEC_COLORS.key;
  return `<span class="sec" title="${esc(s.detail)}" style="color:${fg};background:${bg};border-color:${bd}">${esc(s.label)}</span>`;
}

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
    rgpdAccept: "J'accepte et je continue", rgpdCancel: 'Annuler',
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
    rgpdAccept: 'I agree and continue', rgpdCancel: 'Cancel',
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
  </script>`, og);
}

function langLink(l, extra = '') {
  return `<a class="lang" href="?lang=${l === 'fr' ? 'en' : 'fr'}${extra}">${T[l].other}</a>`;
}

function formPage(site, rd, err, prefill = {}, l = 'fr', og = null) {
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
      <input type="checkbox" name="consent" id="c">
      <label for="c" style="font-weight:400;margin:0;font-size:.82rem;color:var(--muted)">${esc(t.consent)}</label>
    </div>
    <button type="submit">${esc(t.submit)}</button>
  </form>
  <div id="rgpd-modal" hidden>
    <div class="inner">
      <div style="font-size:2rem;margin-bottom:8px">&#128274;</div>
      <h1 style="font-size:1.15rem;margin-bottom:8px">${esc(t.rgpdTitle)}</h1>
      <p class="sub" style="margin-bottom:18px">${esc(t.rgpd)}</p>
      <div class="row2">
        <button type="button" id="rgpd-accept">${esc(t.rgpdAccept)}</button>
        <button type="button" id="rgpd-cancel">${esc(t.rgpdCancel)}</button>
      </div>
    </div>
  </div>
  <script>
  (function(){
    var f = document.querySelector('form'), c = document.getElementById('c'),
        m = document.getElementById('rgpd-modal');
    m.hidden = true;
    f.addEventListener('submit', function(e){
      if (!c.checked) { e.preventDefault(); m.hidden = false; }
    });
    document.getElementById('rgpd-accept').addEventListener('click', function(){
      c.checked = true; m.hidden = false;
      // on ne poste jamais un formulaire incomplet : le navigateur pointe le champ manquant
      if (f.reportValidity()) { m.hidden = true; f.submit(); } else { m.hidden = true; }
    });
    document.getElementById('rgpd-cancel').addEventListener('click', function(){ m.hidden = true; c.focus(); });
    m.addEventListener('click', function(e){ if (e.target === m) m.hidden = true; });
  })();
  </script>
  <small>${esc(t.foot)}</small>`, og);
}

function waitingPage(site, vtoken, l = 'fr', og = null) {
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
  </script>`, og);
}

// ---- auto-suivi des pages de la porte ----
// `into` = schema ou ecrire. Une demande d acces a un site protege est d abord une visite
// **de ce site** : sans cela, un dossier prive derriere la porte affiche toujours 0 visite,
// puisque le visiteur non autorise ne voit jamais la page elle-meme.
async function trackSelf(req, page, into = 'gate') {
  const target = SITES[into] ? into : 'gate';
  if (!SITES[target]) return;
  try {
    const ip = clientIp(req), ua = req.headers['user-agent'] || '';
    const { browser, os, device } = parseUa(ua);
    const g = await geo(ip);
    await q(target, `INSERT INTO visits (site,page,referrer,ip,ua,browser,os,device,country,region,city,org,isp,asn,lang,lat,lon)
      VALUES (:site,:page,:ref,:ip,:ua,:browser,:os,:device,:country,:region,:city,:org,:isp,:asn,:lang,:lat,:lon)`, {
      site: cut(target, 64),
      page: cut(page, 512), ref: cut(req.headers.referer, 512), ip: cut(ip, 64), ua: cut(ua, 512),
      browser, os, device, country: cut(g.country, 64), region: cut(g.region, 64), city: cut(g.city, 64),
      org: cut(g.org, 160), isp: cut(g.isp, 160), asn: cut(g.asn, 64),
      lang: cut((req.headers['accept-language'] || '').split(',')[0], 32),
      lat: g.lat ?? null, lon: g.lon ?? null,
    });
  } catch (e) { console.error('trackSelf:', e.message); }
}

// ---- forwardauth ----
router.get('/auth', async (req, res) => {
  // le site vient du middleware Traefik (?site=…) ; sinon on le déduit du chemin d'origine
  const site = SITES[req.query.site] ? req.query.site : siteFromForward(req);
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || '';
  const uri = req.headers['x-forwarded-uri'] || '/';
  // page exacte demandee : /<site>/… sur un hote partage, ou n'importe quel chemin sur l'hote dedie
  let rd = siteUrl(site);
  if (site && uri && !uri.startsWith('/gate')) {
    if (uri.startsWith('/' + site)) {
      rd = `${proto}://${host}${uri}`;                       // hote partage : /<site>/page
    } else {
      try {
        const base = new URL(siteUrl(site));
        if (base.pathname === '/') rd = base.origin + uri;   // hote dedie : /page
      } catch {}
    }
  }
  if (!site) return res.sendStatus(200); // chemin non protégé
  // lecture interne par la porte (metadonnees de partage)
  if (req.headers['x-gate-bot'] && req.headers['x-gate-bot'] === botToken(site)) return res.sendStatus(200);
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
router.get('/', async (req, res) => {
  const site = SITES[req.query.site] ? req.query.site : Object.keys(SITES)[0];
  trackSelf(req, '/formulaire?site=' + site);        // journal de la porte
  if (site !== 'gate') trackSelf(req, '/porte (acces refuse)', site);  // et visite du site vise
  const og = { ...(await siteMeta(site)), site };
  res.type('html').send(formPage(site, req.query.rd, null, {}, lang(req), og));
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
    return res.type('html').send(waitingPage(site, vtoken, l, { ...(await siteMeta(site)), site }));
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
      `<span style="display:inline-flex;align-items:center;gap:5px;margin:0 6px 6px 0;padding:5px 10px;border:1px solid #e4e8ef;border-radius:8px;
        background:${x === site ? '#1b354d' : '#fff'};font-size:.85rem">
        <a href="${ADMIN_ABS}/admin?site=${x}" style="text-decoration:none;color:${x === site ? '#fff' : '#1b354d'}">${esc(x)}</a>
        ${infoDot(x)}${openLink(x, `color:${x === site ? '#fff' : '#ae8d57'}`)}</span>`).join('');
    const rows = pros.rows.map(p => `<tr onclick="location.href='${ADMIN_ABS}/prospect?site=${site}&id=${p.ID}'" style="cursor:pointer">
      <td data-l="Inscrit">${fmt(p.CREATED_AT)}</td>
      <td data-l="Personne"><b>${esc(p.FIRST_NAME)} ${esc(p.LAST_NAME)}</b><br><span class="m">${esc(p.COMPANY || '')}</span></td>
      <td data-l="Contact">${esc(p.EMAIL)}<br><span class="m">${esc(p.PHONE || '')}</span></td>
      <td data-l="Objet">${esc(p.INTEREST || '')}</td>
      <td data-l="Lieu">${esc(p.CITY || '')} ${esc(p.COUNTRY || '')}<br><span class="m">${esc(p.ORG || p.ISP || '')}</span></td>
      <td data-l="Statut"><span style="color:${badge(p.STATUS)};font-weight:600">${esc(p.STATUS)}</span></td>
      <td data-l="Visites"><b>${p.NB || 0}</b> visite(s)<br><span class="m">${p.NB ? 'derniere ' + fmt(p.LAST_SEEN) : '-'}</span></td>
      <td data-l="Derniere page" class="m">${esc(p.LAST_PAGE || '-')}<br><span class="m">${esc(p.BROWSER || '')} ${esc(p.DEVICE || '')}</span></td>
      <td data-l="Geo">${p.LAT != null ? `<a href="${ADMIN_ABS}/prospect?site=${site}&id=${p.ID}#map" title="${esc(p.LAT + ', ' + p.LON)}">carte</a>` : '-'}</td></tr>`).join('');
    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Prospects — ${esc(site)}</title><style>
${BO_CSS}
.w{max-width:1200px;margin:0 auto}h1{font-size:1.4rem;margin:0 0 4px;color:#1b354d}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.tile{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:16px}
.tile b{display:block;font-size:1.6rem;color:#1b354d}.tile span{color:#5b6472;font-size:.8rem}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;border-radius:12px;overflow:hidden;font-size:.85rem}
th{text-align:left;padding:10px 12px;background:#f2f5f9;color:#1b354d;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
td{padding:10px 12px;border-top:1px solid #e4e8ef;vertical-align:top}
.m{color:#5b6472;font-size:.78rem}a{color:#ae8d57}
${BO_MOBILE}
</style></head><body><div class="w">
${navBar('admin', { site, key: req.query.key })}
<h1>Prospects</h1><p class="m"><a href="${ADMIN_ABS}/prospect/new?site=${site}"><b>+ Ajouter un prospect</b></a> &middot; schéma Oracle dédié par site &middot; <a href="${ADMIN_ABS}/export.csv?site=${site}&key=${encodeURIComponent(req.query.key || ADMIN_KEY)}">export CSV</a></p>
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

// ---- modification / suppression d'un prospect ----
function adminBack(res, site, id, msg) {
  res.redirect(302, `${ADMIN_ABS}/prospect?site=${encodeURIComponent(site)}&id=${id}&ok=${encodeURIComponent(msg)}`);
}

router.post('/prospect/save', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  const id = Number(req.body.id);
  if (!site || !id) return res.status(400).send('parametres manquants');
  try {
    await q(site, `UPDATE prospects SET first_name=:f, last_name=:l, email=:e, phone=:p, company=:c,
      interest=:i, status=:st, notes=:n WHERE id=:id`, {
      f: cut(req.body.first_name, 80), l: cut(req.body.last_name, 80),
      e: cut(String(req.body.email || '').trim().toLowerCase(), 160), p: cut(req.body.phone, 40),
      c: cut(req.body.company, 160), i: cut(req.body.interest, 60),
      st: cut(req.body.status, 20) || 'pending', n: cut(req.body.notes, 500), id });
    console.log(`[admin] prospect ${id} (${site}) modifie`);
    adminBack(res, site, id, 'Fiche enregistree');
  } catch (e) { console.error('save:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.post('/prospect/access', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  const id = Number(req.body.id);
  if (!site || !id) return res.status(400).send('parametres manquants');
  try {
    const r = await q(site, 'SELECT email, first_name FROM prospects WHERE id = :id', { id });
    if (!r.rows.length) return res.status(404).send('inconnu');
    await q(site, `UPDATE prospects SET status='approved', decided_at=SYSTIMESTAMP WHERE id=:id`, { id });
    const t = tok();
    await q(site, `INSERT INTO sessions (prospect_id, token, expires_at) VALUES (:id, :t, SYSTIMESTAMP + INTERVAL '90' DAY)`, { id, t });
    const link = `${gateBase(site)}/access?t=${t}&site=${encodeURIComponent(site)}`;
    const sent = await sendMail(r.rows[0].EMAIL, 'Votre acces — Arx Capital',
      `<p>Bonjour ${esc(r.rows[0].FIRST_NAME || '')},</p><p>Voici votre lien d'acces :</p>
       <p><a href="${link}">${link}</a></p>`);
    if (!sent) await ntfy('Lien d acces genere', `${r.rows[0].EMAIL}\n${link}`);
    console.log(`[admin] nouveau lien d'acces pour prospect ${id} (${site})`);
    adminBack(res, site, id, sent ? 'Lien envoye par email' : 'Lien envoye sur ntfy');
  } catch (e) { console.error('access-admin:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.post('/prospect/revoke', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  const id = Number(req.body.id);
  if (!site || !id) return res.status(400).send('parametres manquants');
  try {
    await q(site, 'UPDATE sessions SET revoked = 1 WHERE prospect_id = :id', { id });
    await q(site, `UPDATE prospects SET status='rejected', decided_at=SYSTIMESTAMP WHERE id=:id`, { id });
    console.log(`[admin] acces revoques pour prospect ${id} (${site})`);
    adminBack(res, site, id, 'Acces revoques');
  } catch (e) { console.error('revoke:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.post('/prospect/delete', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  const id = Number(req.body.id);
  if (!site || !id) return res.status(400).send('parametres manquants');
  try {
    await q(site, 'UPDATE visits SET prospect_id = NULL WHERE prospect_id = :id', { id });
    await q(site, 'DELETE FROM sessions WHERE prospect_id = :id', { id });
    await q(site, 'DELETE FROM access_log WHERE prospect_id = :id', { id });
    await q(site, 'DELETE FROM prospects WHERE id = :id', { id });
    console.log(`[admin] prospect ${id} (${site}) supprime`);
    res.redirect(302, `${ADMIN_ABS}/admin?site=${encodeURIComponent(site)}`);
  } catch (e) { console.error('delete:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

// ---- ajout manuel d'un prospect ----
router.get('/prospect/new', (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.query.site] ? req.query.site : Object.keys(SITES)[0];
  res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Nouveau prospect</title><style>
${BO_CSS}
.w{max-width:640px;margin:0 auto}h1{font-size:1.3rem;color:#1b354d;margin:0 0 14px}
.card{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:22px}
label{display:block;font-size:.78rem;font-weight:600;color:#1b354d;margin:12px 0 4px}
input,select{width:100%;padding:10px 12px;border:1px solid #e4e8ef;border-radius:8px;font:inherit;font-size:.92rem}
input:focus,select:focus{outline:none;border-color:#ae8d57}
button{margin-top:18px;padding:11px 20px;border:none;border-radius:9px;background:#1b354d;color:#fff;font:inherit;font-weight:600;cursor:pointer}
a{color:#ae8d57}
${BO_MOBILE}
</style></head><body><div class="w">
<p><a href="${ADMIN_ABS}/admin?site=${site}">&larr; retour aux prospects</a></p>
<h1>Ajouter un prospect (${esc(site)})</h1>
<form class="card" method="post" action="${ADMIN_ABS}/prospect/create">
  <input type="hidden" name="site" value="${esc(site)}">
  <label>Prenom</label><input name="first_name" required maxlength="80">
  <label>Nom</label><input name="last_name" required maxlength="80">
  <label>Email</label><input name="email" type="email" required maxlength="160">
  <label>Telephone</label><input name="phone" maxlength="40">
  <label>Societe</label><input name="company" maxlength="160">
  <label>Objet</label><input name="interest" maxlength="60">
  <label>Statut</label><select name="status">
    <option>approved</option><option>email_verified</option><option selected>pending</option><option>rejected</option>
  </select>
  <label>Notes</label><input name="notes" maxlength="500">
  <button type="submit">Creer</button>
</form>
</div></body></html>`);
});

router.post('/prospect/create', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  if (!site) return res.status(400).send('site inconnu');
  try {
    const r = await q(site, `INSERT INTO prospects (first_name,last_name,email,phone,company,interest,status,
      consent_rgpd,site,notes,verify_token,decision_token)
      VALUES (:f,:l,:e,:p,:c,:i,:st,0,:site,:n,:v,:d) RETURNING id INTO :id`, {
      f: cut(req.body.first_name, 80), l: cut(req.body.last_name, 80),
      e: cut(String(req.body.email || '').trim().toLowerCase(), 160), p: cut(req.body.phone, 40),
      c: cut(req.body.company, 160), i: cut(req.body.interest, 60),
      st: cut(req.body.status, 20) || 'pending', site, n: cut(req.body.notes, 500),
      v: tok(), d: tok(), id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER } });
    console.log(`[admin] prospect cree manuellement (${site})`);
    adminBack(res, site, r.outBinds.id[0], 'Prospect cree');
  } catch (e) { console.error('create:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

// ---- administration des liens partages ----
// ---- tunnel de conversion (KPI) ----
// ---- carte des menaces : d'ou viennent les acces suspects ----
// Signaux retenus (aucune supposition : uniquement ce qui est journalise)
//  · scan     : chemins d'attaque connus (wp-admin, .env, phpmyadmin...)
//  · refus    : requete rejetee (401/403 signale par le middleware MCP)
//  · robot    : user-agent d'automate
//  · volume   : plus de 60 requetes sur la periode depuis une meme IP
//  · etranger : hors zone habituelle (France, Monaco, Suisse, Belgique)
const ATTACK_PATHS = /(wp-admin|wp-login|xmlrpc|\.env|\.git|phpmyadmin|\/admin\.php|\/shell|\/etc\/passwd|\/config\.|\.aws|\/vendor\/|\/actuator|\/solr|\/cgi-bin)/i;
const HOME_COUNTRIES = new Set(['France', 'Monaco', 'Switzerland', 'Suisse', 'Belgium', 'Belgique']);

router.get('/threats', async (req, res) => {
  if (!authed(req, res)) return;
  const days = Math.min(parseInt(req.query.days || '30', 10) || 30, 365);
  try {
    const perIp = new Map();
    await withEachSite(async (site) => {
      let rows = [];
      try {
        rows = (await q(site, `SELECT ip, page, referrer, ua, city, country, org, isp, lat, lon, ts
          FROM visits WHERE ts >= SYSTIMESTAMP - NUMTODSINTERVAL(:d,'DAY')
          ORDER BY ts DESC FETCH FIRST 4000 ROWS ONLY`, { d: days })).rows;
      } catch { return; }
      for (const v of rows) {
        const ip = v.IP || 'inconnue';
        if (!perIp.has(ip)) perIp.set(ip, {
          ip, n: 0, sites: new Set(), scans: 0, denied: 0, bots: 0,
          city: v.CITY, country: v.COUNTRY, org: v.ORG || v.ISP,
          lat: v.LAT, lon: v.LON, last: v.TS, samples: [],
        });
        const e = perIp.get(ip);
        e.n++;
        e.sites.add(site);
        if (e.lat == null && v.LAT != null) { e.lat = v.LAT; e.lon = v.LON; }
        if (!e.city && v.CITY) { e.city = v.CITY; e.country = v.COUNTRY; e.org = v.ORG || v.ISP; }
        if (ATTACK_PATHS.test(v.PAGE || '')) { e.scans++; if (e.samples.length < 3) e.samples.push(v.PAGE); }
        if (/refus|denied|401|403/i.test(String(v.REFERRER || ''))) e.denied++;
        if (/bot|crawler|spider|curl|wget|python|scan/i.test(String(v.UA || ''))) e.bots++;
      }
    });
    const items = [...perIp.values()].map(e => {
      const reasons = [];
      let score = 0;
      if (e.scans)   { score += 60 + Math.min(e.scans, 20); reasons.push(`${e.scans} chemin(s) d'attaque`); }
      if (e.denied)  { score += 25 + Math.min(e.denied, 20); reasons.push(`${e.denied} refus`); }
      if (e.bots)    { score += 10; reasons.push('automate'); }
      if (e.n > 60)  { score += 15; reasons.push(`${e.n} requetes`); }
      if (e.country && !HOME_COUNTRIES.has(e.country)) { score += 8; reasons.push(`hors zone (${e.country})`); }
      const level = score >= 60 ? 'eleve' : score >= 25 ? 'moyen' : score > 0 ? 'faible' : 'aucun';
      return { ...e, sites: [...e.sites], score, level, reasons };
    }).filter(e => e.score > 0).sort((a, b) => b.score - a.score).slice(0, 60);

    const counts = { eleve: 0, moyen: 0, faible: 0 };
    items.forEach(i => counts[i.level]++);
    const COL = { eleve: ['#a32d2d', '#fdecec', '#f5c2c2'], moyen: ['#8a6d3b', '#f4ede0', '#e6d9c2'], faible: ['#1b354d', '#eef1f6', '#dde5ee'] };
    const fmt = t => t ? new Date(t).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-';
    const mapped = items.filter(i => i.lat != null);
    const first = mapped[0];

    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Carte des menaces</title><style>
${BO_CSS}
.w{max-width:1150px;margin:0 auto}h1{font-size:1.4rem;color:#1b354d;margin:0 0 4px}
h2{font-size:.95rem;color:#1b354d;margin:0 0 12px}
.m{color:#5b6472;font-size:.85rem}a{color:#ae8d57;text-decoration:none}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}
.tile{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:16px}
.tile b{display:block;font-size:1.7rem}.tile span{color:#5b6472;font-size:.8rem}
.card{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:18px;margin-bottom:20px}
iframe{width:100%;height:360px;border:0;border-radius:10px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;border-radius:12px;overflow:hidden;font-size:.84rem}
th{text-align:left;padding:9px 12px;background:#f2f5f9;color:#1b354d;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em}
td{padding:9px 12px;border-top:1px solid #e4e8ef;vertical-align:top}
.lvl{font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:6px;border:1px solid;white-space:nowrap}
a.pin{text-decoration:none;font-size:1rem}
code{background:#f2f5f9;padding:1px 5px;border-radius:4px;font-size:.78rem}
${BO_MOBILE}
</style></head><body><div class="w">
${navBar('threats', { key: req.query.key })}
<h1>Carte des menaces</h1>
<p class="m">${days} derniers jours &middot;
<a href="${ADMIN_ABS}/threats?days=7">7 j</a> · <a href="${ADMIN_ABS}/threats?days=30">30 j</a> · <a href="${ADMIN_ABS}/threats?days=90">90 j</a></p>

<div class="tiles">
  <div class="tile"><b style="color:#a32d2d">${counts.eleve}</b><span>IP a risque eleve</span></div>
  <div class="tile"><b style="color:#8a6d3b">${counts.moyen}</b><span>a surveiller</span></div>
  <div class="tile"><b style="color:#1b354d">${counts.faible}</b><span>signaux faibles</span></div>
  <div class="tile"><b>${mapped.length}</b><span>localisees sur la carte</span></div>
</div>

<div class="card">
  <h2>Origine geographique — <span id="maplabel">${first ? esc((first.city || '') + ', ' + (first.country || '') + ' - ' + first.ip) : 'aucune menace localisee'}</span></h2>
  <iframe id="gmap" title="Carte" loading="lazy" referrerpolicy="no-referrer-when-downgrade"
    src="${first ? `https://maps.google.com/maps?q=${first.lat},${first.lon}&z=5&output=embed` : 'about:blank'}"></iframe>
  <p class="m" style="margin-top:8px">Position approximative de l'IP (precision : ville). Cliquez un &#128205; pour situer une origine.</p>
</div>

<table><thead><tr><th></th><th>Niveau</th><th>Origine</th><th>Organisation</th><th>Signaux</th><th>Requetes</th><th>Derniere</th><th>IP</th></tr></thead>
<tbody>${items.map(i => {
  const [fg, bg, bd] = COL[i.level] || COL.faible;
  return `<tr>
  <td>${i.lat != null ? `<a href="#" class="pin" data-ll="${i.lat},${i.lon}" data-label="${esc((i.city || '') + ' ' + (i.country || '') + ' - ' + i.ip)}">&#128205;</a>` : ''}</td>
  <td data-l="Niveau"><span class="lvl" style="color:${fg};background:${bg};border-color:${bd}">${i.level}</span></td>
  <td data-l="Origine">${esc(i.city || '?')}${i.city ? ', ' : ''}${esc(i.country || '?')}</td>
  <td data-l="Organisation" class="m">${esc(i.org || '-')}</td>
  <td data-l="Signaux">${esc(i.reasons.join(' · '))}${i.samples.length ? `<br><code>${esc(i.samples.join(' '))}</code>` : ''}</td>
  <td data-l="Requetes">${i.n}<br><span class="m">${esc(i.sites.join(', '))}</span></td>
  <td data-l="Derniere" class="m">${fmt(i.last)}</td>
  <td data-l="IP" class="m">${esc(i.ip)}</td></tr>`;
}).join('') || '<tr><td colspan="8">Aucun signal suspect sur la periode : bonne nouvelle.</td></tr>'}</tbody></table>

<p class="m" style="margin-top:16px">Lecture : le score combine les chemins d'attaque connus, les requetes refusees,
les automates, le volume et l'origine geographique. Une IP « hors zone » n'est pas suspecte en soi —
elle ne le devient qu'associee a un autre signal.</p>

<script>
document.addEventListener('click', function(e){
  var a = e.target.closest('a.pin'); if(!a) return; e.preventDefault();
  document.getElementById('gmap').src = 'https://maps.google.com/maps?q=' + a.getAttribute('data-ll') + '&z=8&output=embed';
  document.getElementById('maplabel').textContent = a.getAttribute('data-label');
});
</script>
</div></body></html>`);
  } catch (e) { console.error('threats:', e); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.get('/funnel', async (req, res) => {
  if (!authed(req, res)) return;
  const days = Math.min(parseInt(req.query.days || '30', 10) || 30, 365);
  try {
    const rows = [];
    // Une seule requete a la fois : en parallele, 20 schemas saturent les sessions de l ADB.
    await withEachSite(async (site) => {
      try {
        const one = async (sql) => (await q(site, sql, { d: days })).rows[0].C;
        const vis = await one(`SELECT COUNT(*) c FROM visits WHERE ts >= SYSTIMESTAMP - NUMTODSINTERVAL(:d,'DAY')`);
        const uniq = await one(`SELECT COUNT(DISTINCT ip) c FROM visits WHERE ts >= SYSTIMESTAMP - NUMTODSINTERVAL(:d,'DAY')`);
        const cta = await one(`SELECT COUNT(*) c FROM visits WHERE page LIKE '/cta:%' AND ts >= SYSTIMESTAMP - NUMTODSINTERVAL(:d,'DAY')`);
        const pro = await one(`SELECT COUNT(*) c FROM prospects WHERE created_at >= SYSTIMESTAMP - NUMTODSINTERVAL(:d,'DAY')`);
        const appr = await one(`SELECT COUNT(*) c FROM prospects WHERE status = 'approved' AND created_at >= SYSTIMESTAMP - NUMTODSINTERVAL(:d,'DAY')`);
        rows.push({ site, vis, uniq, cta, pro, appr });
      } catch (e) {
        console.error(`funnel[${site}]:`, e.message.split('\n')[0]);
        rows.push({ site, vis: 0, uniq: 0, cta: 0, pro: 0, appr: 0, err: true });
      }
    });
    const tot = rows.reduce((a, r) => ({
      vis: a.vis + r.vis, uniq: a.uniq + r.uniq, cta: a.cta + r.cta, pro: a.pro + r.pro, appr: a.appr + r.appr,
    }), { vis: 0, uniq: 0, cta: 0, pro: 0, appr: 0 });
    const pct = (a, b) => b ? Math.round((a / b) * 100) + ' %' : '—';
    const steps = [
      ['Visiteurs uniques', tot.uniq, '—'],
      ['Visites', tot.vis, '—'],
      ['Clics sur « Réserver 30 minutes »', tot.cta, pct(tot.cta, tot.uniq)],
      ['Prospects inscrits', tot.pro, pct(tot.pro, tot.uniq)],
      ['Prospects approuvés', tot.appr, pct(tot.appr, tot.pro)],
    ];
    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Tunnel de conversion</title><style>
${BO_CSS}
.w{max-width:900px;margin:0 auto}h1{font-size:1.4rem;color:#1b354d;margin:0 0 4px}
.m{color:#5b6472;font-size:.85rem}a{color:#ae8d57;text-decoration:none}
.step{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:16px 20px;margin-bottom:10px;
 display:flex;align-items:center;justify-content:space-between;gap:16px}
.step .bar{height:10px;background:#1b354d;border-radius:6px;flex:1;max-width:420px;opacity:.85}
.step b{font-size:1.5rem;color:#1b354d;min-width:90px;text-align:right}
.step .lbl{min-width:230px}
.step .cv{color:#ae8d57;font-weight:600;min-width:70px;text-align:right}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;border-radius:12px;overflow:hidden;font-size:.85rem;margin-top:22px}
th{text-align:left;padding:9px 12px;background:#f2f5f9;color:#1b354d;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
td{padding:9px 12px;border-top:1px solid #e4e8ef}
.days a{margin-right:10px}
${BO_MOBILE}
</style></head><body><div class="w">
${navBar('funnel', { key: req.query.key })}
<h1>Tunnel de conversion</h1>
<p class="m">derniers ${days} jours</p>
<p class="m days">Période :
  <a href="${ADMIN_ABS}/funnel?days=7">7 j</a>
  <a href="${ADMIN_ABS}/funnel?days=30">30 j</a>
  <a href="${ADMIN_ABS}/funnel?days=90">90 j</a>
  <a href="${ADMIN_ABS}/funnel?days=365">1 an</a></p>

${steps.map(([lbl, n, cv]) => `<div class="step">
  <span class="lbl">${esc(lbl)}</span>
  <span class="bar" style="max-width:${Math.max(4, Math.round((n / Math.max(1, steps[1][1])) * 420))}px"></span>
  <b>${n}</b><span class="cv">${esc(cv)}</span>
</div>`).join('')}

<table><thead><tr><th>Site</th><th>Visiteurs uniques</th><th>Visites</th><th>Clics CTA</th><th>Inscrits</th><th>Approuvés</th></tr></thead>
<tbody>${rows.map(r => `<tr><td data-l="Site"><b>${esc(r.site)}</b> ${openLink(r.site)}${r.err ? ' <span class="m">(lecture impossible)</span>' : ''}</td><td data-l="Visiteurs uniques">${r.uniq}</td><td data-l="Visites">${r.vis}</td><td data-l="Clics CTA">${r.cta}</td><td data-l="Inscrits">${r.pro}</td><td data-l="Approuves">${r.appr}</td></tr>`).join('')}</tbody></table>

<p class="m" style="margin-top:18px">Les clics sur le bouton de réservation sont comptés via le tracker
(page <code>/cta:calendly</code>). Les rendez-vous réellement tenus et les contrats signés ne sont pas
mesurables automatiquement — à saisir dans les notes du prospect.</p>
</div></body></html>`);
  } catch (e) { console.error('funnel:', e); res.status(500).send('erreur: ' + esc(e.message)); }
});

/**
 * Recherche d un prospect par email (ou nom, societe, telephone) a travers tous les sites.
 *
 * Un prospect est stocke dans le schema du site ou il s est inscrit : sans cette page il
 * faut ouvrir les 29 onglets un par un pour retrouver une adresse. On balaie donc les
 * schemas en sequence — jamais en parallele, l ADB « Always Free » plafonne a 21 sessions.
 */
router.get('/recherche', async (req, res) => {
  if (!authed(req, res)) return;
  const query = String(req.query.q || '').trim().slice(0, 160);
  const key = req.query.key || '';
  try {
    const found = [];
    let scanned = 0, failed = [];
    if (query) {
      const like = '%' + query.toLowerCase() + '%';
      await withEachSite(async (site) => {
        try {
          const r = await q(site, `SELECT id, created_at, first_name, last_name, email, phone,
                     company, interest, status, city, country
                   FROM prospects
                   WHERE LOWER(email) LIKE :p OR LOWER(last_name) LIKE :p
                      OR LOWER(first_name) LIKE :p OR LOWER(company) LIKE :p
                      OR LOWER(phone) LIKE :p
                   ORDER BY created_at DESC FETCH FIRST 50 ROWS ONLY`, { p: like });
          scanned++;
          r.rows.forEach(p => found.push({ site, p }));
        } catch (e) {
          console.error(`recherche[${site}]:`, e.message.split('\n')[0]);
          failed.push(site);
        }
      });
      found.sort((a, b) => new Date(b.p.CREATED_AT) - new Date(a.p.CREATED_AT));
    }

    const fmt = t => t ? new Date(t).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—';
    const badge = st => ({ approved: '#1d7a4f', email_verified: '#ae8d57', pending: '#8a8f98', rejected: '#a32d2d' }[st] || '#8a8f98');
    const kq = key ? `&key=${encodeURIComponent(key)}` : '';

    const rows = found.map(({ site, p }) => `<tr onclick="location.href='${ADMIN_ABS}/prospect?site=${encodeURIComponent(site)}&id=${p.ID}${kq}'" style="cursor:pointer">
      <td data-l="Site"><b>${esc(site)}</b> ${secDot(site)}</td>
      <td data-l="Personne"><b>${esc(p.FIRST_NAME)} ${esc(p.LAST_NAME)}</b><br><span class="m">${esc(p.COMPANY || '')}</span></td>
      <td data-l="Contact">${esc(p.EMAIL)}<br><span class="m">${esc(p.PHONE || '')}</span></td>
      <td data-l="Objet">${esc(p.INTEREST || '')}</td>
      <td data-l="Lieu">${esc(p.CITY || '')} ${esc(p.COUNTRY || '')}</td>
      <td data-l="Statut"><span style="color:${badge(p.STATUS)};font-weight:600">${esc(p.STATUS)}</span></td>
      <td data-l="Inscrit">${fmt(p.CREATED_AT)}</td></tr>`).join('');

    const result = !query
      ? `<p class="m">Tapez une adresse email, un nom, une societe ou un telephone.
           La recherche porte sur les ${Object.keys(SITES).length} sites a la fois.</p>`
      : found.length === 0
        ? `<p class="m">Aucun prospect ne correspond a « ${esc(query)} » sur les ${scanned} sites lus.</p>`
        : `<p class="m"><b>${found.length}</b> resultat${found.length > 1 ? 's' : ''} sur
             ${new Set(found.map(f => f.site)).size} site${new Set(found.map(f => f.site)).size > 1 ? 's' : ''},
             ${scanned} schemas lus.</p>
           <table><thead><tr><th>Site</th><th>Personne</th><th>Contact</th><th>Objet</th>
             <th>Lieu</th><th>Statut</th><th>Inscrit</th></tr></thead><tbody>${rows}</tbody></table>`;

    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Recherche prospect</title><style>
${BO_CSS}
.srch{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 10px}
.srch input{flex:1 1 320px;min-width:0;font:inherit;font-size:1rem;padding:11px 16px;
 border:1px solid #e4e8ef;border-radius:10px;background:#fff;color:#14202e;-webkit-appearance:none}
.srch input:focus{outline:none;border-color:#1b354d;box-shadow:0 0 0 3px rgba(27,53,77,.12)}
.srch button{flex:0 0 auto;background:#1b354d;color:#fff;border:none;border-radius:10px;
 padding:11px 22px;font:inherit;font-weight:600;cursor:pointer}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;vertical-align:middle}
${BO_MOBILE}
</style></head><body><div class="w">
${navBar('recherche', { key })}
<h1>Recherche</h1>
<form class="srch" method="get" action="${ADMIN_ABS}/recherche" role="search">
  ${key ? `<input type="hidden" name="key" value="${esc(key)}">` : ''}
  <input type="search" name="q" value="${esc(query)}" autocomplete="off" autofocus
         placeholder="email, nom, societe ou telephone" aria-label="Rechercher un prospect">
  <button type="submit">Chercher</button>
</form>
${failed.length ? `<p class="m">Sites illisibles : ${esc(failed.join(', '))}.</p>` : ''}
${result}
</div></body></html>`);
  } catch (e) { console.error('recherche:', e); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.get('/share', async (req, res) => {
  if (!authed(req, res)) return;
  try {
    const cards = [];
    await withEachSite(async (site) => {
      const db = await dbMeta(site);
      const auto = await siteMeta(site);
      const m = db && (db.title || db.desc || db.img) ? db : auto;
      const src = db && (db.title || db.desc || db.img) ? 'enregistre en base' : 'lu automatiquement sur le site';
      cards.push(`
      <form class="card" method="post" action="${ADMIN_ABS}/share/save">
        <input type="hidden" name="site" value="${esc(site)}">
        <div class="head">
          <h2>${esc(site)}</h2>
          <span class="tag">${esc(src)}</span>
        </div>
        <div class="prev">
          <img src="${BASE_ABS}/img?site=${encodeURIComponent(site)}&v=${Date.now()}" alt="">
          <div>
            <label>Titre affiche</label>
            <input name="title" value="${esc(m.title || '')}" maxlength="300">
            <label>Description</label>
            <input name="descr" value="${esc(m.desc || '')}" maxlength="600">
            <label>Image (URL complete, vide = image du site)</label>
            <input name="img" value="${esc(m.img || '')}" maxlength="600">
          </div>
        </div>
        <div class="row">
          <button type="submit">Enregistrer</button>
          <button type="submit" formaction="${ADMIN_ABS}/share/delete" class="alt"
            onclick="return confirm('Revenir a la lecture automatique pour ${esc(site)} ?')">Supprimer la fiche</button>
          <a class="lnk" href="${siteUrl(site)}" target="_blank" rel="noopener">${esc(siteUrl(site))}</a>
        </div>
      </form>`);
    });
    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Liens partages</title><style>
${BO_CSS}
.w{max-width:900px;margin:0 auto}h1{font-size:1.4rem;color:#1b354d;margin:0 0 4px}
.card{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:20px;margin-bottom:16px}
.head{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.head h2{font-size:1.05rem;color:#1b354d;margin:0}
.tag{font-size:.72rem;color:#8a6d3b;background:#f4ede0;border:1px solid #e6d9c2;border-radius:6px;padding:2px 8px}
.prev{display:grid;grid-template-columns:200px 1fr;gap:16px;align-items:start}
@media(max-width:640px){.prev{grid-template-columns:1fr}}
.prev img{width:100%;border-radius:10px;border:1px solid #e4e8ef;background:#f2f5f9}
label{display:block;font-size:.74rem;font-weight:600;color:#1b354d;margin:10px 0 3px}
input{width:100%;padding:9px 11px;border:1px solid #e4e8ef;border-radius:8px;font:inherit;font-size:.9rem}
input:focus{outline:none;border-color:#ae8d57}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px}
button{padding:9px 16px;border:none;border-radius:9px;background:#1b354d;color:#fff;font:inherit;font-weight:600;font-size:.86rem;cursor:pointer}
button.alt{background:#fff;color:#1b354d;border:1px solid #e4e8ef}
button.alt:hover{border-color:#a32d2d;color:#a32d2d}
a{color:#ae8d57;text-decoration:none;font-size:.82rem}
.m{color:#5b6472;font-size:.85rem}
${BO_MOBILE}
</style></head><body><div class="w">
${navBar('share', { key: req.query.key })}
<h1>Liens partages</h1>
<p class="m">Ce que voient WhatsApp, LinkedIn ou iMessage quand vous partagez un lien protege.
${req.query.ok ? `<b style="color:#1d7a4f"> &middot; ${esc(req.query.ok)}</b>` : ''}</p>
${cards.join('')}
<p class="m">Astuce : WhatsApp garde l'apercu en cache. Ajoutez <code>?v=2</code> a la fin du lien pour forcer sa regeneration.</p>
</div></body></html>`);
  } catch (e) { console.error('share:', e); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.post('/share/save', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  if (!site) return res.status(400).send('site inconnu');
  try {
    await ensureShareTable(site);
    await q(site, `MERGE INTO share_meta d USING (SELECT 1 id FROM dual) x ON (d.id = x.id)
      WHEN MATCHED THEN UPDATE SET title=:t, descr=:d, img=:i, updated_at=SYSTIMESTAMP
      WHEN NOT MATCHED THEN INSERT (id, title, descr, img) VALUES (1, :t2, :d2, :i2)`, {
      t: cut(req.body.title, 300), d: cut(req.body.descr, 600), i: cut(req.body.img, 600),
      t2: cut(req.body.title, 300), d2: cut(req.body.descr, 600), i2: cut(req.body.img, 600) });
    metaCache.delete(site);
    console.log(`[share] fiche ${site} enregistree`);
    res.redirect(302, `${ADMIN_ABS}/share?ok=${encodeURIComponent('Fiche ' + site + ' enregistree')}`);
  } catch (e) { console.error('share-save:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

router.post('/share/delete', form, async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.body.site] ? req.body.site : null;
  if (!site) return res.status(400).send('site inconnu');
  try {
    await ensureShareTable(site);
    await q(site, 'DELETE FROM share_meta WHERE id = 1');
    metaCache.delete(site);
    console.log(`[share] fiche ${site} supprimee (retour automatique)`);
    res.redirect(302, `${ADMIN_ABS}/share?ok=${encodeURIComponent(site + ' : lecture automatique retablie')}`);
  } catch (e) { console.error('share-delete:', e.message); res.status(500).send('erreur: ' + esc(e.message)); }
});

// racine du back-office : montee a la fois sur /tracker (via app.get) et sur /<base>/tracker
const trackerPage = async (req, res) => {
  if (!authed(req, res)) return;
  const site = SITES[req.query.site] ? req.query.site : Object.keys(SITES)[0];
  try {
    const [today, week, uniq, ident, pages, refs, last] = await Promise.all([
      q(site, `SELECT COUNT(*) c FROM visits WHERE ts >= TRUNC(SYSDATE)`),
      q(site, `SELECT COUNT(*) c FROM visits WHERE ts >= SYSTIMESTAMP - INTERVAL '7' DAY`),
      q(site, `SELECT COUNT(DISTINCT ip) c FROM visits WHERE ts >= SYSTIMESTAMP - INTERVAL '7' DAY`),
      q(site, `SELECT COUNT(*) c FROM visits WHERE prospect_id IS NOT NULL AND ts >= SYSTIMESTAMP - INTERVAL '7' DAY`),
      q(site, `SELECT page, COUNT(*) c FROM visits WHERE ts >= SYSTIMESTAMP - INTERVAL '7' DAY
               GROUP BY page ORDER BY COUNT(*) DESC FETCH FIRST 10 ROWS ONLY`),
      q(site, `SELECT referrer, COUNT(*) c FROM visits WHERE ts >= SYSTIMESTAMP - INTERVAL '7' DAY
               AND referrer IS NOT NULL GROUP BY referrer ORDER BY COUNT(*) DESC FETCH FIRST 10 ROWS ONLY`),
      q(site, `SELECT v.*, p.first_name, p.last_name, p.company FROM visits v
               LEFT JOIN prospects p ON p.id = v.prospect_id
               ORDER BY v.ts DESC FETCH FIRST 150 ROWS ONLY`),
    ]);
    const fmt = t => t ? new Date(t).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-';
    const first = last.rows.find(v => v.LAT != null);
    const li = (arr, k) => arr.map(r => `<li><span>${esc(r[k] || '-')}</span><b>${r.C}</b></li>`).join('');
    // onglets groupes par famille, sur plusieurs lignes
    const FAMILIES = [
      ['Sites vitrine', ['arxcapital', 'training', 'axperience', 'nice', 'nissai', 'chef-jason',
                         'antonweb', 'mcp-root']],
      ['Dossiers prives', ['50', '877', 'cactus', '3point']],
      ['Applications', ['blackstone', 'candidatures', 'prospects', 'gate', 'tracker',
                        'mail-review', 'whatsapp']],
      ['Serveurs MCP', ['mcp-einstein', 'mcp-prisme', 'mcp-immo-rapido', 'mcp-hilde', 'mcp-saul', 'omni']],
      ['Donnees & infra', ['data-api', 'db-prisme', 'db-cv', 'db-saul', 'db-tcm', 'minio', 'coolify', 'mailbot-api', 'n8n']],
    ];
    const known = new Set(FAMILIES.flatMap(f => f[1]));
    const others = Object.keys(SITES).filter(x => !known.has(x));
    if (others.length) FAMILIES.push(['Autres', others]);
    const tab = x => `<span class="tabwrap"><a href="${ADMIN_ABS}?site=${x}" class="tab${x === site ? ' on' : ''}">${esc(x)}${secDot(x)}</a>${infoDot(x)}${openLink(x)}</span>`;
    const tabs = FAMILIES.filter(([, list]) => list.some(x => SITES[x]))
      .map(([name, list]) => `<div class="tabrow"><span class="tabfam">${esc(name)}</span>${
        list.filter(x => SITES[x]).map(tab).join('')}</div>`).join('');
    const rows = last.rows.map(v => `<tr>
      <td>${v.LAT != null ? `<a href="#map" class="pin" data-ll="${v.LAT},${v.LON}" data-label="${esc((v.CITY || '') + ' ' + (v.COUNTRY || '') + ' - ' + v.IP)}">&#128205;</a>` : ''}</td>
      <td data-l="Quand">${fmt(v.TS)}</td>
      <td data-l="Prospect">${v.PROSPECT_ID ? `<a href="${ADMIN_ABS}/prospect?site=${site}&id=${v.PROSPECT_ID}"><b>${esc(v.FIRST_NAME || '')} ${esc(v.LAST_NAME || '')}</b><br><span class="m">${esc(v.COMPANY || '')}</span></a>` : '<span class="m">anonyme</span>'}</td>
      <td data-l="Page">${esc(v.PAGE || '')}</td>
      <td data-l="Ville, pays">${esc(v.CITY || '')}${v.CITY ? ', ' : ''}${esc(v.COUNTRY || '')}</td>
      <td data-l="Organisation / ISP" class="m">${esc(v.ORG || v.ISP || '')}</td>
      <td data-l="Appareil" class="m">${esc(v.BROWSER || '')} &middot; ${esc(v.OS || '')} &middot; ${esc(v.DEVICE || '')}</td>
      <td data-l="Securite">${secBadge(site, v.PAGE, v.REFERRER)}</td>
      <td data-l="Referrer" class="m">${esc(v.REFERRER || '-')}</td>
      <td data-l="IP" class="m">${esc(v.IP || '')}</td></tr>`).join('');
    res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Tracker - ${esc(site)}</title><style>
${BO_CSS}
.w{max-width:1250px;margin:0 auto}h1{font-size:1.4rem;margin:0 0 4px;color:#1b354d}
h2{font-size:.95rem;margin-bottom:10px;color:#1b354d}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}
.tile{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:16px}
.tile b{display:block;font-size:1.7rem;color:#1b354d}.tile span{color:#5b6472;font-size:.8rem}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
@media(max-width:760px){.cols{grid-template-columns:1fr}}
.card{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:18px}
.card ul{list-style:none;margin:0;padding:0}
.card li{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid #e4e8ef;font-size:.85rem}
.card li span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#5b6472}.card li b{color:#ae8d57}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ef;border-radius:12px;overflow:hidden;font-size:.82rem}
th{text-align:left;padding:9px 10px;background:#f2f5f9;color:#1b354d;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em}
td{padding:8px 10px;border-top:1px solid #e4e8ef;vertical-align:top;max-width:220px;overflow:hidden;text-overflow:ellipsis}
.m{color:#5b6472;font-size:.78rem}a{color:#ae8d57;text-decoration:none}a.pin{font-size:1rem}
.sec{display:inline-block;font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:6px;border:1px solid;white-space:nowrap}
.tabrow{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px}
.tabfam{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:#8a8f98;min-width:150px}
.tab{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border:1px solid #e4e8ef;border-radius:8px;
 text-decoration:none;color:#1b354d;background:#fff;font-size:.85rem}
.tab.on{background:#1b354d;color:#fff;border-color:#1b354d}
.tabwrap{display:inline-flex;align-items:center;gap:4px}.tabwrap>a:last-child{color:#ae8d57}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block}
.threat{background:#fff;border:1px solid #e4e8ef;border-radius:12px;padding:18px;margin-bottom:20px}
.threat h2{margin-bottom:12px}
.trow{display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:center;padding:8px 0;border-top:1px solid #e4e8ef;font-size:.85rem}
.trow:first-of-type{border-top:0}
.lvl{font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:6px;border:1px solid;white-space:nowrap}
iframe{width:100%;height:320px;border:0;border-radius:10px}
.nav a{margin-right:10px}
${BO_MOBILE}
</style></head><body><div class="w">
${navBar('tracker', { site, key: req.query.key })}
<h1>Tracker</h1>
<p class="m nav">Schema Oracle dedie par site
&middot; protection de ce site : ${secBadge(site, '', '')} <span class="m">${esc((SECURITY[site] || {}).detail || '')}</span></p>
<div style="margin:14px 0">${tabs}</div>
<div class="tiles">
  <div class="tile"><b>${today.rows[0].C}</b><span>visites aujourd'hui</span></div>
  <div class="tile"><b>${week.rows[0].C}</b><span>visites - 7 jours</span></div>
  <div class="tile"><b>${uniq.rows[0].C}</b><span>visiteurs uniques - 7 j</span></div>
  <div class="tile"><b>${ident.rows[0].C}</b><span>visites identifiees - 7 j</span></div>
</div>
<div class="cols">
  <div class="card"><h2>Top pages - 7 jours</h2><ul>${li(pages.rows, 'PAGE')}</ul></div>
  <div class="card"><h2>Top referrers - 7 jours</h2><ul>${li(refs.rows, 'REFERRER') || '<li><span>aucun</span><b>0</b></li>'}</ul></div>
</div>
<div class="card" id="map" style="margin-bottom:20px">
  <h2>Localisation - <span id="maplabel">${first ? esc((first.CITY || '') + ', ' + (first.COUNTRY || '') + ' - ' + first.IP) : 'aucune visite geolocalisee'}</span></h2>
  <iframe id="gmap" title="Carte" loading="lazy" referrerpolicy="no-referrer-when-downgrade"
    src="${first ? `https://maps.google.com/maps?q=${first.LAT},${first.LON}&z=11&output=embed` : 'about:blank'}"></iframe>
  <p class="m" style="margin-top:8px">Position approximative de l'IP. Cliquez un &#128205; pour situer une visite.</p>
</div>
<table><thead><tr><th></th><th>Quand</th><th>Prospect</th><th>Page</th><th>Ville, pays</th><th>Organisation / ISP</th><th>Appareil</th><th>Securite</th><th>Referrer</th><th>IP</th></tr></thead>
<tbody>${rows || '<tr><td colspan="9">Aucune visite.</td></tr>'}</tbody></table>
<script>
document.addEventListener('click', function(e){
  var a = e.target.closest('a.pin'); if(!a) return;
  document.getElementById('gmap').src = 'https://maps.google.com/maps?q=' + a.getAttribute('data-ll') + '&z=11&output=embed';
  document.getElementById('maplabel').textContent = a.getAttribute('data-label');
});
</script>
</div></body></html>`);
  } catch (e) { console.error('tracker:', e); res.status(500).send('erreur: ' + esc(e.message)); }
};
router.get('/tracker', trackerPage);

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
${BO_CSS}
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
.kv input,.kv select{width:100%;padding:8px 10px;border:1px solid #e4e8ef;border-radius:8px;font:inherit;font-size:.9rem;margin-top:2px}
.kv input:focus,.kv select:focus{outline:none;border-color:#ae8d57}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
.actions button{padding:10px 18px;border:none;border-radius:9px;background:#1b354d;color:#fff;font:inherit;font-weight:600;font-size:.88rem;cursor:pointer}
.actions button:hover{background:#2c4a68}
.actions button.alt{background:#fff;color:#1b354d;border:1px solid #e4e8ef}
.actions button.alt:hover{border-color:#ae8d57;color:#ae8d57}
.actions button.danger{background:#a32d2d}.actions button.danger:hover{background:#c23c3c}
${BO_MOBILE}
</style></head><body><div class="w">
<p><a href="${ADMIN_ABS}/admin?site=${site}">&larr; retour aux prospects (${esc(site)})</a></p>
<h1>${esc(p.FIRST_NAME)} ${esc(p.LAST_NAME)}</h1>
<p class="m">${esc(p.COMPANY || '')} &middot; ${esc(p.INTEREST || '')} &middot; statut <b>${esc(p.STATUS)}</b></p>
${req.query.ok ? `<p style="background:#e6f4ec;border:1px solid #b7e0c8;color:#1d7a4f;padding:10px 14px;border-radius:9px">${esc(req.query.ok)}</p>` : ''}

<h2>Modifier la fiche</h2>
<form class="card" method="post" action="${ADMIN_ABS}/prospect/save">
  <input type="hidden" name="site" value="${esc(site)}"><input type="hidden" name="id" value="${p.ID}">
  <div class="kv">
    <div><span>Prenom</span><input name="first_name" value="${esc(p.FIRST_NAME || '')}" maxlength="80"></div>
    <div><span>Nom</span><input name="last_name" value="${esc(p.LAST_NAME || '')}" maxlength="80"></div>
    <div><span>Email</span><input name="email" type="email" value="${esc(p.EMAIL || '')}" maxlength="160"></div>
    <div><span>Telephone</span><input name="phone" value="${esc(p.PHONE || '')}" maxlength="40"></div>
    <div><span>Societe</span><input name="company" value="${esc(p.COMPANY || '')}" maxlength="160"></div>
    <div><span>Objet</span><input name="interest" value="${esc(p.INTEREST || '')}" maxlength="60"></div>
    <div><span>Statut</span><select name="status">
      ${['pending', 'email_verified', 'approved', 'rejected'].map(x => `<option${p.STATUS === x ? ' selected' : ''}>${x}</option>`).join('')}
    </select></div>
    <div><span>Notes</span><input name="notes" value="${esc(p.NOTES || '')}" maxlength="500"></div>
  </div>
  <div class="actions">
    <button type="submit">Enregistrer</button>
    <button type="submit" formaction="${ADMIN_ABS}/prospect/access" class="alt">Renvoyer un lien d'acces</button>
    <button type="submit" formaction="${ADMIN_ABS}/prospect/revoke" class="alt">Revoquer les acces</button>
    <button type="submit" formaction="${ADMIN_ABS}/prospect/delete" class="danger"
      onclick="return confirm('Supprimer definitivement ce prospect, ses sessions et ses visites liees ?')">Supprimer</button>
  </div>
</form>

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

${ll ? `<h2 id="map">Localisation approximative</h2><div class="card"><iframe loading="lazy" referrerpolicy="no-referrer-when-downgrade"
  src="https://maps.google.com/maps?q=${ll.LAT},${ll.LON}&z=11&output=embed"></iframe></div>` : ''}

<h2>Pages les plus consultees</h2>
<table><thead><tr><th>Page</th><th>Vues</th><th>Derniere</th></tr></thead><tbody>
${agg.rows.map(a => `<tr><td data-l="Page">${esc(a.PAGE)}</td><td data-l="Vues">${a.C}</td><td data-l="Derniere" class="m">${fmt(a.LAST_TS)}</td></tr>`).join('') || '<tr><td colspan="3">Aucune visite tracee.</td></tr>'}
</tbody></table>

<h2>Parcours detaille</h2>
<table><thead><tr><th>Quand</th><th>Page</th><th>Venu de</th><th>Appareil</th><th>Ville</th><th>IP</th></tr></thead><tbody>
${vis.rows.map(v => `<tr><td data-l="Quand">${fmt(v.TS)}</td><td data-l="Page">${esc(v.PAGE)}</td><td data-l="Venu de" class="m">${esc(v.REFERRER || '-')}</td>
  <td data-l="Appareil" class="m">${esc(v.BROWSER)} ${esc(v.OS)} ${esc(v.DEVICE)}</td><td data-l="Ville" class="m">${esc(v.CITY || '')}</td>
  <td data-l="IP" class="m">${esc(v.IP)}</td></tr>`).join('') || '<tr><td colspan="6">Aucune visite tracee.</td></tr>'}
</tbody></table>

<h2>Journal d'acces</h2>
<table><thead><tr><th>Quand</th><th>Evenement</th><th>Depuis</th></tr></thead><tbody>
${acc.rows.map(a => `<tr><td data-l="Quand">${fmt(a.TS)}</td><td data-l="Evenement">${esc(a.EVENT)}</td><td data-l="Depuis" class="m">${esc(a.IP)}</td></tr>`).join('') || '<tr><td colspan="3">-</td></tr>'}
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

router.use('/p', express.static(path.join(__dirname, 'public'), { maxAge: '7d' }));

// image de partage : recuperee sur le site protege et servie publiquement
router.get('/img', async (req, res) => {
  const site = SITES[req.query.site] ? req.query.site : null;
  if (!site) return res.sendStatus(404);
  try {
    const m = await siteMeta(site);
    if (!m.img) return res.redirect(302, `${BASE_ABS}/p/preview-arxcapital.png`);
    const r = await fetch(m.img, { headers: { 'X-Gate-Bot': botToken(site) }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return res.redirect(302, `${BASE_ABS}/p/preview-arxcapital.png`);
    res.set('Content-Type', r.headers.get('content-type') || 'image/jpeg');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(await r.arrayBuffer()));
  } catch (e) { console.error('img:', e.message); res.redirect(302, `${BASE_ABS}/p/preview-arxcapital.png`); }
});
router.get('/health', (req, res) => res.send('ok'));

// Anciens chemins du back-office sous /gate -> /tracker. Traefik retire le prefixe /gate
// avant de nous transmettre la requete, mais laisse l entete X-Forwarded-Prefix : c est
// le seul moyen de distinguer /gate/admin de /admin.
const LEGACY = /^\/(visits|tracker|admin|funnel|threats|share|prospect)(\/.*)?$/;
app.use((req, res, next) => {
  if (req.method !== 'GET' || !BASE_ABS) return next();
  if ((req.headers['x-forwarded-prefix'] || '') !== BASE_ABS) return next();
  const m = req.path.match(LEGACY);
  if (!m) return next();
  const section = (m[1] === 'visits' || m[1] === 'tracker') ? '' : '/' + m[1];
  const qs = req.originalUrl.split('?')[1];
  res.redirect(301, `${ADMIN_ABS}${section}${m[2] || ''}${qs ? '?' + qs : ''}`);
});

app.use('/', router);
const BASE = process.env.BASE_PATH;
if (BASE && BASE !== '/') app.use(BASE, router);
// back-office : /tracker rend la page tracker, /tracker/<section> le reste du menu
if (ADMIN_ABS) {
  app.get(ADMIN_ABS, trackerPage);
  app.use(ADMIN_ABS, router);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(
  `arx-gate :${PORT} base «${BASE || '/'}» · back-office «${ADMIN_ABS}» · sites: ${Object.keys(SITES).join(', ')} · email ${EMAIL_ON ? 'ON' : 'OFF'} · ntfy ${NTFY_URL ? 'ON' : 'OFF'}`));
