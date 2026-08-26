// Premiers tests de arx-gate. Le depot n'en avait aucun, alors que c'est la
// porte par laquelle transitent tous les sites et tout le tracage du parc.
//
// Runner : node:test, integre a Node 20+. Aucune dependance ajoutee.
// Le secret doit etre pose AVANT le require : sign() le lit a l'import.
process.env.GATE_SECRET = 'secret-de-test-arx-gate';

const test = require('node:test');
const assert = require('node:assert');
const {
  makeCookieValue, parseCookieValue, readCookie,
  siteFromForward, clientIp, parseUa, absolute, cut,
} = require('../server.js');

// --- Cookie prospect : c'est lui qui autorise l'acces aux sites protegees ---
// Une signature falsifiable ouvrirait ces sites a n'importe qui.

test('un cookie fabrique se relit a l identique', () => {
  const v = makeCookieValue('arxcapital', 42, 'jeton-abc');
  assert.deepStrictEqual(parseCookieValue(v), {
    site: 'arxcapital', id: 42, token: 'jeton-abc',
  });
});

test('une signature alteree est rejetee', () => {
  const v = makeCookieValue('arxcapital', 42, 'jeton-abc');
  const parts = v.split('.');
  parts[3] = parts[3].split('').reverse().join('');
  assert.strictEqual(parseCookieValue(parts.join('.')), null);
});

test('un identifiant modifie invalide la signature', () => {
  const v = makeCookieValue('arxcapital', 42, 'jeton-abc');
  const parts = v.split('.');
  parts[1] = '99';                       // usurpation d un autre prospect
  assert.strictEqual(parseCookieValue(parts.join('.')), null);
});

test('un site modifie invalide la signature', () => {
  const v = makeCookieValue('arxcapital', 42, 'jeton-abc');
  const parts = v.split('.');
  parts[0] = 'chef-jason';               // acces lateral vers un autre site
  assert.strictEqual(parseCookieValue(parts.join('.')), null);
});

test('un cookie malforme ne fait pas planter', () => {
  for (const v of [null, '', 'abc', 'a.b.c', 'a.b.c.d.e']) {
    assert.strictEqual(parseCookieValue(v), null, `entree : ${JSON.stringify(v)}`);
  }
});

test('un cookie valide suivi de dechet est rejete', () => {
  // Sans controle de longueur, la signature ne porte que sur les trois
  // premieres parties : tout ce qui suit passerait inapercu.
  const v = makeCookieValue('arxcapital', 42, 'jeton-abc');
  assert.strictEqual(parseCookieValue(v + '.dechet'), null);
});

// --- Lecture d en-tetes : entrees non fiables, venues du reseau ---

test('readCookie extrait la bonne valeur parmi plusieurs', () => {
  const req = { headers: { cookie: 'autre=1; agp=valeur-cible; suivant=2' } };
  assert.strictEqual(readCookie(req, 'agp'), 'valeur-cible');
});

test('readCookie rend null quand le cookie manque', () => {
  assert.strictEqual(readCookie({ headers: {} }, 'agp'), null);
  assert.strictEqual(readCookie({ headers: { cookie: 'autre=1' } }, 'agp'), null);
});

test('clientIp prend la premiere adresse de x-forwarded-for', () => {
  const req = { headers: { 'x-forwarded-for': '1.2.3.4, 10.0.0.1' }, socket: {} };
  assert.strictEqual(clientIp(req), '1.2.3.4');
});

test('clientIp retombe sur la socket sans en-tete', () => {
  assert.strictEqual(clientIp({ headers: {}, socket: { remoteAddress: '5.6.7.8' } }), '5.6.7.8');
});

test('siteFromForward rejette un site inconnu', () => {
  // SITES est vide en test : aucun segment ne doit etre accepte.
  assert.strictEqual(siteFromForward({ headers: { 'x-forwarded-uri': '/inconnu/page' } }), null);
  assert.strictEqual(siteFromForward({ headers: {} }), null);
});

// --- Aides de rendu ---

test('cut tronque a la longueur demandee', () => {
  assert.strictEqual(cut('abcdef', 3), 'abc');
  assert.strictEqual(cut('ab', 10), 'ab');
});

test('absolute resout une URL relative sur sa base', () => {
  assert.strictEqual(absolute('https://exemple.fr/a/b', '/c'), 'https://exemple.fr/c');
});

test('parseUa reconnait un navigateur courant', () => {
  const r = parseUa('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    + '(KHTML, like Gecko) Chrome/120.0 Safari/537.36');
  assert.ok(r.browser, 'navigateur non identifie');
  assert.ok(r.os, 'systeme non identifie');
});
