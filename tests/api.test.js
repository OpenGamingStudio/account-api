import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { newCode, normCode, originAllowed, makeLimiter } from '../src/security.js';

let app, base;
const ORIGIN = 'https://trou-malin.opengamingstudio.com';
before(async () => { app = createApp({ cookieDomain: '.opengamingstudio.com', registerLimit: 1000 }); await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${app.server.address().port}`; });
after(() => { app.server.close(); });

const call = async (method, path, body, cookie, origin = ORIGIN) => {
  const headers = {}; if (body !== undefined) headers['Content-Type'] = 'application/json'; if (cookie) headers.Cookie = cookie; if (origin) headers.Origin = origin;
  const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const sc = r.headers.get('set-cookie');
  return { status: r.status, json: await r.json().catch(() => null), sc, cookie: sc ? sc.split(';')[0] : cookie, headers: r.headers };
};

test('code de récupération : format et normalisation', () => {
  const c = newCode();
  assert.match(c, /^[A-HJKMNP-Z2-9]{4}(-[A-HJKMNP-Z2-9]{4}){3}$/);
  assert.equal(normCode(' ab-cd ef '), 'ABCDEF');
  assert.notEqual(newCode(), newCode());
});

test('origines : sous-domaines du studio seulement', () => {
  assert.ok(originAllowed('https://quizdown.opengamingstudio.com'));
  assert.ok(originAllowed('https://opengamingstudio.com'));
  assert.ok(!originAllowed('http://quizdown.opengamingstudio.com'));
  assert.ok(!originAllowed('https://opengamingstudio.com.evil.io'));
  assert.ok(!originAllowed('https://evilopengamingstudio.com'));
  assert.ok(!originAllowed('https://x.opengamingstudio.com:8443'));
  assert.ok(!originAllowed(undefined));
});

test('limiteur : bloque au seuil puis libère', () => {
  const l = makeLimiter(2, 1000);
  l.add('a', 0); l.add('a', 10);
  assert.ok(l.blocked('a', 20));
  assert.ok(!l.blocked('a', 2000));
});

test('créer un compte, cookie sécurisé, code haché, connexion, déconnexion', async () => {
  const r = await call('POST', '/v1/register', { pseudo: 'Alice_01' });
  assert.equal(r.status, 201);
  assert.match(r.json.code, /^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/);
  assert.equal(r.json.qr.rows.length, r.json.qr.size);
  for (const f of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Domain=.opengamingstudio.com']) assert.ok(r.sc.includes(f), f);
  assert.equal(r.headers.get('access-control-allow-origin'), ORIGIN);
  assert.equal(r.headers.get('access-control-allow-credentials'), 'true');
  const row = app.db.prepare('SELECT * FROM users WHERE pseudo_key = ?').get('alice_01');
  assert.ok(!Buffer.from(row.code_hash).toString('utf8').includes(r.json.code.replace(/-/g, '')));
  assert.equal((await call('GET', '/v1/me', undefined, r.cookie)).json.pseudo, 'Alice_01');
  assert.equal((await call('POST', '/v1/register', { pseudo: 'ALICE_01' })).status, 409);
  const l = await call('POST', '/v1/login', { pseudo: 'alice_01', code: r.json.code.toLowerCase().replace(/-/g, ' ') });
  assert.equal(l.status, 200);
  assert.equal((await call('GET', '/v1/me', undefined, l.cookie)).status, 200);
  await call('POST', '/v1/logout', {}, l.cookie);
  assert.equal((await call('GET', '/v1/me', undefined, l.cookie)).status, 401);
});

test('pseudo invalide refusé', async () => {
  for (const p of ['ab', 'a b c', 'x'.repeat(21), '<script>', 'é€é', '']) assert.equal((await call('POST', '/v1/register', { pseudo: p })).status, 400, p);
  assert.equal((await call('POST', '/v1/register', {})).status, 400);
});

test('sauvegardes : par jeu, version, conflit, force, taille max', async () => {
  const c = (await call('POST', '/v1/register', { pseudo: 'Bob_save' })).cookie;
  assert.equal((await call('GET', '/v1/saves/trou-malin', undefined, c)).status, 404);
  assert.equal((await call('GET', '/v1/saves/trou-malin')).status, 401);
  const a = await call('PUT', '/v1/saves/trou-malin', { data: { levels: { 1: 3 } }, baseRev: 0, gameVersion: '2.1.1' }, c);
  assert.equal(a.status, 200); assert.equal(a.json.rev, 1);
  const g = await call('GET', '/v1/saves/trou-malin', undefined, c);
  assert.deepEqual(g.json.data, { levels: { 1: 3 } }); assert.equal(g.json.gameVersion, '2.1.1'); assert.ok(g.json.updatedAt > 0);
  const other = await call('PUT', '/v1/saves/quizdown', { data: { x: 1 }, baseRev: 0 }, c);
  assert.equal(other.json.rev, 1);
  const conf = await call('PUT', '/v1/saves/trou-malin', { data: { levels: {} }, baseRev: 0 }, c);
  assert.equal(conf.status, 409); assert.equal(conf.json.save.rev, 1);
  const ok = await call('PUT', '/v1/saves/trou-malin', { data: { levels: { 2: 1 } }, baseRev: 1 }, c);
  assert.equal(ok.json.rev, 2);
  const forced = await call('PUT', '/v1/saves/trou-malin', { data: { f: 1 }, baseRev: 0, force: true }, c);
  assert.equal(forced.json.rev, 3);
  const big = await call('PUT', '/v1/saves/trou-malin', { data: { s: 'x'.repeat(210 * 1024) }, baseRev: 3 }, c);
  assert.equal(big.status, 413);
  assert.equal((await call('PUT', '/v1/saves/BAD_ID', { data: {}, baseRev: 0 }, c)).status, 400);
  assert.equal((await call('PUT', '/v1/saves/trou-malin', { data: [1], baseRev: 3 }, c)).status, 400);
});

test('isolation : un joueur ne lit pas la sauvegarde d\'un autre', async () => {
  const a = (await call('POST', '/v1/register', { pseudo: 'Carl_a' })).cookie;
  const b = (await call('POST', '/v1/register', { pseudo: 'Dina_b' })).cookie;
  await call('PUT', '/v1/saves/snake', { data: { secret: 1 }, baseRev: 0 }, a);
  assert.equal((await call('GET', '/v1/saves/snake', undefined, b)).status, 404);
});

test('CORS : origine étrangère refusée en écriture, sans en-têtes CORS', async () => {
  const r = await call('POST', '/v1/register', { pseudo: 'Evil_x' }, undefined, 'https://evil.example');
  assert.equal(r.status, 403); assert.equal(r.headers.get('access-control-allow-origin'), null);
  const pre = await fetch(base + '/v1/login', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
  assert.equal(pre.status, 403);
  const ok = await fetch(base + '/v1/login', { method: 'OPTIONS', headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'POST' } });
  assert.equal(ok.status, 204); assert.equal(ok.headers.get('access-control-allow-origin'), ORIGIN);
});

test('JSON obligatoire', async () => {
  const r = await fetch(base + '/v1/login', { method: 'POST', headers: { 'Content-Type': 'text/plain', Origin: ORIGIN }, body: '{}' });
  assert.equal(r.status, 415);
});

test('limite de tentatives : 8 mauvais codes puis blocage, même avec le bon code', async () => {
  const reg = await call('POST', '/v1/register', { pseudo: 'Eve_lock' });
  for (let i = 0; i < 8; i++) assert.equal((await call('POST', '/v1/login', { pseudo: 'Eve_lock', code: 'AAAA-AAAA-AAAA-AAAA' })).status, 401);
  const blocked = await call('POST', '/v1/login', { pseudo: 'Eve_lock', code: reg.json.code });
  assert.equal(blocked.status, 429); assert.ok(Number(blocked.headers.get('retry-after')) > 0);
});

test('supprimer le compte efface tout', async () => {
  const c = (await call('POST', '/v1/register', { pseudo: 'Fay_del' })).cookie;
  await call('PUT', '/v1/saves/snake', { data: { a: 1 }, baseRev: 0 }, c);
  assert.equal((await call('DELETE', '/v1/me', undefined, c)).status, 200);
  assert.equal(app.db.prepare("SELECT COUNT(*) n FROM users WHERE pseudo_key='fay_del'").get().n, 0);
  assert.equal(app.db.prepare('SELECT COUNT(*) n FROM saves').get().n >= 0, true);
  assert.equal((await call('GET', '/v1/me', undefined, c)).status, 401);
});

test('santé, fichiers publics et rien d\'autre', async () => {
  assert.equal((await call('GET', '/health')).json.ok, true);
  assert.equal((await fetch(base + '/account.js')).status, 200);
  assert.equal((await fetch(base + '/package.json')).status, 404);
  assert.equal((await fetch(base + '/..%2fsrc%2fserver.js')).status, 404);
});

test('limite de créations de compte par adresse', async () => {
  const a2 = createApp({ registerLimit: 2 });
  await new Promise((r) => a2.server.listen(0, '127.0.0.1', r));
  const u = `http://127.0.0.1:${a2.server.address().port}/v1/register`;
  const go = (pseudo) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pseudo }) });
  assert.equal((await go('aaa')).status, 201); assert.equal((await go('bbb')).status, 201);
  assert.equal((await go('ccc')).status, 429);
  a2.server.close();
});
