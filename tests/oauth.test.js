import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { createApp } from '../src/server.js';

// Fournisseur simulé : /token vérifie PKCE + secret, rend un id_token (Google) ou un jeton ; /me rend le profil Discord.
let fake, fakeBase, app, base;
const grants = new Map(); // code -> { challenge, subject, nonce, username }
const ORIGIN = 'https://trou-malin.opengamingstudio.com';
const RET = ORIGIN + '/jouer?x=1';
let google, discord;

before(async () => {
  fake = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = new URLSearchParams(Buffer.concat(chunks).toString());
    const send = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.url === '/token') {
      const g = grants.get(body.get('code')); grants.delete(body.get('code'));
      if (!g || body.get('client_secret') !== 'sec' || body.get('redirect_uri') !== g.redirectUri) return send(400, { error: 'invalid_grant' });
      const ok = createHash('sha256').update(body.get('code_verifier') ?? '').digest('base64url') === g.challenge;
      if (!ok) return send(400, { error: 'pkce' });
      if (g.kind === 'oidc') {
        const pl = { iss: 'https://accounts.google.com', aud: g.badAud ? 'autre' : 'gid', sub: g.subject, nonce: g.nonce, exp: Math.floor(Date.now() / 1000) + 60, email: 'a@b.c', name: 'Vrai Nom' };
        return send(200, { id_token: `x.${Buffer.from(JSON.stringify(pl)).toString('base64url')}.y`, access_token: 'z' });
      }
      return send(200, { access_token: `tok-${g.subject}-${g.username}` });
    }
    if (req.url === '/me') { const m = /^Bearer tok-(\d+)-(.*)$/.exec(req.headers.authorization ?? ''); return m ? send(200, { id: m[1], username: m[2], email: 'x@y.z', avatar: 'a' }) : send(401, {}); }
    send(404, {});
  });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  fakeBase = `http://127.0.0.1:${fake.address().port}`;
  google = { kind: 'oidc', clientId: 'gid', clientSecret: 'sec', authorize: fakeBase + '/authorize', token: fakeBase + '/token', scope: 'openid', issuers: ['https://accounts.google.com'] };
  discord = { kind: 'discord', clientId: 'did', clientSecret: 'sec', authorize: fakeBase + '/authorize', token: fakeBase + '/token', userinfo: fakeBase + '/me', scope: 'identify' };
  app = createApp({ cookieDomain: '.opengamingstudio.com', registerLimit: 1000, providers: { google, discord } });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${app.server.address().port}`;
});
after(() => { app.server.close(); fake.close(); });

// Node 18 n'a pas getSetCookie : nos cookies n'ont pas d'Expires, donc la virgule sépare bien les cookies.
const setCookies = (h) => (h.getSetCookie ? h.getSetCookie() : (h.get('set-cookie') ? h.get('set-cookie').split(/,\s*(?=[A-Za-z0-9_]+=)/) : []));
const cookieJar = () => { const j = {}; return { set(r) { for (const c of setCookies(r.headers)) { const [kv] = c.split(';'); const [k, v] = [kv.slice(0, kv.indexOf('=')), kv.slice(kv.indexOf('=') + 1)]; if (v) j[k] = v; else delete j[k]; } }, header: () => Object.entries(j).map(([k, v]) => `${k}=${v}`).join('; '), j }; };
const get = (path, jar, extra = {}) => fetch(base + path, { redirect: 'manual', headers: { ...(jar ? { Cookie: jar.header() } : {}), ...extra } });
const api = async (method, path, body, jar) => {
  const r = await fetch(base + path, { method, headers: { Origin: ORIGIN, ...(body ? { 'Content-Type': 'application/json' } : {}), Cookie: jar.header() }, body: body ? JSON.stringify(body) : undefined });
  jar.set(r); return { status: r.status, json: await r.json().catch(() => null), headers: r.headers };
};

/** Parcourt tout le flux : start -> (fournisseur simulé) -> callback. Renvoie l'adresse de retour. */
async function flow(name, jar, { subject, username = '', link = false, badAud = false, tamper, noCookie = false } = {}) {
  const s = await get(`/auth/${name}/start?return=${encodeURIComponent(RET)}${link ? '&link=1' : ''}`, jar);
  assert.equal(s.status, 302); jar.set(s);
  const loc = new URL(s.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, fakeBase + '/authorize');
  assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(loc.searchParams.get('redirect_uri'), `https://api.opengamingstudio.com/auth/${name}/callback`);
  assert.equal(loc.searchParams.get('scope'), name === 'google' ? 'openid' : 'identify');
  const state = loc.searchParams.get('state');
  const code = 'c' + Math.random().toString(36).slice(2);
  grants.set(code, { challenge: loc.searchParams.get('code_challenge'), subject, nonce: loc.searchParams.get('nonce'), username, kind: name === 'google' ? 'oidc' : 'discord', redirectUri: loc.searchParams.get('redirect_uri'), badAud });
  const cbJar = noCookie ? cookieJar() : jar;
  const c = await get(`/auth/${name}/callback?code=${code}&state=${tamper ?? state}`, cbJar);
  jar.set(c);
  return c;
}

test('fournisseurs : seuls ceux configurés sont proposés', async () => {
  const r = await (await fetch(base + '/v1/providers')).json();
  assert.deepEqual(r.providers.sort(), ['discord', 'google']);
  const none = createApp({});
  await new Promise((rs) => none.server.listen(0, '127.0.0.1', rs));
  const b = `http://127.0.0.1:${none.server.address().port}`;
  assert.deepEqual((await (await fetch(b + '/v1/providers')).json()).providers, []);
  assert.equal((await fetch(b + '/auth/google/start', { redirect: 'manual' })).status, 404);
  none.server.close();
});

test('Google : crée un compte, cookie multidomaine de 365 jours, aucune donnée personnelle gardée', async () => {
  const jar = cookieJar();
  const c = await flow('google', jar, { subject: 'g-123' });
  assert.equal(c.status, 302);
  const back = new URL(c.headers.get('location'));
  assert.equal(back.origin + back.pathname, ORIGIN + '/jouer'); assert.equal(back.searchParams.get('ogs_auth'), 'ok'); assert.equal(back.searchParams.get('x'), '1');
  const sc = setCookies(c.headers).find((x) => x.startsWith('ogs_session='));
  assert.match(sc, /Domain=\.opengamingstudio\.com/); assert.match(sc, /Secure/); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Lax/); assert.match(sc, /Max-Age=31536000/);
  const me = await api('GET', '/v1/me', undefined, jar);
  assert.equal(me.status, 200); assert.match(me.json.pseudo, /^Joueur-[A-Z2-9]{5}$/); assert.equal(me.json.hasCode, false); assert.deepEqual(me.json.identities, ['google']);
  const rows = app.db.prepare('SELECT * FROM identities').all();
  assert.deepEqual(Object.keys(rows[0]).sort(), ['created_at', 'provider', 'subject', 'user_id']);
  const dump = JSON.stringify(app.db.prepare('SELECT * FROM users').all());
  assert.ok(!/a@b\.c|Vrai Nom/.test(dump));
  // même sub -> même compte
  const jar2 = cookieJar(); await flow('google', jar2, { subject: 'g-123' });
  assert.equal((await api('GET', '/v1/me', undefined, jar2)).json.pseudo, me.json.pseudo);
});

test('Discord : pseudo repris du nom Discord s\'il est valide', async () => {
  const jar = cookieJar();
  const c = await flow('discord', jar, { subject: '123456789012345678', username: 'Panda.Rapide' });
  assert.equal(c.status, 302);
  const me = await api('GET', '/v1/me', undefined, jar);
  assert.equal(me.json.pseudo, 'PandaRapide'); assert.deepEqual(me.json.identities, ['discord']);
  const row = app.db.prepare("SELECT * FROM identities WHERE provider='discord'").get();
  assert.equal(row.subject, '123456789012345678');
});

test('state invalide, cookie absent, rejouée ou mauvais id_token : refusé', async () => {
  const jar = cookieJar();
  assert.equal((await flow('google', jar, { subject: 'x1', tamper: 'faux' })).status, 400);
  const jar2 = cookieJar();
  assert.equal((await flow('google', jar2, { subject: 'x2', noCookie: true })).status, 400); // login CSRF : state sans le cookie du navigateur
  const jar3 = cookieJar();
  const c = await flow('google', jar3, { subject: 'x3', badAud: true });
  assert.equal(new URL(c.headers.get('location')).searchParams.get('ogs_error'), 'echec_fournisseur');
  assert.equal((await api('GET', '/v1/me', undefined, jar3)).status, 401);
  // state à usage unique
  const jar4 = cookieJar();
  const s = await get(`/auth/google/start?return=${encodeURIComponent(RET)}`, jar4); jar4.set(s);
  const st = new URL(s.headers.get('location')).searchParams.get('state');
  await get(`/auth/google/callback?error=access_denied&state=${st}`, jar4);
  assert.equal((await get(`/auth/google/callback?code=a&state=${st}`, jar4)).status, 400);
});

test('refus du joueur chez le fournisseur : retour avec une erreur lisible', async () => {
  const jar = cookieJar();
  const s = await get(`/auth/discord/start?return=${encodeURIComponent(RET)}`, jar); jar.set(s);
  const st = new URL(s.headers.get('location')).searchParams.get('state');
  const c = await get(`/auth/discord/callback?error=access_denied&state=${st}`, jar);
  const u = new URL(c.headers.get('location'));
  assert.equal(u.searchParams.get('ogs_auth'), 'erreur'); assert.equal(u.searchParams.get('ogs_error'), 'refuse');
});

test('adresse de retour : jamais hors du studio (pas de redirection ouverte)', async () => {
  for (const bad of ['https://evil.io/', 'https://opengamingstudio.com.evil.io/', 'javascript:alert(1)', '//evil.io']) {
    const jar = cookieJar();
    const s = await get(`/auth/google/start?return=${encodeURIComponent(bad)}`, jar); jar.set(s);
    const loc = new URL(s.headers.get('location'));
    const code = 'k' + Math.random(); grants.set(code, { challenge: loc.searchParams.get('code_challenge'), subject: 'open' + Math.random(), nonce: loc.searchParams.get('nonce'), kind: 'oidc', redirectUri: loc.searchParams.get('redirect_uri') });
    const c = await get(`/auth/google/callback?code=${code}&state=${loc.searchParams.get('state')}`, jar);
    assert.equal(new URL(c.headers.get('location')).origin, 'https://opengamingstudio.com');
  }
});

test('lier plusieurs méthodes à un même compte, délier, dernière méthode protégée', async () => {
  const jar = cookieJar();
  const reg = await api('POST', '/v1/register', { pseudo: 'Lieur' }, jar);
  assert.equal(reg.status, 201);
  assert.equal((await flow('google', jar, { subject: 'g-link', link: true })).headers.get('location').includes('ogs_auth=lie'), true);
  assert.equal((await flow('discord', jar, { subject: '555555555555555555', username: 'x', link: true })).headers.get('location').includes('ogs_auth=lie'), true);
  let me = await api('GET', '/v1/me', undefined, jar);
  assert.equal(me.json.pseudo, 'Lieur'); assert.equal(me.json.hasCode, true); assert.deepEqual(me.json.identities, ['discord', 'google']);
  // se connecter avec Google depuis un autre appareil retrouve le même compte (et ses sauvegardes)
  await api('PUT', '/v1/saves/trou-malin', { data: { niveau: 7 }, baseRev: 0 }, jar);
  const other = cookieJar(); await flow('google', other, { subject: 'g-link' });
  assert.equal((await api('GET', '/v1/saves/trou-malin', undefined, other)).json.data.niveau, 7);
  // une identité déjà liée à un autre compte ne se rattache pas
  const third = cookieJar(); await api('POST', '/v1/register', { pseudo: 'Autre' }, third);
  const c = await flow('google', third, { subject: 'g-link', link: true });
  assert.ok(c.headers.get('location').includes('ogs_error=deja_lie'));
  // délier
  me = await api('DELETE', '/v1/me/identities/google', undefined, jar);
  assert.equal(me.status, 200); assert.deepEqual(me.json.identities, ['discord']);
  assert.equal((await api('DELETE', '/v1/me/identities/google', undefined, jar)).status, 404);
  // compte Discord seul : impossible de délier la dernière méthode
  const solo = cookieJar(); await flow('discord', solo, { subject: '777777777777777777', username: 'Solo' });
  assert.equal((await api('DELETE', '/v1/me/identities/discord', undefined, solo)).json.error, 'derniere_methode');
  // lier sans session : erreur de retour
  const anon = cookieJar();
  const a = await get(`/auth/google/start?link=1&return=${encodeURIComponent(RET)}`, anon);
  assert.ok(a.headers.get('location').includes('ogs_error=non_connecte'));
});

test('compte Google : créer un code de récupération ajoute la méthode pseudo + code', async () => {
  const jar = cookieJar(); await flow('google', jar, { subject: 'g-code' });
  const me = (await api('GET', '/v1/me', undefined, jar)).json;
  assert.equal(me.hasCode, false);
  // sans code, impossible de se connecter par pseudo
  assert.equal((await api('POST', '/v1/login', { pseudo: me.pseudo, code: 'AAAA-AAAA-AAAA-AAAA' }, cookieJar())).status, 401);
  const r = await api('POST', '/v1/me/code', {}, jar);
  assert.equal(r.status, 200); assert.match(r.json.code, /^[A-Z2-9-]{19}$/); assert.equal(r.json.again, false);
  const other = cookieJar();
  assert.equal((await api('POST', '/v1/login', { pseudo: me.pseudo, code: r.json.code }, other)).status, 200);
  const r2 = await api('POST', '/v1/me/code', {}, jar);
  assert.equal(r2.json.again, true);
  assert.equal((await api('POST', '/v1/login', { pseudo: me.pseudo, code: r.json.code }, cookieJar())).status, 401); // l'ancien code ne marche plus
});

test('session glissante : l\'échéance repart à chaque usage et le cookie est renvoyé', async () => {
  const jar = cookieJar(); await api('POST', '/v1/register', { pseudo: 'Glisse' }, jar);
  const old = Date.now() + 100 * 24 * 3600 * 1000;
  app.db.prepare('UPDATE sessions SET expires_at = ?').run(old);
  const me = await api('GET', '/v1/me', undefined, jar);
  assert.equal(me.status, 200);
  const sc = setCookies(me.headers).find((x) => x.startsWith('ogs_session='));
  assert.match(sc, /Max-Age=31536000/); assert.match(sc, /Domain=\.opengamingstudio\.com/);
  const exp = app.db.prepare('SELECT MAX(expires_at) AS e FROM sessions').get().e;
  assert.ok(exp > Date.now() + 364 * 24 * 3600 * 1000);
  // session expirée : refusée
  app.db.prepare('UPDATE sessions SET expires_at = ?').run(Date.now() - 1000);
  assert.equal((await api('GET', '/v1/me', undefined, jar)).status, 401);
});

test('CORS : origine exacte du jeu avec cookies, jamais *', async () => {
  const jar = cookieJar(); await api('POST', '/v1/register', { pseudo: 'Cors' }, jar);
  const r = await fetch(base + '/v1/me', { headers: { Origin: ORIGIN, Cookie: jar.header() } });
  assert.equal(r.headers.get('access-control-allow-origin'), ORIGIN); assert.equal(r.headers.get('access-control-allow-credentials'), 'true');
  const e = await fetch(base + '/v1/me', { headers: { Origin: 'https://evil.io' } });
  assert.equal(e.headers.get('access-control-allow-origin'), null);
});
