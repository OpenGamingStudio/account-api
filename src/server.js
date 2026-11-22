import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, extname, normalize } from 'node:path';
import QRCode from 'qrcode';
import { openDb } from './db.js';
import {
  newCode, hashCode, newSalt, checkCode, newToken, tokenHash, PSEUDO_RE, pseudoKey, GAME_RE,
  makeLimiter, originAllowed,
} from './security.js';

export const VERSION = '1.1.0';
const COOKIE = 'ogs_session';
const SESSION_MS = 30 * 24 * 3600 * 1000;
const MAX_SAVE_BYTES = 200 * 1024;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_GAMES_PER_USER = 40;
const PUBLIC_DIR = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const STATIC_OK = new Set(['/index.html', '/account.js', '/demo.js', '/styles.css', '/fonts/fredoka-latin-wght-normal.woff2']);

class HttpError extends Error { constructor(status, code, extra = {}) { super(code); this.status = status; this.code = code; this.extra = extra; } }

/**
 * Crée le serveur. Options : dbFile, cookieDomain, extraOrigins, trustProxy.
 * Aucune donnée personnelle : un pseudo, un code de récupération (stocké haché) et des sauvegardes JSON.
 */
export function createApp({ dbFile = ':memory:', cookieDomain = '', extraOrigins = [], trustProxy = false, registerLimit = 5 } = {}) {
  const db = openDb(dbFile);
  const q = {
    userByKey: db.prepare('SELECT * FROM users WHERE pseudo_key = ?'),
    insertUser: db.prepare('INSERT INTO users (pseudo, pseudo_key, salt, code_hash, created_at) VALUES (?,?,?,?,?)'),
    insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)'),
    sessionUser: db.prepare('SELECT u.id, u.pseudo FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'),
    delSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
    getSave: db.prepare('SELECT data, rev, game_version, updated_at FROM saves WHERE user_id = ? AND game = ?'),
    putSave: db.prepare(`INSERT INTO saves (user_id, game, data, rev, game_version, updated_at) VALUES (?,?,?,?,?,?)
      ON CONFLICT(user_id, game) DO UPDATE SET data = excluded.data, rev = excluded.rev, game_version = excluded.game_version, updated_at = excluded.updated_at`),
    countSaves: db.prepare('SELECT COUNT(*) AS n FROM saves WHERE user_id = ?'),
    delUser: db.prepare('DELETE FROM users WHERE id = ?'),
  };
  const loginIp = makeLimiter(10, 15 * 60 * 1000);
  const loginUser = makeLimiter(8, 15 * 60 * 1000);
  const registerIp = makeLimiter(registerLimit, 3600 * 1000);
  const writeUser = makeLimiter(60, 60 * 1000);
  // Contre-mesure de temps : un pseudo inconnu coûte autant qu'un mauvais code.
  const dummySalt = newSalt();
  const dummyHash = hashCode('AAAA-AAAA-AAAA-AAAA', dummySalt);

  const clientIp = (req) => {
    if (trustProxy) { const x = String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => s.trim()).filter(Boolean); if (x.length) return x[x.length - 1]; }
    return req.socket.remoteAddress ?? '?';
  };
  const cookieOf = (req) => { for (const p of String(req.headers.cookie ?? '').split(';')) { const [k, ...v] = p.trim().split('='); if (k === COOKIE) return v.join('='); } return ''; };
  const sessionCookie = (token, maxAgeS) => `${COOKIE}=${token}; Path=/; Max-Age=${maxAgeS}; HttpOnly; Secure; SameSite=Lax${cookieDomain ? `; Domain=${cookieDomain}` : ''}`;
  const authUser = (req) => { const t = cookieOf(req); return t ? q.sessionUser.get(tokenHash(t), Date.now()) : undefined; };
  const startSession = (res, userId) => {
    q.purgeSessions.run(Date.now());
    const token = newToken();
    q.insertSession.run(tokenHash(token), userId, Date.now() + SESSION_MS);
    res.setHeader('Set-Cookie', sessionCookie(token, SESSION_MS / 1000));
  };

  async function readJson(req) {
    if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) throw new HttpError(415, 'json_requis');
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > MAX_BODY_BYTES) throw new HttpError(413, 'trop_gros'); chunks.push(c); }
    try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); if (!v || typeof v !== 'object' || Array.isArray(v)) throw 0; return v; } catch { throw new HttpError(400, 'json_invalide'); }
  }
  const saveOut = (r) => ({ data: JSON.parse(r.data), rev: r.rev, gameVersion: r.game_version, updatedAt: r.updated_at });

  async function route(req, res, url, origin) {
    const m = req.method; const p = url.pathname;
    const send = (status, body) => { const s = JSON.stringify(body); res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(s) }); res.end(s); };

    if (p === '/health') return send(200, { ok: true, version: VERSION });
    if (!p.startsWith('/v1/')) throw new HttpError(404, 'introuvable');
    if (m !== 'GET' && origin && !originAllowed(origin, extraOrigins)) throw new HttpError(403, 'origine_refusee');
    const ip = clientIp(req);

    if (p === '/v1/register' && m === 'POST') {
      if (registerIp.blocked(ip)) throw new HttpError(429, 'trop_de_tentatives', { retryAfter: registerIp.retryAfter(ip) });
      const { pseudo } = await readJson(req);
      if (typeof pseudo !== 'string' || !PSEUDO_RE.test(pseudo)) throw new HttpError(400, 'pseudo_invalide');
      registerIp.add(ip);
      if (q.userByKey.get(pseudoKey(pseudo))) throw new HttpError(409, 'pseudo_pris');
      const code = newCode(); const salt = newSalt();
      let id;
      try { id = q.insertUser.run(pseudo, pseudoKey(pseudo), salt, hashCode(code, salt), Date.now()).lastInsertRowid; }
      catch { throw new HttpError(409, 'pseudo_pris'); }
      startSession(res, id);
      const qr = QRCode.create(`${pseudo} ${code}`, { errorCorrectionLevel: 'M' }).modules;
      const rows = []; for (let y = 0; y < qr.size; y++) { let r = ''; for (let x = 0; x < qr.size; x++) r += qr.get(x, y) ? '1' : '0'; rows.push(r); }
      return send(201, { pseudo, code, qr: { size: qr.size, rows } });
    }

    if (p === '/v1/login' && m === 'POST') {
      const { pseudo, code } = await readJson(req);
      if (typeof pseudo !== 'string' || typeof code !== 'string' || code.length > 64 || pseudo.length > 40) throw new HttpError(400, 'identifiants_invalides');
      const key = pseudoKey(pseudo);
      if (loginIp.blocked(ip)) throw new HttpError(429, 'trop_de_tentatives', { retryAfter: loginIp.retryAfter(ip) });
      if (loginUser.blocked(key)) throw new HttpError(429, 'trop_de_tentatives', { retryAfter: loginUser.retryAfter(key) });
      const u = q.userByKey.get(key);
      const ok = u ? checkCode(code, u.salt, u.code_hash) : (checkCode(code, dummySalt, dummyHash), false);
      if (!ok) { loginIp.add(ip); loginUser.add(key); throw new HttpError(401, 'identifiants_invalides'); }
      loginUser.clear(key);
      startSession(res, u.id);
      return send(200, { pseudo: u.pseudo });
    }

    const user = authUser(req);
    if (p === '/v1/logout' && m === 'POST') {
      const t = cookieOf(req); if (t) q.delSession.run(tokenHash(t));
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      return send(200, { ok: true });
    }
    if (p === '/v1/me' && m === 'GET') return user ? send(200, { pseudo: user.pseudo }) : send(401, { error: 'non_connecte' });
    if (!user) throw new HttpError(401, 'non_connecte');

    if (p === '/v1/me' && m === 'DELETE') {
      q.delUser.run(user.id);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      return send(200, { ok: true });
    }

    const sm = /^\/v1\/saves\/([^/]+)$/.exec(p);
    if (sm) {
      const game = sm[1];
      if (!GAME_RE.test(game)) throw new HttpError(400, 'jeu_invalide');
      if (m === 'GET') { const r = q.getSave.get(user.id, game); return r ? send(200, saveOut(r)) : send(404, { error: 'aucune_sauvegarde' }); }
      if (m === 'PUT') {
        if (writeUser.blocked(user.id)) throw new HttpError(429, 'trop_de_requetes', { retryAfter: writeUser.retryAfter(user.id) });
        writeUser.add(user.id);
        const b = await readJson(req);
        if (!b.data || typeof b.data !== 'object' || Array.isArray(b.data)) throw new HttpError(400, 'donnees_invalides');
        if (!Number.isInteger(b.baseRev) || b.baseRev < 0) throw new HttpError(400, 'baserev_invalide');
        const gv = typeof b.gameVersion === 'string' ? b.gameVersion.slice(0, 20) : '';
        const json = JSON.stringify(b.data);
        if (Buffer.byteLength(json) > MAX_SAVE_BYTES) throw new HttpError(413, 'sauvegarde_trop_grosse', { max: MAX_SAVE_BYTES });
        const cur = q.getSave.get(user.id, game);
        if (!cur && q.countSaves.get(user.id).n >= MAX_GAMES_PER_USER) throw new HttpError(400, 'trop_de_jeux');
        const curRev = cur ? cur.rev : 0;
        if (b.baseRev !== curRev && b.force !== true) throw new HttpError(409, 'conflit', { save: cur ? saveOut(cur) : null });
        const now = Date.now();
        q.putSave.run(user.id, game, json, curRev + 1, gv, now);
        return send(200, { rev: curRev + 1, updatedAt: now });
      }
    }
    throw new HttpError(404, 'introuvable');
  }

  async function serveStatic(res, p) {
    const f = p === '/' ? '/index.html' : p;
    if (!STATIC_OK.has(normalize(f))) throw new HttpError(404, 'introuvable');
    const body = await readFile(join(PUBLIC_DIR, f)).catch(() => { throw new HttpError(404, 'introuvable'); });
    res.writeHead(200, { 'Content-Type': MIME[extname(f)] ?? 'application/octet-stream', 'Cache-Control': 'no-cache', 'Content-Length': body.length });
    res.end(body);
  }

  const server = createServer(async (req, res) => {
    const origin = req.headers.origin;
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('Vary', 'Origin');
    if (origin && originAllowed(origin, extraOrigins)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      if (req.method === 'OPTIONS') {
        if (!origin || !originAllowed(origin, extraOrigins)) throw new HttpError(403, 'origine_refusee');
        res.writeHead(204, { 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' });
        return res.end();
      }
      if (req.method === 'GET' && !url.pathname.startsWith('/v1/') && url.pathname !== '/health') return await serveStatic(res, url.pathname);
      await route(req, res, url, origin);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (!(e instanceof HttpError)) console.error('erreur', e?.message);
      if (!res.headersSent) {
        const headers = { 'Content-Type': 'application/json; charset=utf-8' };
        if (e instanceof HttpError && e.extra.retryAfter) headers['Retry-After'] = String(e.extra.retryAfter);
        res.writeHead(status, headers);
      }
      res.end(JSON.stringify({ error: e instanceof HttpError ? e.code : 'erreur_serveur', ...(e instanceof HttpError ? e.extra : {}) }));
    }
  });
  return { server, db };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { server } = createApp({
    dbFile: process.env.DB_FILE || '/data/account.db',
    cookieDomain: process.env.COOKIE_DOMAIN ?? '.opengamingstudio.com',
    extraOrigins: (process.env.EXTRA_ORIGINS || '').split(',').filter(Boolean),
    trustProxy: process.env.TRUST_PROXY !== '0',
  });
  const port = Number(process.env.PORT || 80);
  server.listen(port, '0.0.0.0', () => console.log(`account-api ${VERSION} sur le port ${port}`));
}
