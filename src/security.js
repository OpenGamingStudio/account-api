import { randomBytes, createHash, scryptSync, timingSafeEqual } from 'node:crypto';

// Alphabet sans caractères ambigus (pas de 0/O, 1/I/L).
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const CODE_LEN = 16;

/** Code de récupération : 16 caractères sur 31 (environ 79 bits), affiché XXXX-XXXX-XXXX-XXXX. */
export function newCode() {
  let s = '';
  while (s.length < CODE_LEN) {
    for (const b of randomBytes(32)) {
      if (b < 248 && s.length < CODE_LEN) s += ALPHABET[b % ALPHABET.length]; // 248 = 31 x 8 : sans biais
    }
  }
  return s.match(/.{4}/g).join('-');
}

/** Normalise ce que tape le joueur : majuscules, sans espaces ni tirets, O->0 n'existe pas donc rien d'autre. */
export const normCode = (c) => String(c ?? '').toUpperCase().replace(/[\s-]/g, '');

export const hashCode = (code, salt) => scryptSync(normCode(code), salt, 32, { N: 16384, r: 8, p: 1 });
export const newSalt = () => randomBytes(16);
export function checkCode(code, salt, hash) {
  const h = hashCode(code, salt);
  return h.length === hash.length && timingSafeEqual(h, hash);
}

export const newToken = () => randomBytes(32).toString('base64url');
export const tokenHash = (t) => createHash('sha256').update(String(t)).digest('hex');

export const PSEUDO_RE = /^[A-Za-z0-9_-]{3,20}$/;
export const pseudoKey = (p) => String(p).toLowerCase();
export const GAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

/** Limiteur en mémoire : max `limit` événements par fenêtre `windowMs`, par clé. */
export function makeLimiter(limit, windowMs) {
  const hits = new Map();
  const prune = (now) => { for (const [k, v] of hits) if (!v.some((t) => now - t < windowMs)) hits.delete(k); };
  return {
    /** true si la clé est déjà au maximum (sans compter cette demande). */
    blocked(key, now = Date.now()) {
      const v = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
      hits.set(key, v);
      return v.length >= limit;
    },
    add(key, now = Date.now()) {
      const v = hits.get(key) ?? [];
      v.push(now);
      hits.set(key, v);
      if (hits.size > 5000) prune(now);
    },
    clear(key) { hits.delete(key); },
    retryAfter(key, now = Date.now()) {
      const v = hits.get(key) ?? [];
      return v.length ? Math.max(1, Math.ceil((windowMs - (now - v[0])) / 1000)) : 0;
    },
  };
}

/** Origines autorisées : le domaine du studio et ses sous-domaines en HTTPS (ou localhost en développement). */
export function originAllowed(origin, extra = []) {
  if (!origin) return false;
  if (extra.includes(origin)) return true;
  try {
    const u = new URL(origin);
    if (u.origin !== origin) return false;
    if (u.protocol === 'https:' && !u.port && (u.hostname === 'opengamingstudio.com' || u.hostname.endsWith('.opengamingstudio.com'))) return true;
  } catch { /* origine invalide */ }
  return false;
}

/** Pseudo généré pour un compte créé par Google / Discord : Joueur-XXXXX (alphabet sans ambiguïté). */
export function randomPseudo() {
  let s = ''; for (const b of randomBytes(8)) { if (b < 248 && s.length < 5) s += ALPHABET[b % ALPHABET.length]; }
  while (s.length < 5) s += ALPHABET[randomBytes(1)[0] % ALPHABET.length];
  return `Joueur-${s}`;
}
