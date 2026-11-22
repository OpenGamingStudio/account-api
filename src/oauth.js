import { randomBytes, createHash } from 'node:crypto';

/**
 * Connexion Google (OpenID Connect) et Discord (OAuth 2.0) : flux « code » + PKCE (S256) + state.
 * Les identifiants d'application viennent de variables d'environnement, jamais du code.
 * On ne garde que l'identifiant du fournisseur (sub / id Discord) : ni e-mail, ni avatar.
 */
export const PROVIDER_LABELS = { google: 'Google', discord: 'Discord' };

/** Fournisseurs activés : ceux dont l'identifiant ET le secret sont définis (sinon le bouton est masqué). */
export function providersFromEnv(env = process.env) {
  const out = {};
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    out.google = {
      kind: 'oidc', clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET,
      authorize: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token',
      scope: 'openid', issuers: ['https://accounts.google.com', 'accounts.google.com'],
    };
  }
  if (env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET) {
    out.discord = {
      kind: 'discord', clientId: env.DISCORD_CLIENT_ID, clientSecret: env.DISCORD_CLIENT_SECRET,
      authorize: 'https://discord.com/oauth2/authorize', token: 'https://discord.com/api/oauth2/token',
      userinfo: 'https://discord.com/api/users/@me', scope: 'identify',
    };
  }
  return out;
}

const b64u = (b) => Buffer.from(b).toString('base64url');
export const newVerifier = () => b64u(randomBytes(32));
export const challengeOf = (verifier) => createHash('sha256').update(verifier).digest('base64url');
export const newState = () => b64u(randomBytes(24));

export function authorizeUrl(name, cfg, { redirectUri, state, verifier, nonce }) {
  const u = new URL(cfg.authorize);
  const p = u.searchParams;
  p.set('response_type', 'code'); p.set('client_id', cfg.clientId); p.set('redirect_uri', redirectUri);
  p.set('scope', cfg.scope); p.set('state', state);
  p.set('code_challenge', challengeOf(verifier)); p.set('code_challenge_method', 'S256');
  if (cfg.kind === 'oidc') { p.set('nonce', nonce); p.set('prompt', 'select_account'); }
  return u.toString();
}

async function postForm(fetchImpl, url, form) {
  const r = await fetchImpl(url, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams(form).toString(), signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error('token_' + r.status);
  return r.json();
}

/** Échange le code (avec le secret et le vérificateur PKCE) puis renvoie { subject, hint } : l'identifiant stable du fournisseur. */
export async function exchange(cfg, { code, redirectUri, verifier, nonce }, fetchImpl = fetch) {
  const tok = await postForm(fetchImpl, cfg.token, {
    grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: cfg.clientId, client_secret: cfg.clientSecret, code_verifier: verifier,
  });
  if (cfg.kind === 'oidc') {
    // Jeton reçu directement du fournisseur en TLS avec notre secret : on contrôle les revendications (OIDC Core 3.1.3.7).
    const parts = String(tok.id_token ?? '').split('.');
    if (parts.length !== 3) throw new Error('id_token');
    const c = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (!cfg.issuers.includes(c.iss) || !aud.includes(cfg.clientId) || !(c.exp * 1000 > Date.now()) || c.nonce !== nonce) throw new Error('id_token_invalide');
    if (typeof c.sub !== 'string' || !c.sub || c.sub.length > 255) throw new Error('sub');
    return { subject: c.sub, hint: '' };
  }
  const r = await fetchImpl(cfg.userinfo, { headers: { Authorization: `Bearer ${tok.access_token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error('userinfo_' + r.status);
  const u = await r.json();
  if (typeof u.id !== 'string' || !/^\d{5,32}$/.test(u.id)) throw new Error('id_discord');
  return { subject: u.id, hint: typeof u.username === 'string' ? u.username : '' };
}
