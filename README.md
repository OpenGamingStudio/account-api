# account-api

Compte et sauvegarde multi-jeux d'[OpenGamingStudio](https://opengamingstudio.com), sans e-mail et sans donnée personnelle (le public peut être des enfants). Licence MIT.

- **Créer un compte** : le joueur choisit un pseudo unique (3 à 20 caractères : lettres, chiffres, `_`, `-`). Le serveur génère un **code de récupération** (`XXXX-XXXX-XXXX-XXXX`, environ 79 bits), montré une seule fois (bouton copier + QR code), stocké haché (scrypt + sel).
- **Se connecter** : pseudo + code, sur n'importe quel appareil.
- **Sauvegardes** : un JSON par joueur et par jeu (200 Ko max), avec révision, version du jeu et date.

## API (`https://api.opengamingstudio.com`)

Toutes les routes `/v1` répondent en JSON ; les écritures exigent `Content-Type: application/json` et une origine du studio (`https://*.opengamingstudio.com`).

| Route | Rôle |
|---|---|
| `POST /v1/register` `{pseudo}` | crée le compte, renvoie `{pseudo, code, qr}` (une seule fois), ouvre la session |
| `POST /v1/login` `{pseudo, code}` | ouvre la session |
| `POST /v1/logout` | ferme la session |
| `GET /v1/me` | `{pseudo}` ou 401 |
| `DELETE /v1/me` | supprime le compte et toutes ses sauvegardes |
| `GET /v1/saves/:jeu` | `{data, rev, gameVersion, updatedAt}` ou 404 |
| `PUT /v1/saves/:jeu` `{data, baseRev, gameVersion, force?}` | enregistre ; `baseRev` = révision connue (0 si aucune) ; 409 `conflit` avec la sauvegarde du serveur si elle a changé, sauf `force: true` |
| `GET /health` | `{ok, version}` |

Sécurité : cookie `ogs_session` Secure, HttpOnly, SameSite=Lax, `Domain=.opengamingstudio.com` ; aucun secret dans une URL ; 8 mauvais codes par pseudo ou 10 par adresse en 15 minutes, puis 429 ; 5 créations de compte par adresse et par heure ; CORS réservé aux sous-domaines du studio ; en-têtes CSP/HSTS.

## Brancher un jeu

1. Copier [`public/account.js`](public/account.js) dans le jeu (aucune dépendance) et le charger.
2. Autoriser dans la CSP du jeu : `connect-src https://api.opengamingstudio.com`.
3. Appeler :

```js
OGSAccount.init({
  game: 'trou-malin',          // identifiant du jeu (a-z, 0-9, -)
  version: VERSION,
  getState: () => ({ /* tout ce qui doit être sauvegardé */ }),
  setState: (s) => { /* appliquer et rafraîchir le jeu */ },
  isEmpty: (s) => false,       // optionnel : état vierge ?
  describe: (s) => '12 niveaux', // optionnel : résumé pour le choix en cas de conflit
  color: '#FFB703',            // optionnel : couleur du jeu
});
```

`OGSAccount.show(false|true)` cache ou montre le bouton selon l'écran. Le jeu reste utilisable sans compte. Connecté, la synchronisation est automatique ; en cas de conflit, le joueur choisit la sauvegarde à garder.

## Développement

```
npm i
npm test                 # node --test
npm run build:css        # Tailwind (Node 20+)
PORT=8080 DB_FILE=./dev.db COOKIE_DOMAIN= EXTRA_ORIGINS=http://127.0.0.1:8080 node src/server.js
```

Variables : `PORT` (80), `DB_FILE` (`/data/account.db`), `COOKIE_DOMAIN` (`.opengamingstudio.com`), `EXTRA_ORIGINS`, `TRUST_PROXY` (`0` pour ignorer `X-Forwarded-For`).

## Déploiement (Dokploy)

Dockerfile à la racine, port 80, domaine `api.opengamingstudio.com` en HTTPS. **Monter un volume persistant sur `/data`** (base SQLite) et ne jamais le recréer. L'entrée du conteneur rend `/data` écrivable puis abandonne les droits root.
