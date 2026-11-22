# Changelog

## 1.2.0
- Connexion Google (OpenID Connect) et Discord (OAuth 2.0) : code + PKCE + state, redirection fixe `/auth/<fournisseur>/callback`. Seul l'identifiant fournisseur est gardé. Boutons masqués sans clés (variables d'environnement).
- Menu « Compte » : lier ou retirer Google / Discord, créer ou renouveler le code de récupération.
- Session de 365 jours, renouvelée à chaque usage, cookie multidomaine.
- `account.js` : sauvegarde automatique 10 s après la dernière modification (et à la fermeture), plus de bouton « Synchroniser », contrat `getSave` / `applySave`.

## 1.1.0
- `OGSAccount.show(false|true)` : le jeu cache le bouton compte sur les écrans où il gênerait (la synchronisation continue).

## 1.0.1
- `account.js` compatible avec une CSP stricte (`style-src 'self'`) : feuille de style construite (adoptedStyleSheets), plus aucun attribut `style` en ligne.

## 1.0.0
- Compte sans e-mail : pseudo unique + code de récupération généré par le serveur (affiché une fois, stocké haché avec scrypt).
- Session par cookie Secure, HttpOnly, SameSite=Lax (domaine .opengamingstudio.com), 30 jours.
- Sauvegarde JSON par joueur et par jeu (200 Ko max, révision, version du jeu, date), détection de conflit.
- Limite de tentatives (par pseudo et par adresse), CORS limité aux sous-domaines du studio.
- `account.js` : bibliothèque sans dépendance (bouton compte, QR code, synchronisation automatique, choix en cas de conflit).
