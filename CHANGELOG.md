# Changelog

## 1.0.1
- `account.js` compatible avec une CSP stricte (`style-src 'self'`) : feuille de style construite (adoptedStyleSheets), plus aucun attribut `style` en ligne.

## 1.0.0
- Compte sans e-mail : pseudo unique + code de récupération généré par le serveur (affiché une fois, stocké haché avec scrypt).
- Session par cookie Secure, HttpOnly, SameSite=Lax (domaine .opengamingstudio.com), 30 jours.
- Sauvegarde JSON par joueur et par jeu (200 Ko max, révision, version du jeu, date), détection de conflit.
- Limite de tentatives (par pseudo et par adresse), CORS limité aux sous-domaines du studio.
- `account.js` : bibliothèque sans dépendance (bouton compte, QR code, synchronisation automatique, choix en cas de conflit).
