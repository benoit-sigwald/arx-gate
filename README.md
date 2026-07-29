# arx-gate

Porte d'accès + capture de prospects, **un schéma Oracle par site**.

## Parcours

1. Visiteur sur une URL protégée → Traefik (`forwardauth`) interroge `/gate/auth` → redirection vers le formulaire.
2. Formulaire : prénom, nom, email, téléphone, société, objet de la visite, consentement RGPD (tous obligatoires).
3. Email de confirmation (Gmail SMTP) → clic → statut `email_verified`.
4. **Notification ntfy avec boutons Approuver / Refuser.**
5. Si approuvé : email avec lien d'accès → cookie signé 90 jours (`.duckdns.org`).

## Schémas Oracle

Un utilisateur Oracle par site (`GATE_50`, `GATE_877`, `GATE_CACTUS`, `GATE_ARXCAPITAL`), chacun avec
`PROSPECTS`, `VISITS`, `SESSIONS`, `ACCESS_LOG`. `VISITS.PROSPECT_ID` relie chaque visite à son prospect.

## Beacon tracker

```html
<script defer src="https://arx-apps.duckdns.org/gate/t.js" data-site="mon-site"></script>
```

Écrit dans le schéma du site et renseigne `prospect_id` quand le visiteur est identifié.

## Dashboard

`https://arx-apps.duckdns.org/gate/admin?key=ADMIN_KEY` — un onglet par site, tuiles
(prospects, approuvés, en attente, visites 7 j), tableau détaillé, export CSV.

## Env (Coolify)

`ORA_CONNECT`, `ORA_WALLET_B64`, `ORA_WALLET_PASSWORD`, `ORA_WALLET_DIR`, `SITES_B64` (JSON base64
`{slug:{user,password}}`), `SITE_URLS_B64` (optionnel), `GATE_SECRET`, `ADMIN_KEY`, `PUBLIC_URL`,
`NTFY_URL`, `NTFY_TOPIC`, `SMTP_USER`, `SMTP_PASS`, `BASE_PATH=/gate`, `PORT=3000`.

Sans `SMTP_PASS` : pas d'email, le prospect passe directement en validation ntfy et le lien d'accès
est envoyé dans la notification.
