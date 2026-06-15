# odoo-oidc-sso

Odoo addon (`sp_auth_oidc_roles`) that completes OpenID Connect SSO with Keycloak
for Odoo Community Edition.

Odoo CE (`auth_oauth` / OCA `auth_oidc`) authenticates an SSO user but **does not
map the IdP roles to Odoo groups**, and its logout **does not terminate the
Keycloak SSO session**. This module fixes both.

## Features

- **Role → group mapping at login.** Reads `resource_access.odoo.roles` (and realm
  roles as a fallback) from the OIDC token and applies the matching Odoo groups on
  every SSO login. Keycloak stays the single source of truth — no cron, no SQL
  trigger. Every SSO user becomes an internal user (never `share`/portal); admin
  is granted from the `admin` / `system-admin` role.
- **RP-initiated logout.** Overrides `/web/session/logout` so that, after clearing
  the Odoo session, it bounces to the Keycloak end-session endpoint
  (`id_token_hint` + `post_logout_redirect_uri`) — the SSO session is actually
  killed, no silent re-login.
- **OIDC Back-Channel Logout.** Exposes `POST /web/oidc/backchannel_logout`. When
  Keycloak terminates the SSO session, it POSTs a `logout_token` here; the module
  verifies it (RS256 via the realm JWKS) and invalidates the user's Odoo sessions
  **server-side** by bumping a per-user `sp_logout_epoch` mixed into
  `_compute_session_token`. Register the endpoint on the Keycloak client as the
  *Backchannel logout URL*.

## Requirements

- Odoo 19, modules `auth_oauth` + `auth_oidc` (OCA).
- `python-jose[cryptography]` (for Back-Channel Logout token verification).

## Keycloak client

- *Valid post logout redirect URIs* must include the unified logout landing page.
- *Backchannel logout URL* → `https://<odoo-host>/web/oidc/backchannel_logout`,
  *Backchannel logout session required* on.
- The `odoo` client must expose `resource_access.odoo.roles` in the token
  (`client-roles-userinfo` mapper).

LGPL-3.
