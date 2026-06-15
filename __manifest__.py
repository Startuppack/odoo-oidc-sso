{
    # Maps Keycloak roles (from the OIDC token) to Odoo groups AT LOGIN — the
    # token is the source of truth (no cron, no SQL trigger). Also adds
    # IdP-initiated logout. Bump `version` on every logic change so that
    # `-u sp_auth_oidc_roles` actually reloads the code.
    "name": "OIDC SSO (Keycloak): role mapping + IdP logout",
    "version": "19.0.2.0.0",
    "summary": "Map Keycloak OIDC token roles to Odoo groups at login, and add "
               "IdP-initiated logout (RP-initiated + OIDC Back-Channel Logout).",
    "author": "Startup Pack",
    "website": "https://github.com/Startuppack/odoo-oidc-sso",
    "license": "LGPL-3",
    "category": "Authentication",
    "depends": ["auth_oauth", "auth_oidc"],
    "installable": True,
    "auto_install": False,
}
