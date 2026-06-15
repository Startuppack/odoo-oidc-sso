{
    # Startup Pack — mapping des rôles Keycloak (présents dans le token OIDC)
    # vers les groupes Odoo, AU LOGIN. Source de vérité = le token, pas un cron
    # ni un trigger SQL. Bumpez `version` à chaque modif de la logique pour que
    # `-u sp_auth_oidc_roles` recharge réellement le code.
    "name": "Startup Pack — Sync rôles OIDC → groupes",
    "version": "19.0.2.0.0",
    "summary": "Mappe resource_access.odoo.roles du token Keycloak vers les "
               "groupes Odoo (admin/interne) à chaque connexion SSO.",
    "author": "Startup Pack",
    "license": "LGPL-3",
    "category": "Authentication",
    "depends": ["auth_oauth", "auth_oidc"],
    "installable": True,
    "auto_install": False,
}
