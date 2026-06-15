# Copyright Startup Pack — LGPL-3
#
# Pourquoi cet addon : Odoo CE (auth_oauth / OCA auth_oidc) authentifie l'user
# SSO mais NE MAPPE PAS ses rôles Keycloak vers des groupes Odoo. Résultat :
# tout user SSO est créé `share=True` (portail), même l'owner qui porte le rôle
# KC `odoo:admin`. La bonne réponse n'est ni un cron de rattrapage ni un trigger
# SQL, mais de dériver les droits DU TOKEN, au moment du login : le rôle est déjà
# dans `resource_access.odoo.roles` de l'id_token (mapper `client-roles-userinfo`
# côté Keycloak, claim posé sur id+access+userinfo). On override le hook standard
# `_auth_oauth_signin` (cf. son docstring « can be overridden ») pour appliquer
# les groupes après chaque connexion → Keycloak reste la source de vérité,
# resynchronisée à chaque login.

import hashlib
import logging

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

# Rôle du client Keycloak `odoo` -> liste de groupes Odoo (XML IDs). Les groupes
# dont le module n'est pas installé sont ignorés silencieusement (env.ref
# tolérant). On accepte aussi quelques rôles realm en repli (legacy).
ROLE_MAP = {
    # Administration complète. La plateforme assigne `admin` à l'owner ; le
    # chart (init-oidc) crée aussi la taxonomie persona `system-admin`. On mappe
    # les DEUX vers group_system pour couvrir les deux conventions.
    "admin": ["base.group_system"],
    "system-admin": ["base.group_system"],
    # Personas métier (taxonomie persona du chart). env.ref-gardés.
    "sales-manager": ["sales_team.group_sale_manager"],
    "sales-user": ["sales_team.group_sale_salesman"],
    "hr-manager": ["hr.group_hr_manager"],
    "hr-user": ["hr.group_hr_user"],
    "accounting-manager": ["account.group_account_manager"],
    "accounting-user": ["account.group_account_user"],
    "website-designer": ["website.group_website_designer"],
    # Repli rôles realm (users sans rôle par-client).
    "technique": ["base.group_system"],
}

# Rôles qui confèrent l'admin : pilotent l'ajout/retrait de group_system.
ADMIN_ROLES = {"admin", "system-admin", "technique"}


class ResUsers(models.Model):
    _inherit = "res.users"

    # « Époque de session » : changer cette valeur invalide TOUTES les sessions
    # Odoo de l'utilisateur (cf. _compute_session_token). Utilisé par le
    # Back-Channel Logout (controllers/main.py) pour tuer la session serveur quand
    # Keycloak pousse un logout. Vide par défaut → token de session inchangé
    # (comportement standard préservé pour qui n'a jamais subi de BCL).
    sp_logout_epoch = fields.Char(default="", copy=False)

    def _compute_session_token(self, sid):
        token = super()._compute_session_token(sid)
        # Mixe l'époque dans le token de session : si elle change, le token
        # recalculé ne matche plus celui stocké → session invalidée. Sûr : si
        # l'époque est vide, on renvoie le token de base tel quel.
        try:
            epoch = self.sudo().sp_logout_epoch or ""
        except Exception:
            epoch = ""
        if token and epoch:
            return hashlib.sha256(("%s|%s" % (token, epoch)).encode()).hexdigest()
        return token

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        login = super()._auth_oauth_signin(provider, validation, params)
        if login:
            try:
                self._sp_sync_oidc_groups(login, validation)
            except Exception:  # jamais bloquer le login pour un souci de mapping
                _logger.exception("sp_auth_oidc_roles: sync groupes échouée pour %s", login)
            # Mémorise de quoi faire un RP-initiated logout (end-session Keycloak)
            # à la déconnexion : sans ça, le logout Odoo ne ferme QUE la session
            # Odoo et laisse la session SSO Keycloak vivante (re-login silencieux).
            # Cf. controllers/main.py (override /web/session/logout).
            try:
                from odoo.http import request as _req
                prov = self.env["auth.oauth.provider"].sudo().browse(int(provider))
                auth_ep = prov.auth_endpoint or ""
                # auth_endpoint = <oidc_base>/auth → end-session = <oidc_base>/logout
                end = (auth_ep.rsplit("/auth", 1)[0] + "/logout") if auth_ep.endswith("/auth") else ""
                if _req and end:
                    _req.session["oidc_end_session"] = end
                    _req.session["oidc_client_id"] = prov.client_id or ""
                    _req.session["oidc_id_token"] = (params or {}).get("id_token") or ""
            except Exception:
                _logger.exception("sp_auth_oidc_roles: capture session logout SSO")
        return login

    @api.model
    def _sp_extract_roles(self, validation):
        """Rôles Keycloak présents dans le token : rôles du client `odoo`
        (primaire) + rôles realm (repli). Retourne (set_roles, had_odoo_client_claim)."""
        roles = set()
        ra = (validation or {}).get("resource_access") or {}
        odoo_access = ra.get("odoo")
        had_odoo_client_claim = isinstance(odoo_access, dict)
        if had_odoo_client_claim:
            roles.update(odoo_access.get("roles") or [])
        realm_access = (validation or {}).get("realm_access") or {}
        roles.update(realm_access.get("roles") or [])
        return roles, had_odoo_client_claim

    @api.model
    def _sp_sync_oidc_groups(self, login, validation):
        user = self.sudo().search([("login", "=", login)], limit=1)
        if not user:
            return

        roles, had_odoo_client_claim = self._sp_extract_roles(validation)

        def ref(xmlid):
            return self.env.ref(xmlid, raise_if_not_found=False)

        g_user = ref("base.group_user")
        g_system = ref("base.group_system")
        g_portal = ref("base.group_portal")

        commands = []
        # 1) Tout user SSO est INTERNE (jamais portail/share). group_system
        #    implique group_user, mais on l'ajoute explicitement pour les
        #    non-admins, et on retire le groupe portail (conflit type-groupe).
        if g_user:
            commands.append((4, g_user.id))
        if g_portal:
            commands.append((3, g_portal.id))

        # 2) Groupes métier dérivés des rôles (union, env.ref-gardé).
        for role in roles:
            for xmlid in ROLE_MAP.get(role, []):
                grp = ref(xmlid)
                if grp:
                    commands.append((4, grp.id))

        # 3) Admin : ajoute group_system si rôle admin ; le RETIRE seulement si
        #    le token portait bien les rôles du client `odoo` mais sans admin
        #    (token = source de vérité). Si le claim client `odoo` est absent
        #    (mapper KC mal configuré), on NE rétrograde PAS — évite une
        #    démotion de masse accidentelle.
        is_admin = bool(roles & ADMIN_ROLES)
        if g_system:
            if is_admin:
                commands.append((4, g_system.id))
            elif had_odoo_client_claim:
                commands.append((3, g_system.id))

        # write() recalcule les groupes impliqués et applique la contrainte de
        # groupes-type disjoints (portail retiré avant ajout interne).
        user.write({"group_ids": commands})
        _logger.info(
            "sp_auth_oidc_roles: %s -> %s (roles KC=%s)",
            login, "ADMIN" if is_admin else "interne", sorted(roles),
        )
