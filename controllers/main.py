# Copyright Startup Pack — LGPL-3
#
# RP-initiated logout : par défaut le logout Odoo (/web/session/logout) ne ferme
# QUE la session Odoo → la session SSO Keycloak reste vivante (re-login silencieux,
# cf. issue « Logout dont logout of sso »). On override le controller pour, après
# avoir vidé la session Odoo, REBONDIR sur le end-session Keycloak du realm — qui
# tue la session SSO — avec `post_logout_redirect_uri` vers la page unifiée
# /logoutalltools et `id_token_hint` (évite l'écran de confirmation KC).
#
# Les données SSO (end-session, client_id, id_token) ont été posées en session au
# login par sp_auth_oidc_roles/models/res_users.py (_auth_oauth_signin).
import json
import logging
import os
import uuid
from urllib.parse import urlencode

from odoo import http
from odoo.http import request
from odoo.addons.web.controllers.home import Home

_logger = logging.getLogger(__name__)

# Évènement OIDC Back-Channel Logout (clé du claim `events` du logout_token).
_BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# Page d'atterrissage unifiée post-déconnexion (whitelistée sur le client KC
# `odoo` par oidc-init via post.logout.redirect.uris). Surchargée par l'env
# ODOO_LOGOUT_DONE si besoin (domaine plateforme custom).
LOGOUT_DONE = os.environ.get(
    "ODOO_LOGOUT_DONE", "https://platform.startuppack.eu/logoutalltools"
)


class SpOidcLogout(Home):

    @http.route()
    def logout(self, redirect="/web"):
        # Réutilise la route /web/session/logout du controller web standard.
        end = request.session.get("oidc_end_session") if request else None
        if end:
            params = {"post_logout_redirect_uri": LOGOUT_DONE}
            id_token = request.session.get("oidc_id_token")
            client_id = request.session.get("oidc_client_id")
            if id_token:
                params["id_token_hint"] = id_token
            elif client_id:
                params["client_id"] = client_id
            url = end + "?" + urlencode(params)
            try:
                request.session.logout(keep_db=True)
            except Exception:
                _logger.exception("sp_auth_oidc_roles: logout session Odoo")
            return request.redirect(url, local=False)
        # Pas de session SSO connue → comportement standard.
        return super().logout(redirect=redirect)

    # ── OIDC Back-Channel Logout : Keycloak POSTe un logout_token (JWT signé)
    #    quand la session SSO se termine → on invalide les sessions Odoo de
    #    l'utilisateur CÔTÉ SERVEUR (bump sp_logout_epoch → _compute_session_token
    #    change → sessions invalides). Vraie déconnexion IdP-initiée.
    @http.route("/web/oidc/backchannel_logout", type="http", auth="none",
                csrf=False, methods=["POST"], save_session=False)
    def oidc_backchannel_logout(self, **kw):
        claims = self._sp_verify_logout_token(kw.get("logout_token") or "")
        if not claims:
            return request.make_response("invalid logout_token", status=400)
        sub = claims.get("sub")
        killed = 0
        if sub:
            users = request.env["res.users"].sudo().search([("oauth_uid", "=", sub)])
            for u in users:
                u.write({"sp_logout_epoch": uuid.uuid4().hex})
                killed += 1
        return request.make_response(
            json.dumps({"logged_out": killed}),
            headers=[("Content-Type", "application/json")],
        )

    def _sp_verify_logout_token(self, token):
        """Vérifie le logout_token (RS256 via JWKS du realm) + iss/aud/event.
        Le `cryptography`/`python-jose` est présent dans l'image Odoo custom."""
        if not token:
            return None
        try:
            from jose import jwt as jose_jwt
            import requests as _rq

            prov = request.env["auth.oauth.provider"].sudo().search(
                [("client_id", "=", "odoo")], limit=1)
            auth_ep = prov.auth_endpoint or ""
            if not auth_ep.endswith("/auth"):
                return None
            base = auth_ep[:-5]  # <issuer>/protocol/openid-connect
            issuer = base.rsplit("/protocol/openid-connect", 1)[0]
            header = jose_jwt.get_unverified_header(token)
            jwks = _rq.get(base + "/certs", timeout=10, verify=False).json()
            key = next((k for k in jwks.get("keys", [])
                        if k.get("kid") == header.get("kid")), None)
            if not key:
                return None
            claims = jose_jwt.decode(
                token, key, algorithms=["RS256"], audience="odoo", issuer=issuer,
                options={"verify_at_hash": False})
            if _BCL_EVENT not in (claims.get("events") or {}):
                return None
            return claims
        except Exception:
            _logger.exception("sp_auth_oidc_roles: verify logout_token")
            return None
