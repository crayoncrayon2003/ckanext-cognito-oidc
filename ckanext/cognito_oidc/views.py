from __future__ import annotations

import base64
import logging
from urllib.parse import urlencode

import requests
from flask import Blueprint

import ckan.plugins.toolkit as tk
from ckan.common import session
from ckan.plugins import PluginImplementations

from . import config, utils
from .interfaces import ICognitoOidc

log = logging.getLogger(__name__)

SESSION_STATE = "ckanext:cognito-oidc:state"
SESSION_CAME_FROM = "ckanext:cognito-oidc:came_from"
SESSION_ERROR = "ckanext:cognito-oidc:error"

bp = Blueprint("cognito_oidc", __name__)

def get_blueprints():

    return [bp]

@bp.route("/user/login/cognito-oidc")
def login():
    state = utils.app_state()
    session[SESSION_STATE] = state
    session[SESSION_CAME_FROM] = tk.request.args.get("came_from")

    dict_queryparams = {
        "response_type": "code",
        "client_id": config.client_id(),
        "redirect_uri": config.redirect_url(),
        "state": state,
        "scope": config.scope(),
    }
    str_queryparams = "&".join("%s=%s" % (k,v) for k,v in dict_queryparams.items())

    str_url = "{base_url}?{query_params}".format(
        base_url=config.auth_url(), query_params=str_queryparams
    )

    resp = tk.redirect_to(str_url)

    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


def callback():
    # TODO: check state
    error = tk.request.args.get("error")
    state = tk.request.args.get("state")
    code  = tk.request.args.get("code")

    session_state = session.pop(SESSION_STATE, None)
    came_from = (
        config.error_redirect()
        or tk.url_for("user.login")
    )

    if not error:
        if not code:
            error = "The code was not returned or is not accessible"
        elif state != session_state:
            error = "The app state does not match"

    if error:
        log.error(f"Error: {error}")
        session[SESSION_ERROR] = error
        return tk.redirect_to(came_from)

    # Get tokens
    str_authinfo: str = config.client_id() + ":" + config.client_secret()
    str_authorization = "Basic " + base64.b64encode(str_authinfo.encode('ascii')).decode('ascii')

    dct_tokenurl_headers = {
        "accept": "application/json",
        "cache-control": "no-cache",
        "Authorization": str_authorization,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    dct_tokenurl_queryparams = {
        "grant_type": "authorization_code",
        "client_id": config.client_id(),
        "redirect_uri": config.redirect_url(),
        "code": code,
    }
    # if ("Authorization" not in dct_tokenurl_headers) and (config.client_secret()):
    #     dct_tokenurl_queryparams["client_secret"] = config.client_secret()
    str_tokenurl_queryparams = "&".join("%s=%s" % (k,v) for k,v in dct_tokenurl_queryparams.items())

    str_tokenurl_url = "{base_url}?{query_params}".format(
        base_url=config.token_url(), query_params=str_tokenurl_queryparams
    )
    exchange = requests.post(str_tokenurl_url, headers=dct_tokenurl_headers).json()

    # Validate
    if not exchange.get("token_type"):
        error = "Unsupported token type. Should be 'Bearer'."
        log.error("Error: %s", error)
        session[SESSION_ERROR] = error
        return tk.redirect_to(came_from)

    access_token = exchange["access_token"]

    # Authorization flow successful, get userinfo and login user
    dct_userinfourl_headers = {
        "Authorization": f"Bearer {access_token}",
    }
    dct_userinfourl_queryparams={}
    str_userinfourl_queryparams = "&".join("%s=%s" % (k,v) for k,v in dct_userinfourl_queryparams.items())

    str_userinfourl_url = "{base_url}".format(
        base_url=config.userinfo_url(), query_params=str_userinfourl_queryparams
    )

    userinfo = requests.get(str_userinfourl_url, headers=dct_userinfourl_headers).json()

    # OIDC specifications
    if "name" not in userinfo["username"]:
        userinfo["name"] = userinfo["username"]

    user = utils.sync_user(userinfo)
    if not user:
        error = "User not found"
        log.error("Error: %s", error)
        session[SESSION_ERROR] = error
        return tk.redirect_to(came_from)

    for plugin in PluginImplementations(ICognitoOidc):
        resp = plugin.oidc_login_response(user)
        if resp:
            return resp

    utils.login(user)

    came_from = session.pop(SESSION_CAME_FROM, None)

    return tk.redirect_to(
        came_from or tk.config.get("ckan.route_after_login", "dashboard.index")
    )

bp.add_url_rule(config.redirect_path(), view_func=callback)
