# -*- coding: utf-8 -*-
"""Shared web authentication helpers for admin blueprints."""

from functools import wraps
from ipaddress import ip_address, ip_network

from flask import jsonify, make_response, redirect, request, session, url_for

from anteumbra.interfaces.web.runtime import get_runtime

# Machine-readable marker so the frontend can tell an expired session apart from
# any other 401 (a wrong password on the change-password form is also a 401).
SESSION_EXPIRED_CODE = "session_expired"
IP_DENIED_CODE = "ip_denied"
AUTH_STATUS_HEADER = "X-Auth-Status"

# Message shown by the frontend when the session is gone; the client renders a
# translated string keyed off the code, this is only the fallback body.
SESSION_EXPIRED_MESSAGE = "Your session has expired. Please sign in again."


def get_admin_credentials():
    """从配置读取管理员凭证"""
    cfg = get_runtime().config.get().get("web_admin", {})
    username = cfg.get("username", "admin")
    password_hash = cfg.get("password_hash", "")
    allowed_ips = cfg.get("allowed_ips", ["127.0.0.1"])
    return username, password_hash, allowed_ips


def is_ip_allowed(client_ip: str, allowed_ips) -> bool:
    """Match a client address against exact IPs or CIDR ranges."""
    try:
        address = ip_address(str(client_ip or "").strip())
    except ValueError:
        return False
    if isinstance(allowed_ips, str):
        allowed_ips = [allowed_ips]
    for value in allowed_ips or []:
        try:
            if address in ip_network(str(value).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def is_async_request() -> bool:
    """Whether this request swaps HTML into part of an existing page.

    A redirect is the right answer for a top-level navigation, but for an HTMX or
    fetch request the browser follows it silently and the login page lands inside
    the dashboard's content area.  Those callers need a status code they can
    react to instead.
    """
    if request.headers.get("HX-Request", "").strip().lower() == "true":
        return True
    if request.headers.get("X-Requested-With", "").strip().lower() == "xmlhttprequest":
        return True
    if "application/json" in request.headers.get("Accept", ""):
        return True
    # "document" means a top-level navigation, "empty" means fetch/XHR.  An
    # absent header means an older client, which we treat as a navigation.
    return request.headers.get("Sec-Fetch-Dest") not in (None, "", "document")


def _auth_failure(message: str, status: int, code: str, *, redirect_to_login: bool):
    if is_async_request():
        response = make_response(jsonify({"error": message, "code": code}), status)
        response.headers[AUTH_STATUS_HEADER] = code
        return response
    if redirect_to_login:
        return redirect(url_for("admin.login"))
    return make_response(message, status)


def require_auth(f):
    """认证装饰器：检查 IP 白名单 + Session 登录状态"""

    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        _, _, allowed_ips = get_admin_credentials()
        if not is_ip_allowed(client_ip, allowed_ips):
            return _auth_failure(
                f"IP {client_ip} 被拒绝访问", 403, IP_DENIED_CODE, redirect_to_login=False
            )
        if not session.get("authenticated"):
            return _auth_failure(
                SESSION_EXPIRED_MESSAGE, 401, SESSION_EXPIRED_CODE, redirect_to_login=True
            )
        return f(*args, **kwargs)

    return decorated
