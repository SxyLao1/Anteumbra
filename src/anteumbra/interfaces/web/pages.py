# -*- coding: utf-8 -*-
"""Shell-aware rendering for admin page routes.

Admin pages are HTMX fragments that the frontend router swaps into the
dashboard shell.  A browser navigation (address bar, bookmark, reload)
carries ``Sec-Fetch-Dest: document`` and no ``HX-Request`` header; before
this module existed those requests received the bare fragment — a document
without ``<head>``, stylesheets, or scripts, so every module-driven page
(blocklist, scanner, settings, ...) appeared frozen at its server-rendered
initial state.

``render_page`` keeps the fragment for router fetches and, for browser
navigations, renders the full dashboard shell with the fragment embedded
server-side.  The shell's ``#main-content`` carries ``data-initial-path``
so ``dashboard.js`` adopts the embedded page instead of forcing Overview.
"""

from __future__ import annotations

from flask import render_template, request, session

from anteumbra.interfaces.web.auth import get_admin_credentials
from anteumbra.interfaces.web.blueprints._shared import generate_secure_sse_token

_NAV_TITLES = {
    "overview": "Overview",
    "threats": "Threats",
    "yara/rules": "Rules",
    "scanner": "Scanner",
    "profiles": "Profiles",
    "blocklist": "Blocklist",
    "logs/analyzer": "Log Analyzer",
    "settings": "Settings",
}


def _initial_path() -> str:
    path = request.path
    prefix = "/admin/"
    return path[len(prefix) :].strip("/") if path.startswith(prefix) else path.strip("/")


def _display_title(initial_path: str) -> str:
    title = _NAV_TITLES.get(initial_path)
    if title:
        return title
    segment = initial_path.rsplit("/", 1)[-1] if initial_path else ""
    return segment.replace("-", " ").replace("_", " ").title() or "Overview"


def _sse_token(username: str) -> str:
    token = session.get("sse_token")
    if not token:
        token = generate_secure_sse_token(username)
        session["sse_token"] = token
    return token


def shell_context() -> dict:
    """Context the dashboard shell needs: SSE token, username, client IP.

    Templates that extend ``admin/dashboard.html`` directly — quarantine.html —
    must pass this as well, otherwise the SSE token meta tag renders empty and
    the live stream reports "Token missing" instead of connecting.
    """
    username = session.get("username") or get_admin_credentials()[0]
    session.setdefault("username", username)
    return {
        "auth_header": _sse_token(username),
        "username": username,
        "client_ip": request.remote_addr,
    }


def render_page(template: str, **context):
    """Render ``template`` as a fragment, or embedded in the shell on navigation.

    Router fetches (``HX-Request`` header present, or no ``Sec-Fetch-Dest``)
    receive the bare fragment exactly as before.  Browser navigations
    (``Sec-Fetch-Dest: document``) receive the dashboard shell with the
    fragment included server-side.
    """
    if request.headers.get("Sec-Fetch-Dest") != "document":
        return render_template(template, **context)

    initial_path = _initial_path()
    shell_values = shell_context()
    shell_values.update(
        {
            "initial_fragment": template,
            "initial_path": initial_path,
            "initial_title": _display_title(initial_path),
        }
    )
    shell_values.update(context)
    return render_template("admin/dashboard.html", **shell_values)
