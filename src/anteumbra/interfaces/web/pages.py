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

This module also owns the site scope of the admin frontend.  A deployment may
watch several sites, so every page render resolves one active site: an explicit
``?site=<site_id>`` wins, then the remembered choice (session, then cookie), and
no choice at all means the aggregate of every site.  The resolved scope travels
with the render so the shell, its fragments and each row's own site label agree
with each other instead of drifting apart.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from flask import after_this_request, g, render_template, request, session

from anteumbra.interfaces.web.auth import get_admin_credentials
from anteumbra.interfaces.web.blueprints._shared import generate_secure_sse_token
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

# The URL parameter that scopes a page, plus the legacy alias the record,
# quarantine and profile routes already accepted.
SITE_QUERY_KEYS = ("site", "site_id")
SITE_COOKIE = "anteumbra_site"
SITE_SESSION_KEY = "anteumbra_site"

_NAV_TITLES = {
    "overview": "Overview",
    "threats": "Threats",
    "yara/rules": "Rules",
    "scanner": "Scanner",
    "profiles": "Profiles",
    "blocklist": "Blocklist",
    "memory-shell": "Memory Shell",
    "memory-shell/forensics": "Forensics",
    "logs/analyzer": "Log Analyzer",
    "settings": "Settings",
    # The advanced config editor lives at its own URL so the settings page can
    # link to it; the title is what the shell shows for that navigation.
    "config": "Config Editor",
}


def _initial_path() -> str:
    path = request.path
    prefix = "/admin/"
    return path[len(prefix) :].strip("/") if path.startswith(prefix) else path.strip("/")


def _display_title(initial_path: str) -> str:
    """Titles come from the same catalog the nav uses, so zh stays Chinese."""
    title = _NAV_TITLES.get(initial_path)
    if not title:
        segment = initial_path.rsplit("/", 1)[-1] if initial_path else ""
        title = segment.replace("-", " ").replace("_", " ").title() or "Overview"
    try:
        from flask_babel import gettext as _babel

        return _babel(title)
    except Exception:  # pragma: no cover - flask-babel is optional
        return title


def _sse_token(username: str) -> str:
    token = session.get("sse_token")
    if not token:
        token = generate_secure_sse_token(username)
        session["sse_token"] = token
    return token


def configured_sites() -> list[dict]:
    """Return the enabled sites as ``{site_id, name}`` pairs, in config order."""
    try:
        websites = get_runtime().config.get_enabled_websites()
    except Exception:  # pragma: no cover - a config failure must not break the shell
        logger.debug("enabled websites are unavailable for the site scope", exc_info=True)
        return []
    sites: list[dict] = []
    seen: set[str] = set()
    for website in websites or ():
        site_id = str(getattr(website, "site_id", "") or "").strip().lower()
        if not site_id or site_id in seen:
            continue
        seen.add(site_id)
        sites.append(
            {
                "site_id": site_id,
                "name": str(getattr(website, "name", "") or site_id),
            }
        )
    return sites


def _requested_site_value():
    """Return the site the URL asks for, or ``None`` when the URL is silent.

    An *empty* parameter (``?site=``) is not silence: it is an explicit request
    for the aggregate view, so it must beat the remembered choice.
    """
    for key in SITE_QUERY_KEYS:
        if key in request.args:
            return request.args.get(key, "")
    return None


def _remembered_site_value() -> str:
    """The site the operator last chose, if the browser or session kept it."""
    try:
        remembered = session.get(SITE_SESSION_KEY)
    except Exception:  # pragma: no cover - sessions are optional in thin clients
        remembered = None
    if not remembered:
        remembered = request.cookies.get(SITE_COOKIE)
    return str(remembered or "").strip().lower()


def _remember_site(site_id: str | None) -> None:
    """Persist an explicit URL choice so a plain page load keeps the scope."""
    value = site_id or ""
    try:
        session[SITE_SESSION_KEY] = value
    except Exception:  # pragma: no cover - keep rendering without session support
        logger.debug("site choice could not be stored in the session", exc_info=True)

    @after_this_request
    def _persist(response):
        try:
            if value:
                response.set_cookie(
                    SITE_COOKIE,
                    value,
                    max_age=365 * 24 * 3600,
                    samesite="Lax",
                )
            else:
                response.delete_cookie(SITE_COOKIE)
        except Exception:  # pragma: no cover - a response without headers is not fatal
            logger.debug("site choice could not be written to a cookie", exc_info=True)
        return response


def _resolve_active_site(sites: list[dict]) -> str | None:
    """Resolve the active site: URL wins, then the remembered choice, else all."""
    known = {site["site_id"] for site in sites}
    explicit = _requested_site_value()
    if explicit is not None:
        candidate = str(explicit).strip().lower()
        active = candidate if candidate in known else None
        # An unknown or empty id is an authoritative "all sites" request: it is
        # remembered as such, so a stale cookie cannot resurrect a dead site.
        _remember_site(active)
        return active
    remembered = _remembered_site_value()
    return remembered if remembered in known else None


def site_context() -> dict:
    """Return this request's site scope, resolving and caching it once.

    ``active_site`` is ``None`` for the aggregate view.  Templates read
    ``sites``/``active_site`` directly and build scoped URLs with ``with_site``.
    """
    cached = getattr(g, "_site_context", None)
    if isinstance(cached, dict):
        return dict(cached)

    sites = configured_sites()
    active_site = _resolve_active_site(sites)
    names = {site["site_id"]: site["name"] for site in sites}
    values = {
        "sites": sites,
        "active_site": active_site,
        "active_site_name": names.get(active_site) if active_site else None,
        "aggregate_scope": active_site is None,
        "site_switcher_visible": len(sites) > 1,
    }
    g._site_context = values
    g.active_site = active_site
    return dict(values)


def active_site_id() -> str | None:
    """The active site for this request, resolving the scope on first use."""
    if not isinstance(getattr(g, "_site_context", None), dict):
        site_context()
    return getattr(g, "active_site", None)


def with_site(url: str) -> str:
    """Append the active site to an admin URL so a fragment keeps the scope.

    Fragments carry their scope in the URL: HTMX swaps them in without a page
    load, so the server has no other way to know which site the operator is
    looking at.  In the aggregate view the URL stays untouched.
    """
    site_id = active_site_id()
    if not url or not site_id:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}site={quote(site_id)}"


def shell_context() -> dict:
    """Context the dashboard shell needs: SSE token, username, client IP, site.

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
        **site_context(),
    }


def render_page(template: str, **context):
    """Render ``template`` as a fragment, or embedded in the shell on navigation.

    Router fetches (``HX-Request`` header present, or no ``Sec-Fetch-Dest``)
    receive the bare fragment exactly as before.  Browser navigations
    (``Sec-Fetch-Dest: document``) receive the dashboard shell with the
    fragment included server-side.

    Both paths carry the site scope, and an explicitly passed value wins: a
    caller that already resolved the site (for example a route that filters its
    query) must not be overruled here.
    """
    for key, value in site_context().items():
        context.setdefault(key, value)

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
