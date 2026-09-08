# -*- coding: utf-8 -*-
"""
E2E Test: Shell-aware page rendering for admin fragment routes

Admin pages are HTMX fragments. Before the shell fix, a browser navigation
(address bar, bookmark, reload — ``Sec-Fetch-Dest: document``) received the
bare fragment: no <head>, stylesheets, or scripts, so module-driven pages
(blocklist, scanner, settings, ...) froze at their server-rendered initial
state with no styling. Router fetches must keep receiving bare fragments.
"""

import os

import pytest

# ── Flask test client fixtures ──────────────────────────────────────────────


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(_app):
    with _app.test_client() as c:
        with c.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        yield c


# ── Route matrix ────────────────────────────────────────────────────────────

_PAGE_ROUTES = [
    ("/admin/overview", "runtime-capabilities"),
    ("/admin/threats", "threats-view"),
    ("/admin/yara/rules", "yara-rules-container"),
    ("/admin/scanner", "scanner-view"),
    ("/admin/profiles", "profiles-view"),
    ("/admin/blocklist", "blocklist-view"),
    ("/admin/settings", "settings-grid"),
    ("/admin/settings/config/editor", "config-editor"),
    ("/admin/wal", "wal"),
    ("/admin/registry", "registry"),
    ("/admin/session", "session-page"),
    ("/admin/config", "config"),
]


# ── Tests ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("route,marker", _PAGE_ROUTES)
def test_navigation_gets_shell_with_fragment(client, route, marker):
    """Sec-Fetch-Dest: document (browser navigation) gets the full shell."""
    resp = client.get(route, headers={"Sec-Fetch-Dest": "document"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "app-shell" in body, "shell chrome missing on direct navigation"
    assert "app.js" in body, "app shell scripts missing on direct navigation"
    assert marker in body, f"fragment content missing inside shell for {route}"
    assert f'data-initial-path="{route[len("/admin/") :]}"'.replace('""', '"') in body


@pytest.mark.parametrize("route,marker", _PAGE_ROUTES)
def test_hx_request_gets_bare_fragment(client, route, marker):
    """Router fetches (HX-Request) keep receiving the bare fragment."""
    resp = client.get(route, headers={"HX-Request": "true"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert marker in body, f"fragment content missing for {route}"
    assert "app-shell" not in body, "router fetch must not receive the shell"
    assert "<html" not in body, "router fetch must stay a bare fragment"


@pytest.mark.parametrize("route,marker", _PAGE_ROUTES)
def test_headerless_client_gets_bare_fragment(client, route, marker):
    """Header-less clients (legacy tests, curl) keep the fragment behavior."""
    resp = client.get(route)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert marker in body
    assert "app-shell" not in body


def test_shell_embeds_config_editor_fields(client):
    """The settings config editor is fully usable from a direct navigation."""
    resp = client.get("/admin/settings/config/editor", headers={"Sec-Fetch-Dest": "document"})
    body = resp.get_data(as_text=True)
    assert 'data-initial-path="settings/config/editor"' in body
    assert "web_admin.allowed_ips" in body
    assert "cfg-section" in body


def test_shell_marks_nav_title(client):
    """The shell derives the page title for the embedded fragment."""
    resp = client.get("/admin/blocklist", headers={"Sec-Fetch-Dest": "document"})
    body = resp.get_data(as_text=True)
    assert "Blocklist" in body
    assert 'data-initial-title="Blocklist"' in body


def test_login_still_redirects_for_anonymous(_app):
    """Unauthenticated navigation still bounces to the login page."""
    with _app.test_client() as c:
        resp = c.get(
            "/admin/blocklist", headers={"Sec-Fetch-Dest": "document"}, follow_redirects=False
        )
        assert resp.status_code == 302
        assert "/admin/login" in resp.headers["Location"]


def test_dashboard_index_still_renders_shell(client):
    """The original shell route is unaffected."""
    resp = client.get("/admin/")
    assert resp.status_code == 200
    assert "app-shell" in resp.get_data(as_text=True)
