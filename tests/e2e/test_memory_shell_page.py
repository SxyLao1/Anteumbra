# -*- coding: utf-8 -*-
"""
E2E: the memory-shell admin page is reachable, titled and advertised in the nav.

Follows ``tests/e2e/test_page_shell.py``: a browser navigation
(``Sec-Fetch-Dest: document``) must receive the dashboard shell with the page
embedded, while a router fetch (``HX-Request``) must keep receiving the bare
fragment.

The probe plugin may not be wired into this runtime, so the panel route is only
required to *answer*: which state it reports — ready, unavailable or error — is
covered by ``tests/core/test_web_memory_shell.py`` against a stub service.
"""

import os

import pytest

ROUTE = "/admin/memory-shell"
PANEL_ROUTE = "/admin/memory-shell/panel"


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


# ── Tests ───────────────────────────────────────────────────────────────────


def test_direct_navigation_renders_the_page_in_the_shell(client):
    """A bookmark or reload gets the shell with the memory-shell page inside."""
    resp = client.get(ROUTE, headers={"Sec-Fetch-Dest": "document"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "app-shell" in body, "shell chrome missing on direct navigation"
    assert "app.js" in body, "app shell scripts missing on direct navigation"
    assert 'id="memory-shell-view"' in body, "page fragment missing inside the shell"
    assert 'data-initial-path="memory-shell"' in body
    assert 'data-initial-title="Memory Shell"' in body


def test_router_fetch_gets_the_bare_fragment(client):
    resp = client.get(ROUTE, headers={"HX-Request": "true"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'id="memory-shell-view"' in body
    assert "app-shell" not in body, "router fetch must not receive the shell"
    assert "<html" not in body, "router fetch must stay a bare fragment"


def test_page_loads_its_panel_fragment(client):
    """The page shell must ask for the panel instead of embedding probe state."""
    body = client.get(ROUTE, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'id="memory-shell-panel"' in body
    assert f'hx-get="{PANEL_ROUTE}"' in body
    assert 'hx-trigger="load"' in body


def test_navigation_advertises_the_page(client):
    """The sidebar entry exists with the path the router and title map use."""
    body = client.get("/admin/", headers={"Sec-Fetch-Dest": "document"}).get_data(as_text=True)

    assert f'href="{ROUTE}"' in body
    assert 'data-path="memory-shell"' in body
    assert 'data-title="Memory Shell"' in body


def test_panel_route_answers_with_or_without_the_probe_plugin(client):
    """An unplugged feature is a state in the panel, never a 500."""
    resp = client.get(PANEL_ROUTE, headers={"HX-Request": "true"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "data-memory-shell-state=" in body
    assert "Traceback" not in body


def test_memory_shell_requires_authentication(_app):
    with _app.test_client() as c:
        resp = c.get(ROUTE, headers={"Sec-Fetch-Dest": "document"}, follow_redirects=False)

    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]
