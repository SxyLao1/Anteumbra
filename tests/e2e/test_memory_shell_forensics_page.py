# -*- coding: utf-8 -*-
"""
E2E: the memory-shell forensics (取证) tab is reachable and shell-aware.

Follows ``tests/e2e/test_memory_shell_page.py``: a browser navigation
(``Sec-Fetch-Dest: document``) must receive the dashboard shell with the page
embedded, while a router fetch (``HX-Request``) must keep receiving the bare
fragment.

The probe plugin is not wired into this runtime, so the forensics panel route is
only required to *answer*: which state it reports — ready, unavailable or error
— is covered by ``tests/core/test_memory_shell_forensics_page.py`` against a stub
service.  Nothing here starts a container, a network request or a forensics run.
"""

import os

import pytest

ROUTE = "/admin/memory-shell/forensics"
PANEL_ROUTE = "/admin/memory-shell/forensics/panel"
DETECTION_ROUTE = "/admin/memory-shell"


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
    """A bookmark or reload gets the shell with the forensics page inside."""
    resp = client.get(ROUTE, headers={"Sec-Fetch-Dest": "document"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "app-shell" in body, "shell chrome missing on direct navigation"
    assert "app.js" in body, "app shell scripts missing on direct navigation"
    assert 'id="memory-shell-forensics-view"' in body, "page fragment missing inside the shell"
    assert 'data-initial-path="memory-shell/forensics"' in body


def test_router_fetch_gets_the_bare_fragment(client):
    resp = client.get(ROUTE, headers={"HX-Request": "true"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'id="memory-shell-forensics-view"' in body
    assert "app-shell" not in body, "router fetch must not receive the shell"
    assert "<html" not in body, "router fetch must stay a bare fragment"


def test_page_loads_its_panel_and_the_dialog_container(client):
    """The page shell must ask for the panel and own the 处置 dialog target."""
    body = client.get(ROUTE, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'id="memory-shell-forensics-panel"' in body
    assert f'hx-get="{PANEL_ROUTE}"' in body
    assert 'hx-trigger="load"' in body
    assert 'id="memory-shell-dialog"' in body
    assert 'id="memory-shell-forensics-detail"' in body


def test_panel_route_answers_with_or_without_the_probe_plugin(client):
    """An unplugged feature is a state in the panel, never a 500."""
    resp = client.get(PANEL_ROUTE, headers={"HX-Request": "true"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "data-forensics-state=" in body
    assert "Traceback" not in body


def test_panel_route_accepts_a_prefilled_component(client):
    """前往取证 navigates here with the component; the route must not choke."""
    resp = client.get(
        f"{PANEL_ROUTE}?site_id=alpha&kind=filter&name=evilFilter",
        headers={"HX-Request": "true"},
    )

    assert resp.status_code == 200
    assert "Traceback" not in resp.get_data(as_text=True)


def test_manifest_route_answers_for_an_unknown_artifact(client):
    resp = client.get("/admin/memory-shell/forensics/manifest/nope", headers={"HX-Request": "true"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "data-manifest-state=" in body
    assert "Traceback" not in body


def test_download_route_refuses_an_unknown_artifact(client):
    resp = client.get("/admin/memory-shell/forensics/download/nope/manifest.json")

    assert resp.status_code == 404


def test_forensics_requires_authentication(_app):
    with _app.test_client() as c:
        resp = c.get(ROUTE, headers={"Sec-Fetch-Dest": "document"}, follow_redirects=False)

    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_the_detection_tab_still_renders_next_to_it(client):
    """The two tabs share one probe; neither may break the other."""
    detection = client.get(DETECTION_ROUTE, headers={"HX-Request": "true"})

    assert detection.status_code == 200
    body = detection.get_data(as_text=True)
    assert 'id="memory-shell-view"' in body
    assert 'id="memory-shell-dialog"' in body
