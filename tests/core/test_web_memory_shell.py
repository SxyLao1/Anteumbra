# -*- coding: utf-8 -*-
"""The memory-shell admin surface: panel states and the manual trigger.

The probe service is a runtime attribute that may be absent (plugin not
enabled), and the real one deploys a JSP into a live web root, so these tests
drive the blueprint with a stub service: a unit test must not need a servlet
container, a filesystem or a network.
"""

from __future__ import annotations

import os
import re

import pytest

PANEL_URL = "/admin/memory-shell/panel"
PROBE_URL = "/admin/memory-shell/probe"


class MemoryShellStub:
    """Stand-in for ``MemoryShellService`` that records what the route asks for."""

    def __init__(self, snapshot):
        self._snapshot = snapshot
        self.calls = []
        self.run_error = None

    def snapshot(self):
        if isinstance(self._snapshot, Exception):
            raise self._snapshot
        return self._snapshot

    def run_probe(self, site_id, **kwargs):
        self.calls.append({"site_id": site_id, **kwargs})
        if self.run_error is not None:
            raise self.run_error
        return None


# ── snapshot fixtures ───────────────────────────────────────────────────────


def _site(site_id="alpha", name="Alpha"):
    return {
        "site_id": site_id,
        "name": name,
        "root": "E:/www/alpha",
        "base_url": "http://127.0.0.1:8081",
        "port": 8081,
        "cooldown_remaining": 0.0,
    }


def _entry(name, *, suspect, kind="filter"):
    return {
        "kind": kind,
        "name": name,
        "urls": ["/*"] if kind == "filter" else ["/evil"],
        "class_name": f"com.evil.{name}",
        "class_loader": "WebappClassLoader",
        "resource": None if suspect else "/WEB-INF/lib/known.jar",
        "code_source": None,
        "suspect": suspect,
        "reasons": ["no_class_on_disk", "unknown_loader"] if suspect else [],
        "on_disk": not suspect,
    }


def _report(entries):
    return {
        "site_id": "alpha",
        "url": "http://127.0.0.1:8081/mb-x/probe.jsp",
        "fetched_at": 1_700_000_003.0,
        "probe_version": "1.0.0",
        "context_path": "/alpha",
        "container": ["Apache Tomcat/9.0.85"],
        "error": None,
        "duration_ms": 1200,
        "raw_bytes": 4096,
        "counts": {"filter": 2, "servlet": 1},
        "entries": entries,
    }


def _outcome(**overrides):
    outcome = {
        "site_id": "alpha",
        "site_name": "Alpha",
        "started_at": 1_700_000_000.0,
        "finished_at": 1_700_000_004.0,
        "duration_ms": 4000,
        "ok": True,
        "failure": None,
        "cleanup_ok": True,
        "cleanup_error": None,
        "trigger": "manual",
        "triggered_by": "admin",
        "suspect_count": 0,
        "report": None,
    }
    outcome.update(overrides)
    return outcome


def _snapshot(**overrides):
    snapshot = {
        "enabled": True,
        "auto_probe": True,
        "cooldown_seconds": 300.0,
        "http_timeout_seconds": 8.0,
        "trigger_extensions": [".jsp", ".jspx"],
        "sites": [_site()],
        "latest": {},
        "history": [],
        "running": [],
        "runs": 0,
        "failures": 0,
    }
    snapshot.update(overrides)
    return snapshot


def _run_with_findings():
    """One clean run with one suspect plus, newer, a run whose cleanup failed."""
    return _outcome(
        site_id="alpha",
        site_name="Alpha",
        finished_at=1_700_000_004.0,
        suspect_count=1,
        report=_report(
            [
                _entry("ShellFilter", suspect=True),
                _entry("CharacterEncodingFilter", suspect=False),
                _entry("DefaultServlet", suspect=False, kind="servlet"),
            ]
        ),
    )


def _run_with_broken_cleanup():
    return _outcome(
        site_id="alpha",
        site_name="Alpha",
        finished_at=1_700_000_060.0,
        ok=False,
        failure=None,
        cleanup_ok=False,
        cleanup_error="PermissionError: cannot delete mb-x/probe.jsp",
        trigger="auto",
        triggered_by="E:/www/alpha/upload.jsp",
    )


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
def make_client(monkeypatch, _app):
    """Build a client whose blueprint sees ``service`` as the runtime's probe."""
    from anteumbra.interfaces.web.blueprints import memory_shell_bp as module

    def _make(service, *, authenticated=True):
        runtime = type("Runtime", (), {})()
        if service is not None:
            runtime.memory_shell = service
        monkeypatch.setattr(module, "get_runtime", lambda: runtime)

        client = _app.test_client()
        if authenticated:
            with client.session_transaction() as flask_session:
                flask_session["authenticated"] = True
                flask_session["username"] = "admin"
        return client

    return _make


# ── panel rendering ─────────────────────────────────────────────────────────


def test_panel_reports_findings_failures_and_cleanup_state(make_client):
    service = MemoryShellStub(
        _snapshot(
            latest={"alpha": _run_with_findings()},
            history=[_run_with_broken_cleanup(), _run_with_findings()],
            runs=2,
            failures=0,
        )
    )

    response = make_client(service).get(PANEL_URL, headers={"HX-Request": "true"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-memory-shell-state="ready"' in body
    # the suspicious entry is listed with its class, loader and reason chips
    assert "ShellFilter" in body
    assert "com.evil.ShellFilter" in body
    assert "WebappClassLoader" in body
    assert "no_class_on_disk" in body
    # the two non-suspicious entries are collapsed into a count line
    assert "2 non-suspicious entries collapsed" in body
    assert "CharacterEncodingFilter" not in body
    # a run whose cleanup failed is visible and named as such
    assert "Probe cleanup failed:" in body
    assert "PermissionError: cannot delete mb-x/probe.jsp" in body
    assert "A probe file may still exist in the web root. Remove it manually." in body
    # per-site row and the trigger button
    assert "E:/www/alpha" in body
    assert f'hx-post="{PROBE_URL}?site_id=alpha"' in body


def test_panel_reports_a_failed_run(make_client):
    failed = _outcome(
        ok=False,
        failure="ProbeError: probe returned an empty body",
        suspect_count=0,
        report=None,
    )
    service = MemoryShellStub(_snapshot(history=[failed], latest={"alpha": failed}, failures=1))

    body = make_client(service).get(PANEL_URL).get_data(as_text=True)

    assert "Probe failed:" in body
    assert "ProbeError: probe returned an empty body" in body


def test_panel_renders_a_real_probe_outcome(make_client):
    """Lock the view model to the probe's own serializer, not to a hand-made dict.

    The panel reads ``ProbeOutcome.as_dict()`` output, so the shapes that matter
    are the ones the domain objects actually emit (tuples, counts computed from
    the entries, ``on_disk`` derived from the resource).
    """
    domain = pytest.importorskip("anteumbra.domain.memory_shell")

    suspect = domain.MemoryShellEntry(
        kind=domain.KIND_FILTER,
        name="ShellFilter",
        urls=("/*",),
        class_name="com.evil.ShellFilter",
        class_loader="WebappClassLoader",
        suspect=True,
        reasons=("no_class_on_disk",),
    )
    known = domain.MemoryShellEntry(
        kind=domain.KIND_SERVLET,
        name="DefaultServlet",
        class_name="org.apache.catalina.servlets.DefaultServlet",
        resource="/WEB-INF/lib/tomcat.jar",
    )
    report = domain.ProbeReport(
        site_id="alpha",
        url="http://127.0.0.1:8081/mb-x/probe.jsp",
        fetched_at=1_700_000_003.0,
        context_path="/alpha",
        container=("Apache Tomcat/9.0.85",),
        entries=(suspect, known),
    )
    outcome = domain.ProbeOutcome(
        site_id="alpha",
        site_name="Alpha",
        started_at=1_700_000_000.0,
        finished_at=1_700_000_004.0,
        report=report,
        trigger="manual",
        triggered_by="admin",
    ).as_dict()
    service = MemoryShellStub(_snapshot(latest={"alpha": outcome}, history=[outcome], runs=1))

    body = make_client(service).get(PANEL_URL).get_data(as_text=True)

    assert 'data-memory-shell-state="ready"' in body
    assert "ShellFilter" in body
    assert "com.evil.ShellFilter" in body
    assert "no_class_on_disk" in body
    assert "Apache Tomcat/9.0.85" in body
    assert "filter 1 · servlet 1" in body
    assert "1 non-suspicious entries collapsed" in body


def test_panel_without_the_service_names_the_missing_plugin(make_client):
    """``runtime.memory_shell is None`` is a state, not a crash."""
    response = make_client(None).get(PANEL_URL, headers={"HX-Request": "true"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-memory-shell-state="unavailable"' in body
    assert "memory_shell_probe" in body
    assert "Memory-shell probe unavailable" in body
    assert "Traceback" not in body
    # nothing to probe and nothing to list
    assert "Probe Memory Shell" not in body


def test_panel_reports_a_broken_service_instead_of_raising(make_client):
    service = MemoryShellStub(RuntimeError("service exploded"))

    response = make_client(service).get(PANEL_URL, headers={"HX-Request": "true"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-memory-shell-state="error"' in body
    assert "service exploded" in body


def test_panel_polls_only_while_a_probe_runs(make_client):
    idle = MemoryShellStub(_snapshot(history=[_run_with_findings()]))
    running = MemoryShellStub(_snapshot(running=["alpha"]))

    idle_body = make_client(idle).get(PANEL_URL).get_data(as_text=True)
    running_body = make_client(running).get(PANEL_URL).get_data(as_text=True)

    assert 'hx-trigger="every 2s"' not in idle_body
    assert 'hx-trigger="every 2s"' in running_body
    assert 'hx-target="#memory-shell-panel"' in running_body
    # a running site cannot be triggered a second time from the panel
    assert "Probing..." in running_body
    assert f'hx-post="{PROBE_URL}?site_id=alpha"' not in running_body


def test_page_shell_renders_without_the_service(make_client):
    response = make_client(None).get("/admin/memory-shell", headers={"HX-Request": "true"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'id="memory-shell-view"' in body
    assert 'hx-get="/admin/memory-shell/panel"' in body


# ── manual trigger ──────────────────────────────────────────────────────────


def test_probe_starts_a_background_run(make_client):
    service = MemoryShellStub(_snapshot())

    response = make_client(service).post(PROBE_URL, data={"site_id": "alpha"})

    assert response.status_code == 200
    assert service.calls == [
        {
            "site_id": "alpha",
            "trigger": "manual",
            "triggered_by": "admin",
            "background": True,
        }
    ]
    # the panel keeps polling so the result shows up without a reload
    assert 'hx-trigger="every 2s"' in response.get_data(as_text=True)


def test_probe_accepts_the_query_form_the_panel_posts(make_client):
    """The button posts ``?site_id=...``; a form field must work as well."""
    service = MemoryShellStub(_snapshot())

    query_response = make_client(service).post(f"{PROBE_URL}?site_id=alpha")
    form_response = make_client(service).post(PROBE_URL, data={"site_id": "alpha"})

    assert query_response.status_code == 200
    assert form_response.status_code == 200
    assert [call["site_id"] for call in service.calls] == ["alpha", "alpha"]


def test_probe_refuses_an_unknown_site(make_client):
    service = MemoryShellStub(_snapshot(sites=[_site("alpha")]))

    response = make_client(service).post(PROBE_URL, data={"site_id": "ghost"})

    # 200, not 4xx: htmx does not swap error responses, and the operator has to
    # see why the probe did not run.
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Unknown site: ghost" in body
    assert service.calls == []


def test_probe_refuses_a_missing_site(make_client):
    service = MemoryShellStub(_snapshot())

    response = make_client(service).post(PROBE_URL, data={})

    assert response.status_code == 200
    assert "No site was selected for the probe." in response.get_data(as_text=True)
    assert service.calls == []


def test_probe_refuses_to_guess_when_the_service_is_missing(make_client):
    response = make_client(None).post(PROBE_URL, data={"site_id": "alpha"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-memory-shell-state="unavailable"' in body
    assert "not available" in body


def test_probe_reports_a_snapshot_failure(make_client):
    service = MemoryShellStub(RuntimeError("registry offline"))

    response = make_client(service).post(PROBE_URL, data={"site_id": "alpha"})

    assert response.status_code == 200
    assert "registry offline" in response.get_data(as_text=True)
    assert service.calls == []


def test_probe_reports_a_start_failure(make_client):
    service = MemoryShellStub(_snapshot())
    service.run_error = RuntimeError("worker thread refused")

    response = make_client(service).post(PROBE_URL, data={"site_id": "alpha"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "worker thread refused" in body
    assert 'data-memory-shell-state="error"' in body


def test_probe_requires_authentication(make_client):
    service = MemoryShellStub(_snapshot())

    response = make_client(service, authenticated=False).post(
        PROBE_URL, data={"site_id": "alpha"}
    )

    assert response.status_code in (301, 302, 401, 403)
    assert service.calls == []


def test_panel_requires_authentication(make_client):
    service = MemoryShellStub(_snapshot())

    response = make_client(service, authenticated=False).get(PANEL_URL)

    assert response.status_code in (301, 302, 401, 403)


# ── CSRF: the panel's POST must carry what the shell ships ──────────────────


@pytest.fixture(scope="module")
def _csrf_app():
    """A second app with CSRF protection left on."""
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app


def _csrf_client(monkeypatch, _csrf_app, service):
    from anteumbra.interfaces.web.blueprints import memory_shell_bp as module

    runtime = type("Runtime", (), {})()
    runtime.memory_shell = service
    monkeypatch.setattr(module, "get_runtime", lambda: runtime)

    client = _csrf_app.test_client()
    with client.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    return client


def _shell_csrf_token(client) -> str:
    body = client.get(
        "/admin/memory-shell", headers={"Sec-Fetch-Dest": "document"}
    ).get_data(as_text=True)
    match = re.search(r'name="csrf-token" content="([^"]+)"', body)
    return match.group(1) if match else ""


def test_probe_accepts_the_header_the_front_end_helper_sends(monkeypatch, _csrf_app):
    """app.js adds ``X-CSRFToken`` to every htmx request; hx-post must work."""
    service = MemoryShellStub(_snapshot())
    client = _csrf_client(monkeypatch, _csrf_app, service)
    token = _shell_csrf_token(client)
    assert token, "the shell rendered without a CSRF token"

    response = client.post(PROBE_URL, data={"site_id": "alpha"}, headers={"X-CSRFToken": token})

    assert response.status_code == 200
    assert [call["site_id"] for call in service.calls] == ["alpha"]


def test_probe_without_a_csrf_token_is_rejected(monkeypatch, _csrf_app):
    service = MemoryShellStub(_snapshot())
    client = _csrf_client(monkeypatch, _csrf_app, service)

    response = client.post(PROBE_URL, data={"site_id": "alpha"})

    assert response.status_code == 400
    assert service.calls == []
