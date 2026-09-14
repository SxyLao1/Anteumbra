# -*- coding: utf-8 -*-
"""Forensics (取证) and 处置 (remediation) surfaces: routes and the dialog contract.

The probe service is a runtime attribute that may be absent, and the real one
talks to a live container, so these tests drive the blueprint with a stub
service.  What is pinned down here is the contract the frontend relies on:

* which POST body produces which response (the three button flow);
* that a component without forensics is never removed by a request that did not
  acknowledge that;
* that a refusal, a failure and a missing store each have their own readable
  state instead of a traceback or a silent no-op.
"""

from __future__ import annotations

import os

import pytest

PANEL_URL = "/admin/memory-shell/panel"
FORENSICS_PAGE = "/admin/memory-shell/forensics"
FORENSICS_PANEL = "/admin/memory-shell/forensics/panel"
FORENSICS_RUN = "/admin/memory-shell/forensics/run"
FORENSICS_MANIFEST = "/admin/memory-shell/forensics/manifest"
FORENSICS_DOWNLOAD = "/admin/memory-shell/forensics/download"
CONFIRM_URL = "/admin/memory-shell/remediate/confirm"
REMEDIATE_URL = "/admin/memory-shell/remediate"


# ── stub service ────────────────────────────────────────────────────────────


def _run(**overrides):
    run = {
        "artifact_id": "20260914T101530Z-filter-evilfilter",
        "site_id": "alpha",
        "site_name": "Alpha",
        "created_at": 1_757_840_130.0,
        "created_at_iso": "2026-09-14T10:15:30Z",
        "trigger": "manual",
        "triggered_by": "admin",
        "kind": "filter",
        "name": "evilFilter",
        "class_name": "com.evil.Filter",
        "on_disk": False,
        "directory": "alpha/20260914T101530Z-filter-evilfilter",
        "manifest_file": "manifest.json",
        "class_bytes_available": False,
        "class_bytes_file": "",
        "class_bytes_unavailable_reason": "class_defined_at_runtime_without_bytecode_resource",
        "heap": {"path": "/data/forensics/alpha/x/heap.hprof", "bytes": 4096, "sha256": "ab" * 32},
        "heap_error": "",
        "report_error": "",
        "files": [
            {"name": "manifest.json", "bytes": 812, "sha256": "cd" * 32, "sha256_source": "computed"},
            {"name": "heap.hprof", "bytes": 4096, "sha256": "ef" * 32, "sha256_source": "computed"},
        ],
        "bytes": 4908,
        "remediations": [],
    }
    run.update(overrides)
    return run


def _forensics_snapshot(**overrides):
    snapshot = {
        "available": True,
        "store_error": "",
        "root": "/data/forensics",
        "enabled": True,
        "heap_dump_enabled": True,
        "history": 200,
        "max_dump_mb": 2048,
        "timeout_seconds": 300,
        "running": [],
        "runs": [],
        "latest": {},
        "latest_remediation": {},
    }
    snapshot.update(overrides)
    return snapshot


def _memory_shell_snapshot():
    entry = {
        "kind": "filter",
        "name": "evilFilter",
        "urls": ["/*"],
        "class_name": "com.evil.Filter",
        "class_loader": "WebappClassLoader",
        "resource": None,
        "code_source": None,
        "suspect": True,
        "reasons": ["class_not_on_disk"],
        "on_disk": False,
    }
    outcome = {
        "site_id": "alpha",
        "site_name": "Alpha",
        "finished_at": 1_757_840_000.0,
        "duration_ms": 900,
        "ok": True,
        "failure": None,
        "cleanup_ok": True,
        "cleanup_error": None,
        "trigger": "manual",
        "triggered_by": "admin",
        "suspect_count": 1,
        "report": {
            "site_id": "alpha",
            "url": "http://127.0.0.1:8081/mb-x/p.jsp",
            "fetched_at": 1_757_840_000.0,
            "probe_version": "1.1.0",
            "context_path": "/alpha",
            "container": ["Apache Tomcat/9.0.85"],
            "error": None,
            "duration_ms": 900,
            "raw_bytes": 4096,
            "counts": {"filter": 1},
            "entries": [entry],
        },
    }
    return {
        "enabled": True,
        "auto_probe": True,
        "cooldown_seconds": 300.0,
        "http_timeout_seconds": 8.0,
        "trigger_extensions": [".jsp"],
        "sites": [
            {
                "site_id": "alpha",
                "name": "Alpha",
                "root": "E:/www/alpha",
                "base_url": "http://127.0.0.1:8081",
                "port": 8081,
                "cooldown_remaining": 0.0,
            }
        ],
        "latest": {"alpha": outcome},
        "history": [outcome],
        "running": [],
        "runs": 1,
        "failures": 0,
    }


def _removed(**overrides):
    outcome = {
        "action": "kill",
        "site_id": "alpha",
        "site_name": "Alpha",
        "kind": "filter",
        "name": "evilFilter",
        "component": "filter:evilFilter",
        "expect_class": "com.evil.Filter",
        "ok": True,
        "removed": True,
        "refused": False,
        "reason": "",
        "failure": None,
        "cleanup_ok": True,
        "cleanup_error": None,
        "force": False,
        "acknowledge_no_forensics": False,
        "after_component": {},
        "after_count": 0,
    }
    outcome.update(overrides)
    return outcome


class MemoryShellStub:
    """Stand-in for ``MemoryShellService`` that records what the route asks for."""

    def __init__(self, *, forensics=None, memory_shell=None, remediate_result=None, file_path=None):
        self._forensics = forensics if forensics is not None else _forensics_snapshot()
        self._memory_shell = memory_shell if memory_shell is not None else _memory_shell_snapshot()
        self._remediate_result = remediate_result
        self._file_path = file_path
        self.calls: list[dict] = []

    def snapshot(self):
        if isinstance(self._memory_shell, Exception):
            raise self._memory_shell
        return self._memory_shell

    def forensics_snapshot(self):
        if isinstance(self._forensics, Exception):
            raise self._forensics
        return self._forensics

    def run_probe(self, site_id, **kwargs):
        self.calls.append({"method": "run_probe", "site_id": site_id, **kwargs})
        return None

    def run_forensics(self, site_id, kind, name, **kwargs):
        self.calls.append(
            {"method": "run_forensics", "site_id": site_id, "kind": kind, "name": name, **kwargs}
        )
        return None

    def remediate(self, site_id, kind, name, **kwargs):
        self.calls.append(
            {"method": "remediate", "site_id": site_id, "kind": kind, "name": name, **kwargs}
        )
        if isinstance(self._remediate_result, Exception):
            raise self._remediate_result
        return self._remediate_result if self._remediate_result is not None else _removed()

    def forensics_manifest(self, artifact_id):
        if artifact_id != "20260914T101530Z-filter-evilfilter":
            return None
        return {
            "artifact_id": artifact_id,
            "kind": "filter",
            "name": "evilFilter",
            "class_name": "com.evil.Filter",
            "class_loader_identity": "WebappClassLoader@1a2b@@7ff",
            "on_disk": False,
            "methods": ["doFilter(ServletRequest,ServletResponse,FilterChain)->void"],
            "fields": ["whatever:java.lang.String"],
            "container": ["server_info:Apache Tomcat/9.0.85"],
            "jvm_input_arguments": ["-Xmx512m"],
            "attach_self": "unset",
            "class_bytes_available": False,
            "class_bytes_unavailable_reason": "class_defined_at_runtime_without_bytecode_resource",
            "heap": None,
            "heap_error": "heap_dump_failed: java.io.IOException: no space left on device",
        }

    def forensics_file_path(self, artifact_id, filename):
        if filename == "manifest.json" and artifact_id == "20260914T101530Z-filter-evilfilter":
            return self._file_path
        return None


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


# ── the forensics tab ───────────────────────────────────────────────────────


def test_forensics_page_loads_its_panel_and_dialog_container(make_client):
    body = make_client(MemoryShellStub()).get(FORENSICS_PAGE, headers={"HX-Request": "true"})
    text = body.get_data(as_text=True)

    assert body.status_code == 200
    assert 'id="memory-shell-forensics-view"' in text
    assert f'hx-get="{FORENSICS_PANEL}"' in text
    assert 'hx-trigger="load"' in text
    assert 'id="memory-shell-dialog"' in text


def test_forensics_panel_lists_artifacts_with_files_and_hashes(make_client):
    service = MemoryShellStub(forensics=_forensics_snapshot(runs=[_run()]))

    body = make_client(service).get(FORENSICS_PANEL).get_data(as_text=True)

    assert 'data-forensics-state="ready"' in body
    assert "20260914T101530Z-filter-evilfilter" in body
    assert "evilFilter" in body
    assert "com.evil.Filter" in body
    assert "No class bytes" in body, "the unavailable class bytes must be visible"
    assert "Heap" in body and "4.0 KB" in body
    assert f"{FORENSICS_DOWNLOAD}/20260914T101530Z-filter-evilfilter/manifest.json" in body
    assert f"{FORENSICS_MANIFEST}/20260914T101530Z-filter-evilfilter" in body
    assert "Remediate" in body
    assert "Traceback" not in body


def test_forensics_panel_marks_a_remediated_component(make_client):
    run = _run(
        remediations=[
            {
                "remediated_at": 1_757_841_000.0,
                "remediated_at_iso": "2026-09-14T10:30:00Z",
                "result": "removed",
                "removed": True,
                "reason": "",
                "operator": "admin",
            }
        ]
    )

    body = make_client(MemoryShellStub(forensics=_forensics_snapshot(runs=[run]))).get(
        FORENSICS_PANEL
    ).get_data(as_text=True)

    assert "Removed" in body


def test_forensics_panel_polls_only_while_a_run_is_running(make_client):
    idle = MemoryShellStub(forensics=_forensics_snapshot())
    running = MemoryShellStub(forensics=_forensics_snapshot(running=["alpha"]))

    idle_body = make_client(idle).get(FORENSICS_PANEL).get_data(as_text=True)
    running_body = make_client(running).get(FORENSICS_PANEL).get_data(as_text=True)

    assert 'hx-trigger="every 3s"' not in idle_body
    assert 'hx-trigger="every 3s"' in running_body
    assert "Forensics running for" in running_body


def test_forensics_panel_reports_a_missing_store(make_client):
    service = MemoryShellStub(
        forensics=_forensics_snapshot(available=False, store_error="forensics_store_unavailable")
    )

    body = make_client(service).get(FORENSICS_PANEL).get_data(as_text=True)

    assert "Forensics unavailable" in body
    assert "forensics_store_unavailable" in body
    assert "Traceback" not in body


def test_forensics_panel_reports_a_broken_service(make_client):
    service = MemoryShellStub(forensics=RuntimeError("index exploded"))

    body = make_client(service).get(FORENSICS_PANEL).get_data(as_text=True)

    assert 'data-forensics-state="error"' in body
    assert "index exploded" in body


def test_forensics_panel_without_the_service_names_the_plugin(make_client):
    body = make_client(None).get(FORENSICS_PANEL).get_data(as_text=True)

    assert 'data-forensics-state="unavailable"' in body
    assert "memory_shell_probe" in body


def test_forensics_panel_offers_a_run_form_for_the_chosen_component(make_client):
    service = MemoryShellStub(forensics=_forensics_snapshot())

    body = make_client(service).get(
        f"{FORENSICS_PANEL}?site_id=alpha&kind=filter&name=evilFilter"
    ).get_data(as_text=True)

    assert f'hx-post="{FORENSICS_RUN}"' in body
    assert 'name="kind" value="filter"' in body
    assert 'name="name" value="evilFilter"' in body
    assert "Run forensics for this component" in body


def test_forensics_panel_explains_how_to_choose_a_component(make_client):
    body = make_client(MemoryShellStub()).get(FORENSICS_PANEL).get_data(as_text=True)

    assert "Run forensics for this component" not in body
    assert "Open forensics from a finding on the detection tab" in body


# ── manifest and download routes ────────────────────────────────────────────


def test_manifest_route_renders_the_stored_manifest(make_client):
    artifact = "20260914T101530Z-filter-evilfilter"

    response = make_client(MemoryShellStub()).get(f"{FORENSICS_MANIFEST}/{artifact}")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-manifest-state="ready"' in body
    assert "com.evil.Filter" in body
    assert "doFilter" in body
    assert "whatever:java.lang.String" in body
    assert "class_defined_at_runtime_without_bytecode_resource" in body
    assert "no space left on device" in body, "the heap failure is part of the record"
    assert "Raw manifest.json" in body
    assert "Traceback" not in body


def test_manifest_route_reports_a_missing_artifact(make_client):
    response = make_client(MemoryShellStub()).get(f"{FORENSICS_MANIFEST}/nope")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-manifest-state="missing"' in body
    assert "No stored manifest exists for this artifact" in body


def test_download_serves_only_indexed_files(make_client, tmp_path):
    stored = tmp_path / "manifest.json"
    stored.write_text('{"kind": "filter"}', encoding="utf-8")
    artifact = "20260914T101530Z-filter-evilfilter"
    service = MemoryShellStub(file_path=stored)
    client = make_client(service)

    ok = client.get(f"{FORENSICS_DOWNLOAD}/{artifact}/manifest.json")
    assert ok.status_code == 200
    assert ok.get_data() == b'{"kind": "filter"}'
    assert "attachment" in ok.headers.get("Content-Disposition", "")

    assert client.get(f"{FORENSICS_DOWNLOAD}/{artifact}/heap.hprof").status_code == 404
    assert client.get(f"{FORENSICS_DOWNLOAD}/other/manifest.json").status_code == 404


def test_download_requires_authentication(make_client, tmp_path):
    stored = tmp_path / "manifest.json"
    stored.write_text("{}", encoding="utf-8")
    service = MemoryShellStub(file_path=stored)
    client = make_client(service, authenticated=False)

    response = client.get(
        f"{FORENSICS_DOWNLOAD}/20260914T101530Z-filter-evilfilter/manifest.json",
        follow_redirects=False,
    )

    assert response.status_code in (301, 302, 401, 403)


# ── starting a forensics run ────────────────────────────────────────────────


def test_forensics_run_starts_a_background_dump(make_client):
    service = MemoryShellStub()

    response = make_client(service).post(
        FORENSICS_RUN,
        data={"site_id": "alpha", "kind": "filter", "name": "evilFilter", "heap_live": "1"},
    )

    assert response.status_code == 200
    assert service.calls == [
        {
            "method": "run_forensics",
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "trigger": "manual",
            "triggered_by": "admin",
            "background": True,
            "heap_live": True,
        }
    ]
    body = response.get_data(as_text=True)
    assert 'hx-trigger="every 3s"' in body, "the panel polls so the result shows up on its own"


def test_forensics_run_needs_a_component(make_client):
    service = MemoryShellStub()

    body = make_client(service).post(FORENSICS_RUN, data={"site_id": "alpha"}).get_data(as_text=True)

    assert "before running forensics" in body
    assert service.calls == []


def test_forensics_run_needs_a_site(make_client):
    service = MemoryShellStub()

    body = make_client(service).post(FORENSICS_RUN, data={"kind": "filter", "name": "x"}).get_data(
        as_text=True
    )

    assert "No site was selected for forensics." in body
    assert service.calls == []


# ── the 处置 flow: three buttons, decided by the server ──────────────────────


def test_confirm_dialog_is_a_plain_confirmation_when_forensics_exist(make_client):
    service = MemoryShellStub(forensics=_forensics_snapshot(runs=[_run()]))

    body = make_client(service).get(
        f"{CONFIRM_URL}?site_id=alpha&kind=filter&name=evilFilter&expect_class=com.evil.Filter"
    ).get_data(as_text=True)

    assert 'data-remediate-dialog="confirm"' in body
    assert "removes the component from the container memory and cannot be undone" in body
    assert 'name="acknowledge_no_forensics" value="0"' in body
    assert f'hx-post="{REMEDIATE_URL}"' in body
    assert "Confirm remediation" in body
    assert "Remediate now" not in body, "no warning buttons when the evidence exists"
    assert service.calls == []


def test_confirm_dialog_warns_with_three_buttons_when_forensics_are_missing(make_client):
    service = MemoryShellStub()

    body = make_client(service).get(
        f"{CONFIRM_URL}?site_id=alpha&kind=filter&name=evilFilter&expect_class=com.evil.Filter"
    ).get_data(as_text=True)

    assert 'data-remediate-dialog="no-forensics"' in body
    assert "There is no forensics artifact for this component." in body
    # 立即处置: the acknowledging POST
    assert 'name="acknowledge_no_forensics" value="1"' in body
    assert f'hx-post="{REMEDIATE_URL}"' in body
    assert "Remediate now" in body
    # 前往取证: the forensics tab for this component
    assert "/admin/memory-shell/forensics?site_id=alpha&amp;kind=filter&amp;name=evilFilter" in body
    assert "Go to forensics" in body
    # 取消: the registered close action
    assert 'data-action="core.modal-hide"' in body
    assert "Cancel" in body
    assert service.calls == []


def test_post_without_acknowledgement_is_answered_with_the_warning_and_changes_nothing(make_client):
    """A refusal can never be a silent no-op: the operator gets the dialog back."""
    service = MemoryShellStub(
        remediate_result=_removed(
            ok=False,
            removed=False,
            refused=True,
            reason="forensics_required",
            acknowledge_no_forensics=False,
        )
    )

    response = make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "0",
        },
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-remediate-dialog="no-forensics"' in body
    assert "Remediate now" in body
    assert service.calls[0]["acknowledge_no_forensics"] is False
    assert service.calls[0]["expect_class"] == "com.evil.Filter"


def test_post_with_acknowledgement_removes_and_refreshes_the_panels(make_client):
    service = MemoryShellStub()

    response = make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "1",
        },
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-remediate-result="removed"' in body
    assert "Removed from the container memory." in body
    assert response.headers.get("HX-Trigger") == "memory-shell-refresh"
    assert service.calls == [
        {
            "method": "remediate",
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "acknowledge_no_forensics": True,
            "force": False,
            "expect_class": "com.evil.Filter",
            "trigger": "manual",
            "triggered_by": "admin",
        }
    ]


def test_post_passes_force_through(make_client):
    service = MemoryShellStub()

    make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "WsFilter",
            "expect_class": "org.apache.tomcat.websocket.server.WsFilter",
            "acknowledge_no_forensics": "1",
            "force": "1",
        },
    )

    assert service.calls[0]["force"] is True


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"kind": "filter", "name": "x"}, "No site was selected for remediation."),
        ({"site_id": "alpha", "name": "x"}, "No component kind was selected for remediation."),
        ({"site_id": "alpha", "kind": "filter"}, "No component was selected for remediation."),
    ],
)
def test_post_without_a_component_never_reaches_the_service(make_client, payload, expected):
    service = MemoryShellStub()

    body = make_client(service).post(REMEDIATE_URL, data=payload).get_data(as_text=True)

    assert expected in body
    assert 'data-remediate-result="refused"' in body
    assert service.calls == []


def test_post_reports_a_refusal_from_the_probe(make_client):
    service = MemoryShellStub(
        remediate_result=_removed(
            ok=False,
            removed=False,
            refused=True,
            reason="class_name_mismatch: expected com.evil.Filter but found com.other.Thing",
        )
    )

    body = make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "1",
        },
    ).get_data(as_text=True)

    assert 'data-remediate-result="refused"' in body
    assert "Refused; nothing was changed." in body
    assert "class_name_mismatch" in body


def test_post_reports_a_still_registered_component(make_client):
    service = MemoryShellStub(
        remediate_result=_removed(
            ok=False,
            removed=False,
            refused=False,
            reason="remove_filter_map_failed: method_not_found:removeFilterMap",
            after_component={"kind": "filter", "name": "evilFilter", "class_name": "com.evil.Filter"},
            after_count=1,
        )
    )

    body = make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "1",
        },
    ).get_data(as_text=True)

    assert 'data-remediate-result="not-removed"' in body
    assert "The component is still registered." in body
    assert "remove_filter_map_failed" in body


def test_post_reports_a_failed_request(make_client):
    service = MemoryShellStub(remediate_result=_removed(ok=False, removed=False, failure="ProbeError: probe HTTP 500"))

    body = make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "1",
        },
    ).get_data(as_text=True)

    assert 'data-remediate-result="failed"' in body
    assert "The request failed." in body


def test_post_reports_an_exception_instead_of_raising(make_client):
    service = MemoryShellStub(remediate_result=RuntimeError("service exploded"))

    response = make_client(service).post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "1",
        },
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'data-remediate-dialog="error"' in body
    assert "service exploded" in body
    assert "Traceback" not in body


def test_post_without_the_service_explains_why(make_client):
    body = make_client(None).post(
        REMEDIATE_URL,
        data={"site_id": "alpha", "kind": "filter", "name": "evilFilter"},
    ).get_data(as_text=True)

    assert 'data-remediate-dialog="error"' in body
    assert "not available" in body


def test_detection_panel_offers_forensics_and_remediation_for_suspects(make_client):
    body = make_client(MemoryShellStub()).get(PANEL_URL).get_data(as_text=True)

    assert f'hx-get="{CONFIRM_URL}?site_id=alpha&amp;kind=filter&amp;name=evilFilter' in body
    assert 'href="/admin/memory-shell/forensics?site_id=alpha&amp;kind=filter&amp;name=evilFilter"' in body
    assert 'hx-target="#memory-shell-dialog"' in body
    assert "memory-shell-refresh from:body" in body


# ── authentication and CSRF ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "method,url",
    [
        ("get", FORENSICS_PAGE),
        ("get", FORENSICS_PANEL),
        ("get", f"{FORENSICS_MANIFEST}/x"),
        ("get", CONFIRM_URL),
        ("post", FORENSICS_RUN),
        ("post", REMEDIATE_URL),
    ],
)
def test_new_routes_require_authentication(make_client, method, url):
    service = MemoryShellStub()
    client = make_client(service, authenticated=False)

    response = getattr(client, method)(url, data={})

    assert response.status_code in (301, 302, 401, 403)
    assert service.calls == []


@pytest.fixture(scope="module")
def _csrf_app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app


def _csrf_client(monkeypatch, _csrf_app, service):
    import re

    from anteumbra.interfaces.web.blueprints import memory_shell_bp as module

    runtime = type("Runtime", (), {})()
    runtime.memory_shell = service
    monkeypatch.setattr(module, "get_runtime", lambda: runtime)

    client = _csrf_app.test_client()
    with client.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    body = client.get(FORENSICS_PAGE, headers={"Sec-Fetch-Dest": "document"}).get_data(as_text=True)
    match = re.search(r'name="csrf-token" content="([^"]+)"', body)
    return client, (match.group(1) if match else "")


def test_remediate_accepts_the_header_app_js_sends(monkeypatch, _csrf_app):
    service = MemoryShellStub()
    client, token = _csrf_client(monkeypatch, _csrf_app, service)
    assert token, "the shell rendered without a CSRF token"

    response = client.post(
        REMEDIATE_URL,
        data={
            "site_id": "alpha",
            "kind": "filter",
            "name": "evilFilter",
            "expect_class": "com.evil.Filter",
            "acknowledge_no_forensics": "1",
        },
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 200
    assert [call["method"] for call in service.calls] == ["remediate"]


def test_remediate_without_a_csrf_token_is_rejected(monkeypatch, _csrf_app):
    service = MemoryShellStub()
    client, _ = _csrf_client(monkeypatch, _csrf_app, service)

    response = client.post(
        REMEDIATE_URL,
        data={"site_id": "alpha", "kind": "filter", "name": "evilFilter"},
    )

    assert response.status_code == 400
    assert service.calls == []
