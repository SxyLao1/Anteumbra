# -*- coding: utf-8 -*-
"""Forensics (取证) and remediation (处置) for the memory-shell probe.

Everything here runs against real objects and ``tmp_path``: the real probe
deployer writes and removes a real file, the real forensics store writes a real
index, and only the HTTP round trip is faked.  No container, no network, no live
Anteumbra instance.

The behaviour these tests pin down is mostly about honesty:

* a class defined at runtime has no bytecode resource, and the reason string has
  to reach the operator instead of an empty field;
* a failed heap dump must not cost us the manifest;
* the index is written atomically and rotates, and an unreadable index is
  reported rather than silently emptied;
* remediation refuses without a forensics artifact, refuses when the class name
  moved under us, and never reads anything but the component it was asked about.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from anteumbra.domain.memory_shell import (
    ACTION_DUMP,
    ACTION_KILL,
    ACTION_PROBE,
    CLASS_BYTES_RUNTIME_DEFINED,
    PROBE_MARKER,
    REASON_FORENSICS_DISABLED,
    REASON_FORENSICS_REQUIRED,
    REASON_NO_RECORDED_CLASS,
    ForensicsManifest,
    HeapDumpInfo,
    ProbeError,
    SiteTarget,
    manifest_from_payload,
)
from anteumbra.infrastructure.internal_artifacts import InMemoryInternalArtifactRegistry
from anteumbra.infrastructure.memory_shell import (
    MemoryShellForensicsStore,
    MemoryShellProbeDeployer,
)
from anteumbra.infrastructure.memory_shell.probe_deployer import load_probe_template

LOGGER = logging.getLogger("test.memory_shell_forensics")
JSP_TEMPLATE = load_probe_template()


# ── fakes ───────────────────────────────────────────────────────────


class FakeProbeServer:
    """A probe that answers like the JSP, and records every request.

    ``dump`` and ``kill`` are callables taking the request parameters and
    returning the JSON body; the default ones behave like a component that was
    found and removed.
    """

    def __init__(self, *, dump=None, kill=None, probe=None, write_heap=True, error=None) -> None:
        self.calls: list[dict] = []
        self._dump = dump or default_dump
        self._kill = kill or default_kill
        self._probe = probe or default_probe
        self._write_heap = write_heap
        self._error = error

    def __call__(self, url: str, timeout: float) -> bytes:
        params = {key: value[0] for key, value in parse_qs(urlparse(url).query).items()}
        action = params.get("action", ACTION_PROBE)
        self.calls.append({"action": action, "params": params, "url": url, "timeout": timeout})
        if self._error is not None:
            raise self._error
        if action == ACTION_DUMP:
            body = self._dump(params, self._write_heap)
        elif action == ACTION_KILL:
            body = self._kill(params)
        else:
            body = self._probe(params)
        return json.dumps(body).encode("utf-8")

    @property
    def actions(self) -> list[str]:
        return [call["action"] for call in self.calls]

    def last(self, action: str) -> dict:
        for call in reversed(self.calls):
            if call["action"] == action:
                return call
        raise AssertionError(f"no {action} request was made")


def _envelope(action: str, *, entries=(), error=None, container=("Apache Tomcat/9.0.85",)):
    return {
        "probe": PROBE_MARKER,
        "version": "1.1.0",
        "action": action,
        "context_path": "/dshlab",
        "container": list(container),
        "error": error,
        "entry_count": len(entries),
        "duration_ms": 3,
        "entries": list(entries),
    }


def _entry(kind="filter", name="evilFilter", class_name="com.evil.Filter", suspect=True):
    return {
        "type": kind,
        "name": name,
        "urls": ["/*"],
        "class": class_name,
        "class_loader": "org.apache.catalina.loader.WebappClassLoader",
        "resource": None,
        "code_source": None,
        "suspect": suspect,
        "reasons": ["class_not_on_disk"] if suspect else [],
    }


def default_probe(_params) -> dict:
    return _envelope(ACTION_PROBE, entries=[_entry()])


def _manifest_payload(**overrides) -> dict:
    manifest = {
        "kind": "filter",
        "name": "evilFilter",
        "urls": ["/*"],
        "class_name": "com.evil.Filter",
        "class_loader": "org.apache.catalina.loader.WebappClassLoader",
        "class_loader_identity": "WebappClassLoader@abc@@1f2e3d",
        "code_source": None,
        "resource": None,
        "on_disk": False,
        "on_disk_path": None,
        "methods": ["doFilter(ServletRequest,ServletResponse,FilterChain)->void"],
        "fields": ["secret:java.lang.String"],
        "protection_domain": "ProtectionDomain  (null)",
        "container": ["context_class:org.apache.catalina.core.StandardContext"],
        "context_path": "/dshlab",
        "probe_url": "http://127.0.0.1:8081/mb-x/p.jsp",
        "jvm_input_arguments": ["-Xmx512m"],
        "attach_self": "unset",
        "captured_at": 1_700_000_000_000,
    }
    manifest.update(overrides)
    return manifest


def default_dump(params, write_heap=True) -> dict:
    body = _envelope(ACTION_DUMP, entries=[_entry()])
    body.update(
        {
            "removed": False,
            "refused": False,
            "reason": None,
            "kind": "filter",
            "name": "evilFilter",
            "class_name": "com.evil.Filter",
            "manifest": _manifest_payload(),
            "class_bytes_b64": None,
            "class_bytes_len": 0,
            "class_bytes_sha256": None,
            "class_bytes_source": None,
            "class_bytes_unavailable_reason": CLASS_BYTES_RUNTIME_DEFINED,
            "heap": None,
            "heap_error": "",
        }
    )
    heap_path = params.get("heap_path")
    if heap_path:
        if write_heap:
            payload = b"\xca\xfe\xba\xbe" * 8
            Path(heap_path).write_bytes(payload)
            import hashlib

            body["heap"] = {
                "heap_requested": True,
                "heap_path": heap_path,
                "heap_bytes": len(payload),
                "heap_sha256": hashlib.sha256(payload).hexdigest(),
                "heap_live": params.get("heap_live") == "1",
                "heap_error": None,
            }
        else:
            body["heap"] = {
                "heap_requested": True,
                "heap_path": heap_path,
                "heap_bytes": 0,
                "heap_sha256": None,
                "heap_live": False,
                "heap_error": "heap_dump_failed: java.io.IOException: no space left on device",
            }
            body["heap_error"] = (
                "heap_dump_failed: java.io.IOException: no space left on device"
            )
    return body


def default_kill(params) -> dict:
    body = _envelope(ACTION_KILL, entries=[])
    body.update(
        {
            "removed": True,
            "refused": False,
            "reason": None,
            "kind": params.get("kind"),
            "name": params.get("name"),
            "expect_class": params.get("expect_class"),
            "force": params.get("force") == "1",
            "removal_error": None,
            "still_present": False,
            "before_component": {
                "kind": params.get("kind"),
                "name": params.get("name"),
                "class_name": params.get("expect_class"),
                "urls": ["/*"],
            },
            "after_component": None,
        }
    )
    return body


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def publish(self, event_type, source, payload):
        self.events.append((event_type, source, dict(payload)))


def _provider(config: dict, site_root: Path, *, site_id: str = "site-a", paths: dict | None = None):
    website = SimpleNamespace(site_id=site_id, name="Site A", path=site_root, port=8081)
    payload = {"plugins": {"memory_shell_probe": config}, "paths": dict(paths or {})}
    return SimpleNamespace(get=lambda: payload, get_enabled_websites=lambda: [website])


def build_service(
    tmp_path: Path,
    *,
    server: FakeProbeServer | None = None,
    config: dict | None = None,
    store_root: Path | None = None,
    paths: dict | None = None,
    with_store: bool = True,
    **kwargs,
):
    """A real service, real deployer, real store; only HTTP is faked."""
    from anteumbra.application.memory_shell_service import MemoryShellService

    server = server or FakeProbeServer()
    artifacts = InMemoryInternalArtifactRegistry()
    deployer = MemoryShellProbeDeployer(
        artifacts=artifacts, reader=server, template_loader=lambda: JSP_TEMPLATE, log=LOGGER
    )
    service_kwargs = {}
    if with_store:
        service_kwargs["forensics"] = MemoryShellForensicsStore(
            store_root or (tmp_path / "data" / "forensics"), log=LOGGER
        )
    service = MemoryShellService(
        config_provider=_provider(config or {}, tmp_path, paths=paths),
        deployer=deployer,
        artifacts=artifacts,
        clock=time.time,
        log=LOGGER,
        **service_kwargs,
        **kwargs,
    )
    return service, server, service.forensics_store


# ── the probe template ──────────────────────────────────────────────


def test_template_implements_exactly_three_token_gated_actions():
    for action in ('ACTION_PROBE = "probe"', 'ACTION_DUMP = "dump"', 'ACTION_KILL = "kill"'):
        assert action in JSP_TEMPLATE
    # the token gate is the first thing the scriptlet does, for every action
    scriptlet = JSP_TEMPLATE.split("<%\n    String probeToken", 1)[1]
    gate = scriptlet.index("PROBE_TOKEN.equals(probeToken)")
    dispatch = scriptlet.index('request.getParameter("action")')
    refused = scriptlet.index("response.setStatus(404)")
    assert gate < dispatch, "the token must be checked before the action is read"
    assert gate < refused < dispatch, "a bad token answers 404 before anything else happens"
    assert "entries" in JSP_TEMPLATE


def test_template_stays_java6_and_avoid_the_implicit_objects():
    """Tomcat 7 compiles JSPs at source level 1.6; ``config`` is an implicit object."""
    assert "<>" not in JSP_TEMPLATE
    assert "java.util.Base64" not in JSP_TEMPLATE, "that is Java 8; the probe carries its own"
    assert "Object config = " not in JSP_TEMPLATE
    assert "String config = " not in JSP_TEMPLATE
    for forbidden in ("try (", "-> {", "Stream<"):
        assert forbidden not in JSP_TEMPLATE


def test_template_documents_what_it_cannot_do():
    """The honesty rules are part of the artifact, not only of the docs."""
    assert CLASS_BYTES_RUNTIME_DEFINED in JSP_TEMPLATE
    assert "no supported way to read the bytecode" in JSP_TEMPLATE
    assert "never deletes a file" in JSP_TEMPLATE
    for reason in (
        "component_not_found",
        "class_name_mismatch",
        "class_on_disk",
        "expect_class_required",
        "unknown_kind",
        "invalid_component",
    ):
        assert reason in JSP_TEMPLATE, f"the probe never reports {reason}"


def test_template_uses_the_reference_removal_technique():
    """Same reflection calls as tools/memory-shell/java/tomcat-memshell-scanner.jsp."""
    for call in (
        "removeFilterDef",
        "removeFilterMap",
        "removeServletMapping",
        "removeChild",
        "filterDef",
        "applicationEventListenersList",
    ):
        assert call in JSP_TEMPLATE
    # both Tomcat 7 and 8 package names for the descriptor classes
    assert "org.apache.tomcat.util.descriptor.web.FilterDef" in JSP_TEMPLATE
    assert "org.apache.catalina.deploy.FilterDef" in JSP_TEMPLATE


def test_template_dump_reads_the_hotspot_diagnostic_mxbean():
    assert "com.sun.management:type=HotSpotDiagnostic" in JSP_TEMPLATE
    assert "getPlatformMBeanServer" in JSP_TEMPLATE
    assert '"dumpHeap"' in JSP_TEMPLATE
    assert "heap_error" in JSP_TEMPLATE
    # the heap dump must not be able to lose the manifest
    assert "manifest" in JSP_TEMPLATE


# ── deployer: action requests ───────────────────────────────────────


def test_action_url_keeps_the_token_and_encodes_parameters(tmp_path):
    deployer = MemoryShellProbeDeployer(
        artifacts=InMemoryInternalArtifactRegistry(),
        reader=lambda _url, _timeout: b"{}",
        template_loader=lambda: JSP_TEMPLATE,
    )
    artifact = deployer.deploy(
        SiteTarget(
            site_id="site-a",
            name="Site A",
            root=tmp_path,
            base_url="http://127.0.0.1:8081",
            port=8081,
        ),
        ttl=30,
    )
    url = deployer.action_url(
        artifact,
        action=ACTION_DUMP,
        params={"kind": "filter", "name": "a b/c", "heap_path": r"F:\data\heap.hprof"},
    )
    deployer.cleanup(artifact)

    query = parse_qs(urlparse(url).query)
    assert url.startswith(artifact.url + "&")
    assert query["t"] == [artifact.token], "the token stays first and present"
    assert query["action"] == ["dump"]
    assert query["name"] == ["a b/c"]
    assert query["heap_path"] == [r"F:\data\heap.hprof"]


def test_read_action_refuses_an_unknown_verb(tmp_path):
    deployer = MemoryShellProbeDeployer(
        artifacts=InMemoryInternalArtifactRegistry(),
        reader=lambda _url, _timeout: b"{}",
        template_loader=lambda: JSP_TEMPLATE,
    )
    artifact = deployer.deploy(
        SiteTarget(
            site_id="site-a",
            name="Site A",
            root=tmp_path,
            base_url="http://127.0.0.1:8081",
            port=8081,
        ),
        ttl=30,
    )
    try:
        with pytest.raises(ProbeError, match="unknown probe action"):
            deployer.read_action(artifact, action="rm -rf", timeout=1.0)
    finally:
        deployer.cleanup(artifact)


def test_parse_action_still_rejects_foreign_payloads(tmp_path):
    deployer = MemoryShellProbeDeployer(
        artifacts=InMemoryInternalArtifactRegistry(),
        reader=lambda _url, _timeout: b"{}",
        template_loader=lambda: JSP_TEMPLATE,
    )
    artifact = SimpleNamespace(site_id="site-a", url="http://127.0.0.1/x.jsp")
    with pytest.raises(ProbeError, match="marker"):
        deployer.parse_action(json.dumps({"probe": "other"}).encode(), artifact)


# ── manifest building ───────────────────────────────────────────────


def test_manifest_reads_every_field_the_probe_reports():
    manifest = manifest_from_payload(_manifest_payload())

    assert isinstance(manifest, ForensicsManifest)
    assert manifest.kind == "filter"
    assert manifest.class_name == "com.evil.Filter"
    assert manifest.class_loader_identity.endswith("@@1f2e3d")
    assert manifest.on_disk is False
    assert manifest.methods and "doFilter" in manifest.methods[0]
    assert manifest.fields == ("secret:java.lang.String",)
    assert manifest.container and "StandardContext" in manifest.container[0]
    assert manifest.jvm_input_arguments == ("-Xmx512m",)
    assert manifest.attach_self == "unset"
    assert manifest.as_dict()["class_loader"] == "org.apache.catalina.loader.WebappClassLoader"


def test_manifest_tolerates_garbage_and_bounds_it():
    manifest = manifest_from_payload(
        {
            "kind": "filter",
            "name": "x" * 900,
            "urls": "not-a-list",
            "methods": [f"m{i}" for i in range(2000)],
            "on_disk": "yes",
            "unknown_field": "kept as text",
        }
    )
    assert len(manifest.name) < 900, "untrusted text is bounded"
    assert manifest.urls == ()
    assert len(manifest.methods) <= 500
    assert manifest.on_disk is True
    assert manifest.extra["unknown_field"] == "kept as text"

    assert manifest_from_payload(None).as_dict()["kind"] == ""


# ── forensics runs ──────────────────────────────────────────────────

def test_forensics_stores_a_manifest_and_says_why_there_are_no_class_bytes(tmp_path):
    server = FakeProbeServer()
    # heap dumping off keeps this test about the class bytes alone; the dump has
    # its own tests below.
    service, _, store = build_service(
        tmp_path, server=server, config={"heap_dump_enabled": False}
    )

    outcome = service.run_forensics("site-a", "filter", "evilFilter", triggered_by="test")

    assert outcome is not None and outcome.ok
    assert server.actions == [ACTION_DUMP]
    request = server.last(ACTION_DUMP)
    assert request["params"]["kind"] == "filter"
    assert request["params"]["name"] == "evilFilter"
    # a runtime-defined class has no bytecode resource: the reason is data
    assert outcome.has_class_bytes is False
    assert outcome.class_bytes_unavailable_reason == CLASS_BYTES_RUNTIME_DEFINED
    assert outcome.manifest is not None and outcome.manifest.class_loader_identity

    entry = store.get(outcome.artifact_id)
    assert entry is not None
    names = {item["name"] for item in entry["files"]}
    assert names == {"manifest.json"}, "no class file may be written without bytes"
    assert entry["class_bytes_available"] is False
    assert entry["class_bytes_unavailable_reason"] == CLASS_BYTES_RUNTIME_DEFINED
    stored = json.loads(
        (store.root / str(entry["directory"]) / "manifest.json").read_text(encoding="utf-8")
    )
    assert stored["class_name"] == "com.evil.Filter"
    assert stored["class_bytes_unavailable_reason"] == CLASS_BYTES_RUNTIME_DEFINED
    # every indexed file carries a size and a hash
    for item in entry["files"]:
        assert item["bytes"] > 0
        assert len(item["sha256"]) == 64
        assert item["sha256_source"] == "computed"


def test_class_bytes_are_written_when_the_class_really_resolves(tmp_path):
    payload = b"\xca\xfe\xba\xbe" + b"real-class-bytes"

    def dump(_params, _write_heap=True):
        body = default_dump(_params)
        import base64

        body["class_bytes_b64"] = base64.b64encode(payload).decode("ascii")
        body["class_bytes_len"] = len(payload)
        body["class_bytes_source"] = "jar:file:/opt/tomcat/webapps/a/WEB-INF/lib/x.jar!/com/evil/Filter.class"
        body["class_bytes_unavailable_reason"] = None
        body["manifest"] = _manifest_payload(on_disk=True, resource="file:/x.jar")
        return body

    service, _, store = build_service(
        tmp_path, server=FakeProbeServer(dump=dump), config={"heap_dump_enabled": False}
    )
    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.ok and outcome.has_class_bytes
    assert outcome.class_bytes_bytes == len(payload)
    entry = store.get(outcome.artifact_id)
    class_file = store.root / str(entry["directory"]) / "class-Filter.class"
    assert class_file.read_bytes() == payload
    assert {item["name"] for item in entry["files"]} == {"manifest.json", "class-Filter.class"}


def test_undecodable_class_bytes_are_reported_not_trusted(tmp_path):
    def dump(_params, _write_heap=True):
        body = default_dump(_params)
        body["class_bytes_b64"] = "not base64 !!!"
        body["class_bytes_unavailable_reason"] = None
        return body

    service, _, store = build_service(
        tmp_path, server=FakeProbeServer(dump=dump), config={"heap_dump_enabled": False}
    )
    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.has_class_bytes is False
    assert "class_bytes_undecodable" in outcome.class_bytes_unavailable_reason
    entry = store.get(outcome.artifact_id)
    assert {item["name"] for item in entry["files"]} == {"manifest.json"}


def test_heap_dump_is_requested_into_the_artifact_directory(tmp_path):
    server = FakeProbeServer()
    service, _, store = build_service(tmp_path, server=server)

    outcome = service.run_forensics("site-a", "filter", "evilFilter", heap_live=True)

    requested = server.last(ACTION_DUMP)["params"]
    assert requested["heap_live"] == "1"
    assert requested["heap_max_mb"] == "2048"
    heap_path = Path(requested["heap_path"])
    assert heap_path.is_absolute()
    assert heap_path.name == "heap.hprof"
    assert outcome.heap is not None and outcome.heap.ok
    assert outcome.heap.sha256 and outcome.heap.bytes > 0
    entry = store.get(outcome.artifact_id)
    assert entry["heap"]["bytes"] == outcome.heap.bytes
    heap_file = store.root / str(entry["directory"]) / "heap.hprof"
    assert heap_file.is_file(), "the artifact directory holds the dump the JVM wrote"


def test_a_failed_heap_dump_never_loses_the_manifest(tmp_path):
    server = FakeProbeServer(write_heap=False)
    service, _, store = build_service(tmp_path, server=server)

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.ok, "the dump failed, the forensics run did not"
    assert "no space left on device" in outcome.heap_error
    assert outcome.manifest is not None
    assert outcome.heap is not None and not outcome.heap.ok
    entry = store.get(outcome.artifact_id)
    assert "no space left on device" in entry["heap_error"]
    assert "manifest.json" in {item["name"] for item in entry["files"]}
    assert entry["manifest_file"] == "manifest.json"


def test_heap_dump_can_be_switched_off(tmp_path):
    server = FakeProbeServer()
    service, _, _ = build_service(
        tmp_path, server=server, config={"heap_dump_enabled": False}
    )

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert "heap_path" not in server.last(ACTION_DUMP)["params"]
    assert outcome.heap is None
    assert outcome.heap_skipped_reason == "heap_dump_disabled"
    assert outcome.ok, "a disabled dump is not a failure"


def test_forensics_cleans_up_its_probe_file(tmp_path):
    service, _, _ = build_service(tmp_path)

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.cleanup_ok is True and outcome.cleanup_error is None
    assert not list(tmp_path.glob("mb-*")), "a forensics run must not leave the probe behind"


def test_forensics_reports_a_cleanup_failure_instead_of_hiding_it(tmp_path, monkeypatch):
    import shutil

    service, _, _ = build_service(tmp_path)

    def refuse(_path, *_args, **_kwargs):
        raise OSError("directory is busy")

    monkeypatch.setattr(shutil, "rmtree", refuse)

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.ok, "the dump itself succeeded"
    assert outcome.cleanup_ok is False
    assert "directory is busy" in (outcome.cleanup_error or "")
    assert list(tmp_path.glob("mb-*")), "the leftover probe is the operator's problem"


def test_forensics_refuses_when_the_component_is_gone(tmp_path):
    def dump(_params, _write_heap=True):
        body = _envelope(ACTION_DUMP, entries=[])
        body.update({"refused": True, "reason": "component_not_found", "removed": False})
        return body

    service, _, store = build_service(tmp_path, server=FakeProbeServer(dump=dump))

    outcome = service.run_forensics("site-a", "filter", "ghost")

    assert outcome.ok is False
    assert outcome.failure == "component_not_found"
    assert store.index() == [], "a refused run must not leave an artifact behind"
    assert outcome.cleanup_ok is True
    assert not list(tmp_path.glob("mb-*"))


def test_forensics_refuses_unknown_kinds_and_sites(tmp_path):
    service, server, store = build_service(tmp_path)

    bad_kind = service.run_forensics("site-a", "session", "x@y")
    bad_site = service.run_forensics("ghost", "filter", "evilFilter")

    assert bad_kind.failure == "unknown_kind"
    assert bad_site.failure == "unknown_or_unwatchable_site"
    assert server.calls == [], "nothing may be sent to a container for an invalid request"
    assert store.index() == []


def test_forensics_obeys_its_own_switch(tmp_path):
    service, server, _ = build_service(tmp_path, config={"forensics_enabled": False})

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.failure == REASON_FORENSICS_DISABLED
    assert server.calls == []


def test_forensics_without_a_store_says_so(tmp_path):
    from anteumbra.application.memory_shell_service import MemoryShellService

    artifacts = InMemoryInternalArtifactRegistry()
    server = FakeProbeServer()
    service = MemoryShellService(
        config_provider=_provider({}, tmp_path),
        deployer=MemoryShellProbeDeployer(
            artifacts=artifacts, reader=server, template_loader=lambda: JSP_TEMPLATE
        ),
        artifacts=artifacts,
        log=LOGGER,
    )

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.failure == "forensics_store_unavailable"
    assert server.calls == []
    snapshot = service.forensics_snapshot()
    assert snapshot["available"] is False
    assert snapshot["store_error"] == "forensics_store_unavailable"


def test_the_store_is_wired_from_the_configured_data_directory(tmp_path):
    """The production path: no store is injected, the data directory says where."""
    data_dir = tmp_path / "runtime"
    service, _, store = build_service(
        tmp_path, with_store=False, paths={"data_dir": str(data_dir)}
    )

    assert store is not None and store.available is True
    assert store.root == (data_dir / "forensics").resolve(), "no store is guessed elsewhere"

    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    assert outcome.ok and outcome.index_recorded
    assert (data_dir / "forensics" / "index.json").is_file()
    snapshot = service.forensics_snapshot()
    assert snapshot["available"] is True
    assert snapshot["root"] == str((data_dir / "forensics").resolve())
    assert len(snapshot["runs"]) == 1


def test_no_store_is_created_without_a_configured_data_directory(tmp_path):
    service, server, store = build_service(tmp_path, with_store=False)

    assert store is None
    assert service.forensics_root is None
    outcome = service.run_forensics("site-a", "filter", "evilFilter")
    assert outcome.failure == "forensics_store_unavailable"
    assert server.calls == [], "nothing may be dumped without somewhere to put it"
    assert not (tmp_path / "data").exists()


# ── index: write, rotation, atomicity ───────────────────────────────


def test_index_rotates_and_keeps_the_newest_runs(tmp_path):
    store = MemoryShellForensicsStore(tmp_path / "forensics", history_limit=3, log=LOGGER)

    for index in range(5):
        manifest = manifest_from_payload(_manifest_payload(name=f"f{index}"))
        plan = store.begin(site_id="site-a", kind="filter", name=f"f{index}", created_at=100.0 + index)
        store.save_run(
            plan,
            site_name="Site A",
            class_name="com.evil.Filter",
            on_disk=False,
            trigger="manual",
            triggered_by="test",
            manifest=manifest,
            class_bytes=None,
            heap=None,
            heap_error="",
            class_bytes_unavailable_reason=CLASS_BYTES_RUNTIME_DEFINED,
            report_error="",
        )

    runs = store.index()
    assert [item["name"] for item in runs] == ["f4", "f3", "f2"], "newest first, bounded"
    payload = json.loads(store.index_path.read_text(encoding="utf-8"))
    assert payload["history_limit"] == 3
    assert payload["run_count"] == 3
    assert len(payload["runs"]) == 3


def test_index_write_is_atomic_and_leaves_no_temporary_files(tmp_path):
    store = MemoryShellForensicsStore(tmp_path / "forensics", log=LOGGER)
    manifest = manifest_from_payload(_manifest_payload())
    plan = store.begin(site_id="site-a", kind="filter", name="evilFilter", created_at=1.0)

    store.save_run(
        plan,
        site_name="Site A",
        class_name="com.evil.Filter",
        on_disk=False,
        trigger="manual",
        triggered_by="test",
        manifest=manifest,
        class_bytes=None,
        heap=None,
        heap_error="",
        class_bytes_unavailable_reason="",
        report_error="",
    )

    leftovers = [path.name for path in store.root.iterdir() if path.name.startswith(".")]
    assert leftovers == []
    assert json.loads(store.index_path.read_text(encoding="utf-8"))["version"] == 1


def test_a_corrupt_index_is_reported_and_recovered(tmp_path):
    root = tmp_path / "forensics"
    store = MemoryShellForensicsStore(root, log=LOGGER)
    root.mkdir(parents=True, exist_ok=True)
    store.index_path.write_text("{not json", encoding="utf-8")

    assert store.index() == []
    assert store.load_error, "an unreadable index is reported, never silently ignored"

    manifest = manifest_from_payload(_manifest_payload())
    plan = store.begin(site_id="site-a", kind="filter", name="evilFilter", created_at=1.0)
    store.save_run(
        plan,
        site_name="Site A",
        class_name="com.evil.Filter",
        on_disk=False,
        trigger="manual",
        triggered_by="test",
        manifest=manifest,
        class_bytes=None,
        heap=None,
        heap_error="",
        class_bytes_unavailable_reason="",
        report_error="",
    )
    assert len(store.index()) == 1
    assert store.load_error == ""


def test_index_records_the_remediation_history_for_a_component(tmp_path):
    store = MemoryShellForensicsStore(tmp_path / "forensics", log=LOGGER)
    manifest = manifest_from_payload(_manifest_payload())
    plan = store.begin(site_id="site-a", kind="filter", name="evilFilter", created_at=1.0)
    entry = store.save_run(
        plan,
        site_name="Site A",
        class_name="com.evil.Filter",
        on_disk=False,
        trigger="manual",
        triggered_by="test",
        manifest=manifest,
        class_bytes=None,
        heap=None,
        heap_error="",
        class_bytes_unavailable_reason="",
        report_error="",
    )

    assert store.find_component(site_id="site-a", kind="filter", name="evilFilter") is not None
    assert store.find_component(site_id="site-a", kind="servlet", name="evilFilter") is None

    store.record_remediation(
        entry["artifact_id"],
        result="removed",
        removed=True,
        reason="",
        operator="admin",
        acknowledge_no_forensics=False,
        force=False,
        remediated_at=1234.0,
    )
    history = store.get(entry["artifact_id"])["remediations"]
    assert len(history) == 1
    assert history[0]["result"] == "removed"
    assert history[0]["operator"] == "admin"
    assert history[0]["remediated_at_iso"].endswith("Z")


def test_store_confines_reads_to_its_own_root(tmp_path):
    store = MemoryShellForensicsStore(tmp_path / "forensics", log=LOGGER)
    secret = tmp_path / "secret.txt"
    secret.write_text("do not serve me", encoding="utf-8")
    manifest = manifest_from_payload(_manifest_payload())
    plan = store.begin(site_id="site-a", kind="filter", name="evilFilter", created_at=1.0)
    entry = store.save_run(
        plan,
        site_name="Site A",
        class_name="com.evil.Filter",
        on_disk=False,
        trigger="manual",
        triggered_by="test",
        manifest=manifest,
        class_bytes=None,
        heap=None,
        heap_error="",
        class_bytes_unavailable_reason="",
        report_error="",
    )

    assert store.resolve_file(entry["artifact_id"], "manifest.json") is not None
    assert store.resolve_file(entry["artifact_id"], "../secret.txt") is None
    assert store.resolve_file(entry["artifact_id"], "no-such-file") is None
    assert store.resolve_file("no-such-artifact", "manifest.json") is None


def test_discard_only_removes_an_empty_unindexed_directory(tmp_path):
    store = MemoryShellForensicsStore(tmp_path / "forensics", log=LOGGER)
    empty = store.begin(site_id="site-a", kind="filter", name="a", created_at=1.0)
    assert store.discard(empty) is True
    assert not Path(empty.directory).exists()

    with_heap = store.begin(site_id="site-a", kind="filter", name="b", created_at=2.0)
    Path(with_heap.heap_path).write_bytes(b"evidence")
    assert store.discard(with_heap) is False
    assert Path(with_heap.heap_path).read_bytes() == b"evidence", "evidence is never discarded"


# ── remediation ─────────────────────────────────────────────────────


def test_remediate_refuses_without_acknowledgement_when_there_is_no_forensics(tmp_path):
    server = FakeProbeServer()
    service, _, _ = build_service(tmp_path, server=server)

    outcome = service.remediate(
        "site-a",
        "filter",
        "evilFilter",
        acknowledge_no_forensics=False,
        expect_class="com.evil.Filter",
    )

    assert outcome.refused is True and outcome.removed is False
    assert outcome.reason == REASON_FORENSICS_REQUIRED
    assert server.calls == [], "a refusal must not reach the container"
    assert not list(tmp_path.glob("mb-*"))


def test_remediate_with_acknowledgement_removes_and_records(tmp_path):
    server = FakeProbeServer()
    service, _, store = build_service(tmp_path, server=server)

    outcome = service.remediate(
        "site-a",
        "filter",
        "evilFilter",
        acknowledge_no_forensics=True,
        expect_class="com.evil.Filter",
        triggered_by="admin",
    )

    assert outcome.removed is True and outcome.ok is True
    request = server.last(ACTION_KILL)["params"]
    assert request["kind"] == "filter"
    assert request["name"] == "evilFilter"
    assert request["expect_class"] == "com.evil.Filter"
    assert request["force"] == "0"
    assert outcome.after_entries == ()
    assert outcome.after_component == {}
    assert outcome.before_component["class_name"] == "com.evil.Filter"
    assert outcome.cleanup_ok is True
    assert not list(tmp_path.glob("mb-*")), "remediation must remove its own probe file"
    assert store.index() == [], "no artifact existed, so there is nothing to update"


def test_remediate_uses_the_forensics_artifact_and_updates_its_history(tmp_path):
    service, server, store = build_service(tmp_path)
    forensics = service.run_forensics("site-a", "filter", "evilFilter")
    assert forensics.ok
    server.calls.clear()

    outcome = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=False, triggered_by="admin"
    )

    assert outcome.removed is True
    assert outcome.expect_class == "com.evil.Filter", "the stored class is what we match on"
    assert outcome.forensics_artifact_id == forensics.artifact_id
    assert server.actions == [ACTION_KILL]
    history = store.get(forensics.artifact_id)["remediations"]
    assert len(history) == 1
    assert history[0]["result"] == "removed"
    assert history[0]["removed"] is True
    assert history[0]["operator"] == "admin"


def test_remediate_refuses_when_the_class_name_moved(tmp_path):
    def kill(params):
        body = _envelope(ACTION_KILL, entries=[_entry()])
        body.update(
            {
                "removed": False,
                "refused": True,
                "reason": (
                    "class_name_mismatch: expected com.evil.Filter but found com.other.Thing"
                ),
                "kind": params.get("kind"),
                "name": params.get("name"),
                "expect_class": params.get("expect_class"),
            }
        )
        return body

    service, server, _ = build_service(tmp_path, server=FakeProbeServer(kill=kill))

    outcome = service.remediate(
        "site-a",
        "filter",
        "evilFilter",
        acknowledge_no_forensics=True,
        expect_class="com.evil.Filter",
    )

    assert outcome.refused is True
    assert outcome.removed is False
    assert "class_name_mismatch" in outcome.reason
    assert "com.other.Thing" in outcome.reason
    assert outcome.cleanup_ok is True
    assert not list(tmp_path.glob("mb-*"))


def test_remediate_reports_a_probe_failure_as_a_failure(tmp_path):
    server = FakeProbeServer(error=OSError("connection refused"))
    service, _, _ = build_service(tmp_path, server=server)

    outcome = service.remediate(
        "site-a",
        "filter",
        "evilFilter",
        acknowledge_no_forensics=True,
        expect_class="com.evil.Filter",
    )

    assert outcome.removed is False and outcome.refused is False
    assert "connection refused" in (outcome.failure or "")
    assert outcome.cleanup_ok is True
    assert not list(tmp_path.glob("mb-*"))


def test_remediate_refuses_without_a_recorded_class(tmp_path):
    service, server, _ = build_service(tmp_path)

    outcome = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=True
    )

    assert outcome.refused is True
    assert outcome.reason == REASON_NO_RECORDED_CLASS
    assert server.calls == [], "without a class to match, nothing may be removed"


def test_remediate_takes_the_recorded_class_from_the_last_probe_report(tmp_path):
    """A finding the panel shows is enough to justify a match, and nothing else is."""
    service, server, _ = build_service(tmp_path)
    probe = service.run_probe("site-a")
    assert probe.suspect_count == 1

    outcome = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=True
    )

    assert outcome.removed is True
    assert outcome.expect_class == "com.evil.Filter"
    assert server.last(ACTION_KILL)["params"]["expect_class"] == "com.evil.Filter"


def test_remediate_never_matches_a_component_the_probe_did_not_flag(tmp_path):
    def probe(_params):
        return _envelope(ACTION_PROBE, entries=[_entry(suspect=False)])

    service, server, _ = build_service(tmp_path, server=FakeProbeServer(probe=probe))
    service.run_probe("site-a")

    outcome = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=True
    )

    assert outcome.refused is True
    assert outcome.reason == REASON_NO_RECORDED_CLASS
    assert server.actions == [ACTION_PROBE]


def test_remediate_publishes_an_event_for_every_attempt(tmp_path):
    publisher = FakePublisher()
    service, _, _ = build_service(tmp_path, publisher=publisher)

    refused = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=False,
        expect_class="com.evil.Filter", triggered_by="admin",
    )
    removed = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=True,
        expect_class="com.evil.Filter", triggered_by="admin",
    )

    assert refused.refused and removed.removed
    assert refused.published is True, "a refusal is an audit event too"
    assert removed.published is True
    event_types = [event[0] for event in publisher.events]
    assert event_types == ["memory_shell_remediated", "memory_shell_remediated"]
    assert publisher.events[0][2]["refused"] is True
    assert publisher.events[0][2]["reason"] == REASON_FORENSICS_REQUIRED
    payload = publisher.events[1][2]
    assert payload["removed"] is True
    assert payload["before_component"]["class_name"] == "com.evil.Filter"
    assert payload["operator"] == "admin"
    assert publisher.events[1][1] == "memory_shell_probe"


def test_remediation_outcomes_are_immutable_snapshots(tmp_path):
    """Every outcome field is set through the constructor, never patched later."""
    publisher = FakePublisher()
    service, _, store = build_service(tmp_path, publisher=publisher)
    forensics = service.run_forensics("site-a", "filter", "evilFilter")

    outcome = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=False
    )

    assert outcome.published is True
    assert outcome.recorded is True, "the artifact's history was updated"
    assert store.get(forensics.artifact_id)["remediations"][0]["operator"] == ""
    assert service.remediation_for("site-a")["removed"] is True


def test_a_removal_error_reaches_the_outcome_as_the_reason(tmp_path):
    """A registry that refused the removal is not a refusal: it is a reason."""

    def kill(params):
        body = _envelope(ACTION_KILL, entries=[_entry()])
        body.update(
            {
                "removed": False,
                "refused": False,
                "reason": None,
                "kind": params.get("kind"),
                "name": params.get("name"),
                "removal_error": "remove_filter_map_failed: method_not_found:removeFilterMap",
                "still_present": True,
                "after_component": {
                    "kind": "filter",
                    "name": params.get("name"),
                    "class_name": params.get("expect_class"),
                    "urls": ["/*"],
                },
            }
        )
        return body

    service, _, store = build_service(tmp_path, server=FakeProbeServer(kill=kill))
    forensics = service.run_forensics("site-a", "filter", "evilFilter")

    outcome = service.remediate(
        "site-a", "filter", "evilFilter", acknowledge_no_forensics=False
    )

    assert outcome.refused is False, "the probe did not refuse, it failed to remove"
    assert outcome.removed is False
    assert outcome.ok is False
    assert "method_not_found:removeFilterMap" in outcome.reason
    assert outcome.after_component["class_name"] == "com.evil.Filter"
    assert outcome.probe_url.startswith("http://127.0.0.1:8081/mb-")
    history = store.get(forensics.artifact_id)["remediations"]
    assert history[0]["result"] == "not_removed", "no refusal: a container that kept the filter"
    assert "removeFilterMap" in history[0]["reason"]


def test_remediate_passes_force_through_for_a_component_on_disk(tmp_path):
    service, server, _ = build_service(tmp_path)

    outcome = service.remediate(
        "site-a",
        "filter",
        "WsFilter",
        acknowledge_no_forensics=True,
        force=True,
        expect_class="org.apache.tomcat.websocket.server.WsFilter",
    )

    assert outcome.removed is True
    assert outcome.force is True
    assert server.last(ACTION_KILL)["params"]["force"] == "1"


def test_remediate_rejects_an_unknown_kind_before_anything_else(tmp_path):
    service, server, _ = build_service(tmp_path)

    outcome = service.remediate(
        "site-a", "session", "attr@session", acknowledge_no_forensics=True
    )

    assert outcome.refused is True
    assert outcome.reason == "unknown_kind"
    assert server.calls == []


# ── configuration validation ────────────────────────────────────────


def test_forensics_config_values_are_validated_in_code(tmp_path):
    service, _, _ = build_service(
        tmp_path,
        config={
            "forensics_enabled": "no",
            "heap_dump_enabled": "off",
            "forensics_history": "999999",
            "forensics_max_dump_mb": -5,
            "forensics_timeout_seconds": "not-a-number",
        },
    )

    assert service.forensics_enabled is False
    assert service.heap_dump_enabled is False
    assert service.forensics_history == 10_000, "clamped to the maximum"
    assert service.forensics_max_dump_mb == 0, "a negative bound means no pre-check"
    assert service.forensics_timeout == 300.0, "an unparsable value falls back to the default"

    other, _, _ = build_service(
        tmp_path, config={"forensics_history": 0, "forensics_max_dump_mb": "64"}
    )
    assert other.forensics_history == 1
    assert other.forensics_max_dump_mb == 64

    floored, _, _ = build_service(
        tmp_path, config={"forensics_timeout_seconds": 1, "http_timeout_seconds": 8}
    )
    assert floored.forensics_timeout == 8.0, "never below the probe HTTP timeout"


def test_forensics_config_defaults_match_the_documented_values(tmp_path):
    service, _, _ = build_service(tmp_path)

    assert service.forensics_enabled is True
    assert service.heap_dump_enabled is True
    assert service.forensics_history == 200
    assert service.forensics_max_dump_mb == 2048


# ── views ───────────────────────────────────────────────────────────


def test_forensics_snapshot_reports_runs_and_state(tmp_path):
    service, _, _ = build_service(tmp_path, config={"heap_dump_enabled": False})
    service.run_forensics("site-a", "filter", "evilFilter")

    snapshot = service.forensics_snapshot()

    assert snapshot["available"] is True
    assert snapshot["enabled"] is True
    assert snapshot["heap_dump_enabled"] is False
    assert snapshot["history"] == 200
    assert len(snapshot["runs"]) == 1
    run = snapshot["runs"][0]
    assert run["site_id"] == "site-a"
    assert run["kind"] == "filter"
    assert run["name"] == "evilFilter"
    assert run["files"][0]["name"] == "manifest.json"
    assert run["class_bytes_available"] is False
    assert run["class_bytes_unavailable_reason"] == CLASS_BYTES_RUNTIME_DEFINED

    manifest = service.forensics_manifest(run["artifact_id"])
    assert manifest is not None and manifest["class_name"] == "com.evil.Filter"
    assert service.forensics_manifest("nope") is None
    path = service.forensics_file_path(run["artifact_id"], "manifest.json")
    assert path is not None and path.is_file()
    assert service.forensics_file_path(run["artifact_id"], "../index.json") is None


def test_probe_runs_still_report_the_probe_action_unchanged(tmp_path):
    """The first release's contract must survive the two new actions."""
    service, server, _ = build_service(tmp_path)

    outcome = service.run_probe("site-a")

    assert outcome.ok is True
    assert outcome.report is not None
    assert outcome.report.probe_version == "1.1.0"
    assert outcome.suspect_count == 1
    assert server.actions == [ACTION_PROBE]
    assert "action=probe" in server.last(ACTION_PROBE)["url"]
    assert not list(tmp_path.glob("mb-*"))


def test_manifest_json_round_trips_through_the_store(tmp_path):
    """What the operator reads on the page is what was written to disk."""
    service, _, store = build_service(tmp_path)
    outcome = service.run_forensics("site-a", "filter", "evilFilter")

    entry = store.get(outcome.artifact_id)
    on_disk = json.loads(
        (store.root / str(entry["directory"]) / "manifest.json").read_text(encoding="utf-8")
    )

    for key in ("kind", "name", "class_name", "class_loader_identity", "methods", "fields"):
        assert on_disk[key] == outcome.manifest.as_dict()[key]
    assert on_disk["artifact_id"] == outcome.artifact_id


def test_heap_dump_info_is_an_honest_view_of_the_probe_report():
    assert HeapDumpInfo().ok is False
    info = HeapDumpInfo(path="/x/heap.hprof", bytes=10, sha256="ab", live=True, requested=True)
    assert info.ok is True
    assert info.as_dict()["bytes"] == 10


# ── the Chinese catalog for this feature ────────────────────────────


def test_every_forensics_string_has_a_chinese_translation():
    """A half-translated tab is what users notice first.

    The feature-scoped map (``build/zh_map_extra_memshell.py``) is merged into
    the shipped catalog by ``build/build_zh_catalog.py``; every literal this
    feature puts in front of an operator has to be in it (or already be in one of
    the other maps the catalog build reads), otherwise the string silently falls
    back to English.
    """
    import re
    import runpy

    root = Path(__file__).resolve().parents[2]
    feature_map = runpy.run_path(str(root / "build" / "zh_map_extra_memshell.py"))[
        "ZH_MAP_EXTRA_MEMSSHELL"
    ]
    assert feature_map, "the feature map is empty"
    assert all(isinstance(key, str) and key for key in feature_map)

    known = set(runpy.run_path(str(root / "build" / "zh_map.py"))["TRANSLATIONS"])
    for name, variable in (
        ("zh_map_extra.py", "TRANSLATIONS"),
        ("zh_map_extra_sites.py", "ZH_MAP_EXTRA_SITES"),
        ("zh_map_extra_settings.py", "ZH_MAP_EXTRA_SETTINGS"),
        ("zh_map_extra_mcp.py", "ZH_MAP_EXTRA_MCP"),
    ):
        path = root / "build" / name
        if not path.is_file():
            continue
        entries = runpy.run_path(str(path)).get(variable)
        if isinstance(entries, dict):
            known |= set(entries)
    known |= set(feature_map)

    admin = root / "src" / "anteumbra" / "interfaces" / "web" / "templates" / "admin"
    sources = [
        admin / "memory_shell.html",
        admin / "panels" / "memory_shell_panel.html",
        admin / "memory_shell_forensics.html",
        admin / "memory_shell_forensics_panel.html",
        admin / "memory_shell_forensics_manifest.html",
        admin / "memory_shell_forensics_dialog.html",
        root / "src" / "anteumbra" / "interfaces" / "web" / "blueprints" / "memory_shell_bp.py",
    ]
    pattern = re.compile(r"\b_\('([^']+)'")
    missing: dict[str, list[str]] = {}
    for path in sources:
        assert path.is_file(), f"missing source: {path}"
        for literal in pattern.findall(path.read_text(encoding="utf-8")):
            if literal not in known:
                missing.setdefault(path.name, []).append(literal)
    assert not missing, f"untranslated memory-shell forensics strings: {missing}"
