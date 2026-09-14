# -*- coding: utf-8 -*-
"""The memory-shell probe must not be detected by Anteumbra itself.

Deploying the probe means writing a JSP into the web root the defender is
watching, and reading it means one HTTP request that lands in the very access
log the defender analyses.  Both look exactly like an intrusion, so the wiring
has to make the runtime recognise its own artifact in three places — the file
monitor, the scanner and the log monitor — for as long as the probe lives and
not one moment longer.

These tests use real objects and ``tmp_path`` throughout: no container, no
network, no real ports.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from anteumbra.domain.memory_shell import SiteTarget
from anteumbra.infrastructure.internal_artifacts import InMemoryInternalArtifactRegistry
from anteumbra.infrastructure.memory_shell import MemoryShellProbeDeployer, ProbeError

PROBE_TEMPLATE = "ANTEUMBRA-MEMORY-SHELL-PROBE {{PROBE_TOKEN}}"
PROBE_PAYLOAD_MARKER = "ANTEUMBRA-MEMORY-SHELL-PROBE"

LOGGER = logging.getLogger("test.memory_shell_wiring")


# ── fakes and helpers ───────────────────────────────────────────────


class _FakeNotifier:
    def __init__(self) -> None:
        self.alerts: list[dict] = []

    def send_alert(self, message, **_kwargs):
        self.alerts.append({"message": message})


class _FakePublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def publish(self, event_type, source, payload):
        self.events.append((event_type, source, dict(payload)))


def _config_provider(site_root: Path, *, site_id: str = "site-a"):
    config = {
        "plugins": {"memory_shell_probe": {"enabled": True, "cooldown_seconds": 0}},
        "paths": {},
        "website": [{"name": site_id, "path": str(site_root), "port": 8080}],
    }
    website = SimpleNamespace(
        site_id=site_id,
        name=site_id,
        path=site_root,
        port=8080,
    )
    return SimpleNamespace(get=lambda: config, get_enabled_websites=lambda: [website])


def _probe_response(entries: list[dict]) -> bytes:
    return json.dumps(
        {
            "probe": PROBE_PAYLOAD_MARKER,
            "version": "1.0.0",
            "context_path": "/app",
            "container": ["Apache Tomcat/9.0"],
            "entries": entries,
            "duration_ms": 4,
        }
    ).encode("utf-8")


def _deployer(artifacts, reader, site_root: Path) -> MemoryShellProbeDeployer:
    return MemoryShellProbeDeployer(
        artifacts=artifacts,
        reader=reader,
        template_loader=lambda: PROBE_TEMPLATE,
        log=LOGGER,
    )


def _service(artifacts, reader, site_root: Path, **kwargs):
    from anteumbra.application.memory_shell_service import MemoryShellService

    return MemoryShellService(
        config_provider=_config_provider(site_root),
        deployer=_deployer(artifacts, reader, site_root),
        artifacts=artifacts,
        clock=kwargs.pop("clock", None) or time.time,
        log=LOGGER,
        **kwargs,
    )


# ── file monitor ────────────────────────────────────────────────────


def _file_monitor(tmp_path: Path, internal_artifacts):
    from anteumbra.domain.runtime import RuntimeContext, RuntimeServices
    from anteumbra.infrastructure.models import ScanOptions
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    services = RuntimeServices(
        context=RuntimeContext.from_websites({"paths": {}}, []),
        registry=SimpleNamespace(add=lambda *_a, **_k: None),
        metrics=SimpleNamespace(
            increment=lambda *_a, **_k: None, increment_site=lambda *_a, **_k: None
        ),
        events=SimpleNamespace(publish=lambda *_a, **_k: None),
        quarantine=SimpleNamespace(is_recently_restored=lambda _path: False),
        internal_artifacts=internal_artifacts,
    )
    return monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".jsp"]),
        base_path=tmp_path,
        logger=LOGGER,
        services=services,
    )


def test_file_monitor_skips_a_registered_probe_and_resumes_after_release(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    handler = _file_monitor(tmp_path, artifacts)
    probe_dir = tmp_path / "mb-0123456789abcdef"
    probe_dir.mkdir()
    probe = probe_dir / "9f8e7d6c5b4a.jsp"
    probe.write_text(PROBE_TEMPLATE.replace("{{PROBE_TOKEN}}", "t"), encoding="utf-8")
    normal = tmp_path / "upload.jsp"
    normal.write_text("<% out.print(1); %>", encoding="utf-8")
    try:
        artifacts.register(path=probe, url_fragment="/mb-0123456789abcdef/9f8e7d6c5b4a.jsp", ttl=60)
        artifacts.register(path=probe_dir, url_fragment="/mb-0123456789abcdef/", ttl=60)

        assert handler._should_monitor(probe) is False
        assert handler._should_monitor(normal) is True, "a normal JSP must still be scanned"

        artifacts.release(probe)
        artifacts.release(probe_dir)

        assert handler._should_monitor(probe) is True, "the path is only exempt while registered"
    finally:
        handler.shutdown()


def test_file_monitor_without_a_registry_still_monitors(tmp_path):
    """A runtime built without the probe must behave exactly as before."""
    handler = _file_monitor(tmp_path, None)
    sample = tmp_path / "page.jsp"
    sample.write_text("<% out.print(1); %>", encoding="utf-8")
    try:
        assert handler._should_monitor(sample) is True
    finally:
        handler.shutdown()


# ── scanner ─────────────────────────────────────────────────────────


class _FakeYaraEngine:
    """Minimal engine: a rule that matches, so a normal file is still flagged."""

    def __init__(self) -> None:
        self.compiled_rules = object()
        self.scanned: list[Path] = []

    def scan(self, file_path):
        self.scanned.append(Path(file_path))
        return [SimpleNamespace(rule_name="jsp_runtime_exec", severity="critical")]

    def scan_data(self, _content, *, source_name=""):
        return []


def _scanner(tmp_path: Path, internal_artifacts, engine=None):
    from anteumbra.infrastructure.detection.scanner import ScannerService
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector

    provider = SimpleNamespace(
        get=lambda: {
            "filesizes": {"max_scan_file_size_mb": 10},
            "paths": {"monitor_extensions": [".jsp"]},
        }
    )
    metrics = MetricsCollector(tmp_path / "metrics.json")
    return (
        ScannerService(provider, engine or _FakeYaraEngine(), metrics, internal_artifacts),
        metrics,
    )


def test_scanner_skips_a_registered_probe_and_still_scans_ordinary_files(tmp_path):
    from anteumbra.infrastructure.models import ScanOptions

    artifacts = InMemoryInternalArtifactRegistry()
    engine = _FakeYaraEngine()
    scanner, metrics = _scanner(tmp_path, artifacts, engine)
    probe = tmp_path / "mb-probe" / "abc123.jsp"
    probe.parent.mkdir()
    probe.write_text(PROBE_TEMPLATE.replace("{{PROBE_TOKEN}}", "t"), encoding="utf-8")
    normal = tmp_path / "shell.jsp"
    normal.write_text("<% Runtime.getRuntime().exec(c); %>", encoding="utf-8")
    options = ScanOptions(monitor_extensions=[".jsp"])

    artifacts.register(path=probe.parent, url_fragment="/mb-probe/", ttl=60)

    probe_result = scanner.scan(probe, options, LOGGER)
    assert probe_result.is_suspicious is False
    assert probe_result.features == []
    assert engine.scanned == [], "the probe must never reach a detection engine"

    normal_result = scanner.scan(normal, options, LOGGER)
    assert normal_result.is_suspicious is True
    assert engine.scanned == [normal]
    assert metrics.get()["scan_total"] == 1, "only the real file counts as a scan attempt"


# ── log monitor ─────────────────────────────────────────────────────


class _FakeAnalyzer:
    def __init__(self, site_root: Path) -> None:
        self.website = SimpleNamespace(site_id="site-a", name="Site A", path=site_root, port=8080)
        self.log_path = site_root / "access.log"

    @staticmethod
    def extract_ip(line: str) -> str:
        return line.split(" ", 1)[0] if line.strip() else ""

    @staticmethod
    def get_configured_path():
        return None


class _FakeRegistry:
    def __init__(self, file_path: Path) -> None:
        self._records = [
            {"file_path": str(file_path), "display_name": file_path.name, "file_exists": True}
        ]
        self.accesses: list[tuple[str, str]] = []

    def get_all(self, **_kwargs):
        return list(self._records)

    def increment_access(self, file_path, ip, site_id=None):
        self.accesses.append((str(file_path), ip))

    def mark_alerted(self, *_args, **_kwargs):
        return True


def _log_monitor(tmp_path: Path, internal_artifacts, registry):
    from anteumbra.infrastructure.monitoring.log_monitor import LogMonitor

    return LogMonitor(
        LOGGER,
        _FakeAnalyzer(tmp_path),
        config_provider=SimpleNamespace(get=lambda: {"thresholds": {}}),
        notifier=_FakeNotifier(),
        registry=registry,
        internal_artifacts=internal_artifacts,
    )


def test_log_monitor_ignores_the_probes_own_request_but_not_a_real_one(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    shell = tmp_path / "shell.jsp"
    shell.write_text("<% out.print(1); %>", encoding="utf-8")
    registry = _FakeRegistry(shell)
    monitor = _log_monitor(tmp_path, artifacts, registry)

    probe_path = "/mb-0123456789abcdef/9f8e7d6c5b4a.jsp"
    artifacts.register(path=tmp_path / probe_path.lstrip("/"), url_fragment=probe_path, ttl=60)

    probe_line = (
        '127.0.0.1 - - [28/Jun/2026:08:15:30 +0800] "GET '
        f'{probe_path}?t=deadbeef HTTP/1.1" 200 321 "-" "Anteumbra-MemoryShellProbe/1.0.0"'
    )
    monitor._process_line(probe_line)

    assert registry.accesses == [], "the probe request must not be attributed to an attacker"

    real_line = (
        '203.0.113.9 - - [28/Jun/2026:08:16:00 +0800] "GET /shell.jsp HTTP/1.1" '
        '200 987 "-" "AntSword/2.1"'
    )
    monitor._process_line(real_line)

    assert registry.accesses == [(str(shell), "203.0.113.9")], "a real access must still be seen"


def test_log_monitor_without_a_registry_keeps_processing_every_line(tmp_path):
    shell = tmp_path / "shell.jsp"
    shell.write_text("<% out.print(1); %>", encoding="utf-8")
    registry = _FakeRegistry(shell)
    monitor = _log_monitor(tmp_path, None, registry)

    line = (
        '203.0.113.9 - - [28/Jun/2026:08:16:00 +0800] "GET /shell.jsp HTTP/1.1" '
        '200 987 "-" "AntSword/2.1"'
    )
    monitor._process_line(line)

    assert registry.accesses == [(str(shell), "203.0.113.9")]


# ── probe service ───────────────────────────────────────────────────


def test_run_probe_records_an_outcome_with_suspects(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    payload = _probe_response(
        [
            {
                "type": "filter",
                "name": "evilFilter",
                "class": "com.evil.Filter",
                "urls": ["/*"],
                "suspect": True,
                "reasons": ["no on-disk class"],
            },
            {"type": "servlet", "name": "jsp", "class": "org.apache.jasper.servlet.JspServlet"},
        ]
    )
    service = _service(artifacts, lambda _url, _timeout: payload, tmp_path)

    outcome = service.run_probe("site-a", trigger="manual", triggered_by="test")

    assert outcome is not None and outcome.ok is True
    assert outcome.suspect_count == 1
    assert outcome.report.suspects[0].name == "evilFilter"
    assert outcome.cleanup_ok is True and outcome.cleanup_error is None
    assert not list(tmp_path.glob("mb-*")), "the probe directory must be gone"
    # The registration outlives the deletion by a grace period on purpose: the
    # create/modify events for this file may still be queued in the monitor.
    assert artifacts.snapshot(), "the registration must survive cleanup briefly"
    assert artifacts.is_internal_path(tmp_path / "mb-gone" / "p.jsp") is False
    assert service is not None


def test_run_probe_still_cleans_up_when_the_reader_fails(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()

    def explode(_url, _timeout):
        raise OSError("connection refused")

    service = _service(artifacts, explode, tmp_path)

    outcome = service.run_probe("site-a", trigger="auto", triggered_by="upload.jsp")

    assert outcome is not None
    assert outcome.ok is False
    assert "connection refused" in (outcome.failure or "")
    assert outcome.cleanup_ok is True
    assert not list(tmp_path.glob("mb-*")), "a failed probe must not leave its file behind"
    # The registration outlives the deletion by a grace period on purpose: the
    # monitor may still hold create/modify events for this exact path.
    assert artifacts.snapshot(), "in-flight events for the deleted probe stay internal"


def test_run_probe_reports_a_cleanup_failure_instead_of_hiding_it(tmp_path, monkeypatch):
    artifacts = InMemoryInternalArtifactRegistry()
    payload = _probe_response([])
    service = _service(artifacts, lambda _url, _timeout: payload, tmp_path)

    def refuse(_path, *_args, **_kwargs):
        raise OSError("directory is busy")

    monkeypatch.setattr(shutil, "rmtree", refuse)

    outcome = service.run_probe("site-a")

    assert outcome is not None
    assert outcome.ok is True, "the probe itself succeeded"
    assert outcome.cleanup_ok is False
    assert "directory is busy" in (outcome.cleanup_error or "")
    assert list(tmp_path.glob("mb-*")), "the leftover directory is the operator's problem to fix"


def test_run_probe_alerts_and_publishes_once_for_suspects(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    payload = _probe_response(
        [{"type": "listener", "name": "evil", "class": "com.evil.L", "suspect": True}]
    )
    notifier = _FakeNotifier()
    publisher = _FakePublisher()
    service = _service(artifacts, lambda _url, _timeout: payload, tmp_path)
    service._notifier = notifier
    service.bind_publisher(publisher)

    outcome = service.run_probe("site-a")

    assert outcome.suspect_count == 1
    assert [event[0] for event in publisher.events] == ["memory_shell_found"]
    assert len(notifier.alerts) == 1


# ── deployer safety ─────────────────────────────────────────────────


def test_cleanup_refuses_a_directory_outside_the_site_root(tmp_path):
    artifacts = InMemoryInternalArtifactRegistry()
    site_root = tmp_path / "webroot"
    site_root.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    victim = outside / "keep.jsp"
    victim.write_text("do not delete me", encoding="utf-8")

    target = SiteTarget(
        site_id="site-a", name="Site A", root=site_root, base_url="http://127.0.0.1:8080"
    )
    deployer = _deployer(artifacts, lambda _url, _timeout: b"", site_root)
    artifact = deployer.deploy(target, ttl=60)

    forged = type(artifact)(
        site_id=artifact.site_id,
        site_root=site_root,
        directory=outside,
        file_path=victim,
        token=artifact.token,
        url=artifact.url,
        created_at=artifact.created_at,
    )
    try:
        with pytest.raises(ProbeError, match="outside the site root"):
            deployer.cleanup(forged)
        assert victim.exists(), "only paths under the site root may ever be removed"
    finally:
        deployer.cleanup(artifact)
