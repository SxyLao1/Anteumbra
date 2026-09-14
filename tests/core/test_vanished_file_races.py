# -*- coding: utf-8 -*-
"""A file may disappear between its filesystem event and its scan.

Attackers delete a shell right after using it, deployment tooling replaces
files, and Anteumbra's own memory-shell probe removes itself within seconds.
None of that is a failure, and none of it may reach the operator as an error
traceback in the live log stream - which is exactly what happened before these
guards existed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

from anteumbra.application.detection_workflow import DetectionWorkflow
from anteumbra.domain.scan import ScanOptions
from anteumbra.infrastructure.detection.scanner import EmergencyScanner, ScannerService

LOGGER = logging.getLogger("test.vanished")


class _Metrics:
    def __init__(self) -> None:
        self.counters: list[str] = []

    def increment(self, name: str) -> None:
        self.counters.append(name)

    def increment_site(self, name: str, site_id: str | None = None) -> None:
        self.counters.append(f"{name}:{site_id}")


class _Registry:
    def __init__(self) -> None:
        self.records: list[object] = []

    def get_all(self, **_kwargs):
        return list(self.records)

    def was_alerted(self, *_args, **_kwargs):
        return False


class _Site:
    site_id = "site-a"
    site_name = "Site A"

    def as_dict(self) -> dict[str, str]:
        return {"site_id": self.site_id, "site_name": self.site_name}


def _workflow(metrics: _Metrics) -> DetectionWorkflow:
    return DetectionWorkflow(
        config={},
        registry=_Registry(),
        metrics=metrics,
        events=SimpleNamespace(publish=lambda *a, **k: None),
        quarantine=SimpleNamespace(is_recently_restored=lambda *a, **k: False),
        site=_Site(),
        logger=LOGGER,
    )


def test_workflow_treats_a_vanished_file_as_normal(tmp_path):
    metrics = _Metrics()
    reported: list[tuple[Path, BaseException]] = []

    def scan(path: Path):
        raise FileNotFoundError(2, "No such file or directory", str(path))

    _workflow(metrics).execute(
        tmp_path / "gone.jsp",
        "CREATE",
        scan=scan,
        resolve_first_seen_ip=lambda path: "127.0.0.1",
        emit_alert=lambda **kwargs: None,
        emit_file_quarantined=lambda **kwargs: None,
        report_scan_error=lambda path, error: reported.append((path, error)),
    )

    assert reported == [], "a disappearance must not be reported as a scan error"
    assert "scan_file_vanished:site-a" in metrics.counters


def test_workflow_still_reports_real_failures(tmp_path):
    metrics = _Metrics()
    reported: list[tuple[Path, BaseException]] = []

    def scan(path: Path):
        raise RuntimeError("decoder exploded")

    _workflow(metrics).execute(
        tmp_path / "broken.jsp",
        "CREATE",
        scan=scan,
        resolve_first_seen_ip=lambda path: "127.0.0.1",
        emit_alert=lambda **kwargs: None,
        emit_file_quarantined=lambda **kwargs: None,
        report_scan_error=lambda path, error: reported.append((path, error)),
    )

    assert len(reported) == 1 and isinstance(reported[0][1], RuntimeError)


def test_decoder_pass_skips_a_vanished_file_without_a_traceback(caplog, tmp_path):
    metrics = _Metrics()
    service = ScannerService.__new__(ScannerService)
    service.metrics = metrics
    service.yara_engine = SimpleNamespace(compiled_rules=[object()])
    service.internal_artifacts = None
    service.config_provider = SimpleNamespace(get=lambda: {"paths": {}})
    service.chain = SimpleNamespace(scan=lambda *a, **k: None)

    with caplog.at_level(logging.DEBUG):
        result = service._scan_decoded(tmp_path / "gone.jsp", LOGGER)

    assert result is None
    assert "scan_file_vanished" in metrics.counters
    records = [record for record in caplog.records if record.name == LOGGER.name]
    assert any("[SCAN][GONE]" in record.getMessage() for record in records)
    assert not any(record.exc_info for record in records), "no traceback for a disappearance"


def test_emergency_scanner_does_not_blame_a_vanished_file(tmp_path):
    scanner = EmergencyScanner(SimpleNamespace(get=lambda: {"filesizes": {}}))
    options = ScanOptions()

    result = scanner.scan(tmp_path / "gone.jsp", options, LOGGER)

    assert result.is_suspicious is False
    assert result.error is None


def test_should_monitor_skips_a_vanished_file_without_a_traceback(caplog, tmp_path):
    from anteumbra.infrastructure.monitoring.monitor import FileMonitorHandler

    handler = SimpleNamespace(
        monitor_extensions={".jsp"},
        base_path=tmp_path,
        exclude_dirs=set(),
        scan_options=ScanOptions(),
        services=SimpleNamespace(internal_artifacts=None),
        logger=LOGGER,
    )
    handler._is_internal_artifact = lambda path: False  # type: ignore[attr-defined]

    with caplog.at_level(logging.DEBUG):
        decision = FileMonitorHandler._should_monitor(handler, tmp_path / "gone.jsp")

    assert decision is False
    records = [r for r in caplog.records if r.name == LOGGER.name]
    assert records, "the skip should still be visible at DEBUG"
    assert not any(r.exc_info for r in records), "a disappearance is not an exception"
