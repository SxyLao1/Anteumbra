"""End-to-end scanner, Registry, quarantine, and restore coverage."""

from __future__ import annotations

import logging

import pytest


@pytest.fixture
def monitor_target(tmp_path):
    target = tmp_path / "www"
    target.mkdir()
    return target


def test_scanner_pipeline_returns_a_result(
    monitor_target,
    webshell_samples,
    scanner_service,
):
    from anteumbra.infrastructure.detection.scanner import quick_scan_yara
    from anteumbra.infrastructure.models import ScanOptions

    target = monitor_target / "simple_eval.php"
    target.write_text(
        (webshell_samples / "simple_eval.php").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = quick_scan_yara(
        target,
        ScanOptions(monitor_extensions=[".php"]),
        logging.getLogger("test.e2e.scanner"),
        scanner_service=scanner_service,
    )

    assert result is not None
    assert result.file_path == target


def test_scanner_does_not_flag_a_clean_php_file(monitor_target, scanner_service):
    from anteumbra.infrastructure.detection.scanner import quick_scan_yara
    from anteumbra.infrastructure.models import ScanOptions

    target = monitor_target / "index.php"
    target.write_text("<?php echo 'Hello World';", encoding="utf-8")

    result = quick_scan_yara(
        target,
        ScanOptions(monitor_extensions=[".php"]),
        logging.getLogger("test.e2e.clean"),
        scanner_service=scanner_service,
    )

    assert result is not None
    assert result.is_suspicious is False


def test_registry_add_and_site_qualified_retrieval(
    monitor_target,
    webshell_samples,
    detection_runtime,
):
    target = monitor_target / "system_cmd.php"
    target.write_text(
        (webshell_samples / "system_cmd.php").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    detection_runtime.registry.add(
        target,
        ["system-call"],
        first_seen_ip="10.99.99.1",
        detection_source="active",
        site=detection_runtime.site,
    )
    record = detection_runtime.registry.get(
        target,
        detection_runtime.site.site_id,
    )

    assert record is not None
    assert record["features"] == ["system-call"]
    assert record["first_seen_ip"] == "10.99.99.1"
    assert record["site_id"] == "test-site"


def test_registered_quarantine_and_restore_remain_consistent(
    monitor_target,
    webshell_samples,
    detection_runtime,
):
    target = monitor_target / "base64_decode.php"
    original_content = (webshell_samples / "base64_decode.php").read_text(encoding="utf-8")
    target.write_text(original_content, encoding="utf-8")
    detection_runtime.registry.add(
        target,
        ["eval", "base64-decode"],
        first_seen_ip="10.99.99.1",
        detection_source="active",
        site=detection_runtime.site,
    )

    quarantined = detection_runtime.quarantine.quarantine_file(
        target,
        "php-eval-backdoor",
        ["eval", "base64-decode"],
        site=detection_runtime.site,
    )

    assert quarantined is not None
    assert not target.exists()
    linked = detection_runtime.registry.get(target, detection_runtime.site.site_id)
    assert linked["quarantine_id"] == quarantined["quarantine_id"]
    assert linked["file_exists"] is False

    restored = detection_runtime.quarantine.restore_file(quarantined["quarantine_id"])

    assert restored["status"] == "restored"
    assert target.read_text(encoding="utf-8") == original_content
    assert detection_runtime.quarantine.is_recently_restored(target)
    linked = detection_runtime.registry.get(target, detection_runtime.site.site_id)
    assert linked["quarantine_id"] is None
    assert linked["file_exists"] is True
