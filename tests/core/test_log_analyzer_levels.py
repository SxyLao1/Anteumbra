# -*- coding: utf-8 -*-
"""Log levels for the access-log analyzer's per-file chatter.

Resolving the configured log path and starting a pass run once per scanned file,
so at INFO they flood the live panel: a single site sweep produced thousands of
lines that said nothing.  They are internal steps and belong at DEBUG.

"Found N suspicious IPs" is different — that is a result.  It stays at INFO when
N > 0 and drops to DEBUG when N == 0, because "found 0" is also just a step.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from anteumbra.infrastructure.monitoring.log_analyzer import LogAnalyzer

ACCESS_LOG = (
    '192.168.1.100 - - [28/Jun/2026:08:15:30 +0800] "POST /uploads/shell.php HTTP/1.1" 201 1234\n'
    '10.0.0.1 - - [28/Jun/2026:08:16:00 +0800] "GET /index.php HTTP/1.1" 200 890\n'
)


class _Website:
    """Minimal website double exposing only what the analyzer reads."""

    def __init__(self, access_log: Path, site_root: Path):
        self.name = "Test Site"
        self.site_id = "test"
        self.path = site_root
        self.scan_options = type(
            "Options",
            (),
            {"access_log_path": str(access_log), "monitor_extensions": [".php"]},
        )()


@pytest.fixture()
def analyzer(tmp_path, sample_log_file):
    site_root = tmp_path / "site"
    site_root.mkdir()
    return LogAnalyzer(_Website(sample_log_file, site_root), logger=logging.getLogger("test.analyzer"))


def test_log_path_resolution_is_debug(analyzer, caplog):
    with caplog.at_level(logging.DEBUG, logger="test.analyzer"):
        resolved = analyzer.get_configured_path()

    assert resolved is not None
    records = {r.message for r in caplog.records}
    assert any("固定路径加载" in message for message in records), records
    for record in caplog.records:
        if "固定路径加载" in record.message:
            assert record.levelno == logging.DEBUG, "path resolution must not be INFO"
            # It used to carry the [MONITOR][START][SUCCESS] prefix, which made
            # these per-file lines read like monitor restarts.
            assert "[MONITOR][START][SUCCESS]" not in record.getMessage()


def test_scan_start_banner_is_debug(analyzer, caplog):
    analyzer.get_configured_path()
    target = analyzer.website.path / "shell.php"
    target.write_text("<?php ?>", encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="test.analyzer"):
        analyzer.analyze_shell_access(target)

    starts = [r for r in caplog.records if "开始全量扫描" in r.message]
    assert starts, [r.message for r in caplog.records]
    assert all(r.levelno == logging.DEBUG for r in starts)


def test_zero_suspicious_ips_is_debug(analyzer, caplog):
    analyzer.get_configured_path()
    with caplog.at_level(logging.DEBUG, logger="test.analyzer"):
        result = analyzer.analyze_shell_access(analyzer.website.path / "shell.php")

    reported = [r for r in caplog.records if "个可疑IP" in r.message]
    assert reported, [r.message for r in caplog.records]
    if result and not result.get("suspicious_ips"):
        assert all(r.levelno == logging.DEBUG for r in reported), "found 0 must not be INFO"


def test_hits_are_reported_at_info(tmp_path, caplog):
    site_root = tmp_path / "site"
    (site_root / "uploads").mkdir(parents=True)
    (site_root / "uploads" / "shell.php").write_text("<?php ?>", encoding="utf-8")
    log = tmp_path / "access.log"
    log.write_text(ACCESS_LOG, encoding="utf-8")

    analyzer = LogAnalyzer(_Website(log, site_root), logger=logging.getLogger("test.hits"))
    analyzer.get_configured_path()
    with caplog.at_level(logging.DEBUG, logger="test.hits"):
        result = analyzer.analyze_shell_access(analyzer.website.path / "shell.php")

    reported = [r for r in caplog.records if "个可疑IP" in r.message]
    assert reported, "the analyzer reported nothing"
    hits = result.get("suspicious_ips") if result else None
    if hits:
        assert any(r.levelno == logging.INFO for r in reported), "a real hit must be visible at INFO"
