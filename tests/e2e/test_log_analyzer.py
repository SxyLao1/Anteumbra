# -*- coding: utf-8 -*-
"""
Tests for the dedicated Log Analyzer page.

Covers the line parser (five runtime dialects), the filter/aggregate service
and the page + data endpoints.
"""

import os
from datetime import datetime, timedelta

import pytest

from anteumbra.application.log_analyzer_service import (
    LEVELS,
    analyze_lines,
    parse_line,
    range_bounds,
)

NOW = datetime(2026, 9, 12, 12, 0, 0)


def _stamp(minutes_ago: int) -> str:
    moment = NOW - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


SAMPLE_LINES = [
    f"[{_stamp(5)}] SCAN    [HIT] E:\\www\\shell.php",
    f"[STDOUT][{_stamp(4)[11:]}] CRITICAL local_detection -> E:\\www\\shell.php",
    f"[NOTIFIER][LOCAL_ONLY][WARNING] [Anteumbra WARNING] {_stamp(3)}",
    "NotifierHandler: queued alert level=WARNING",
    "[QUARANTINE] 总开关关闭，跳过隔离: shell.php",
    "[YARA][MATCH] E:\\www\\shell.php matched 21 rules",
    "Task queue depth is 1",
    "[MONITOR][START][SUCCESS] 固定路径加载: access.log",
]


class TestParseLine:
    def test_full_timestamp_and_module(self):
        row = parse_line("[2026-09-12 01:40:09] SCAN    [HIT] E:\\www\\a.php", today=NOW)
        assert row["time"] == "2026-09-12 01:40:09"
        assert row["module"] == "SCAN"
        assert row["marker"] == "HIT"
        assert row["hit"] is True

    def test_stdout_time_only_uses_today(self):
        row = parse_line("[STDOUT][01:40:09] CRITICAL local_detection -> x", today=NOW)
        assert row["level"] == "CRITICAL"
        assert row["time"].startswith("2026-09-12")
        assert row["time"].endswith("01:40:09")

    def test_tagged_level_wins(self):
        row = parse_line("[NOTIFIER][LOCAL_ONLY][WARNING] [Anteumbra WARNING] 2026-09-12 01:40:09")
        assert row["level"] == "WARNING"
        assert row["module"] == "NOTIFIER"

    def test_level_assignment_form(self):
        row = parse_line("NotifierHandler: queued alert level=WARNING")
        assert row["level"] == "WARNING"
        assert row["module"] == "SYSTEM"
        assert row["epoch"] is None

    def test_hit_marker_detected(self):
        assert parse_line("[YARA][MATCH] file matched 21 rules")["hit"] is True
        assert parse_line("[MONITOR][START][SUCCESS] loaded")["hit"] is False

    def test_plain_line_defaults_to_info(self):
        row = parse_line("Task queue depth is 1")
        assert row["level"] == "INFO"
        assert row["module"] == "SYSTEM"
        assert row["time"] == ""


class TestAnalyzeLines:
    def test_all_range_counts_every_line(self):
        result = analyze_lines(SAMPLE_LINES, range_key="all", now=NOW)
        assert result["scanned"] == len(SAMPLE_LINES)
        assert result["matched"] == len(SAMPLE_LINES)
        assert result["hits"] == 2
        assert set(result["levels"]) == set(LEVELS)

    def test_continuation_lines_inherit_the_record_timestamp(self):
        """Runtime records span several lines; only the first carries a stamp."""
        result = analyze_lines(SAMPLE_LINES, range_key="15m", now=NOW)
        by_text = {row["text"]: row for row in result["rows"]}
        notice = by_text["NotifierHandler: queued alert level=WARNING"]
        assert notice["inherited"] is True
        assert notice["time"] == "2026-09-12 11:57:00"
        assert result["undated"] == 0
        assert result["matched"] == len(SAMPLE_LINES)

    def test_undated_leading_lines_are_counted(self):
        lines = ["Task queue depth is 1", f"[{_stamp(1)}] SCAN    [HIT] x.php"]
        result = analyze_lines(lines, range_key="15m", now=NOW)
        assert result["undated"] == 1
        assert result["matched"] == 1

    def test_level_filter(self):
        result = analyze_lines(SAMPLE_LINES, level="WARNING", now=NOW)
        assert result["matched"] == 2
        assert all(row["level"] == "WARNING" for row in result["rows"])

    def test_module_filter(self):
        result = analyze_lines(SAMPLE_LINES, module="YARA", now=NOW)
        assert result["matched"] == 1
        assert result["rows"][0]["module"] == "YARA"

    def test_keyword_terms_must_all_match(self):
        # shell.php appears on the SCAN, STDOUT, QUARANTINE and YARA lines
        assert analyze_lines(SAMPLE_LINES, keyword="shell.php", now=NOW)["matched"] == 4
        assert analyze_lines(SAMPLE_LINES, keyword="shell.php nope", now=NOW)["matched"] == 0

    def test_hits_only(self):
        result = analyze_lines(SAMPLE_LINES, hits_only=True, now=NOW)
        assert result["matched"] == 2
        assert all(row["hit"] for row in result["rows"])

    def test_limit_truncates_newest_kept(self):
        result = analyze_lines(SAMPLE_LINES, limit=3, now=NOW)
        assert result["returned"] == 3
        assert result["truncated"] is True
        assert result["rows"][-1]["text"] == SAMPLE_LINES[-1]

    def test_timeline_buckets_are_returned(self):
        result = analyze_lines(SAMPLE_LINES, range_key="15m", buckets=6, now=NOW)
        assert len(result["timeline"]) == 6
        assert sum(point["total"] for point in result["timeline"]) >= 1

    def test_explicit_window_overrides_range_key(self):
        lower = (NOW - timedelta(minutes=1)).timestamp()
        result = analyze_lines(SAMPLE_LINES, range_key="all", from_epoch=lower, now=NOW)
        assert result["matched"] < len(SAMPLE_LINES)

    def test_range_bounds_helpers(self):
        lower, upper = range_bounds("1h", now=NOW)
        assert upper - lower == pytest.approx(3600)
        assert range_bounds("all", now=NOW)[0] is None


class TestLogAnalyzerRoutes:
    @pytest.fixture(scope="class")
    @classmethod
    def _app(cls):
        os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")
        from anteumbra.interfaces.web.factory import create_app

        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        return app

    @pytest.fixture
    def client(self, _app):
        with _app.test_client() as c:
            with c.session_transaction() as flask_session:
                flask_session["authenticated"] = True
                flask_session["username"] = "admin"
            yield c

    def test_page_renders_filter_controls(self, client):
        resp = client.get("/admin/logs/analyzer")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        for marker in (
            'id="log-rows"',
            'data-action="logs.range"',
            'id="log-keyword"',
            'data-action="logs.live-toggle"',
            'id="log-timeline"',
        ):
            assert marker in body, f"missing {marker}"

    def test_page_is_shell_wrapped_on_navigation(self, client):
        resp = client.get("/admin/logs/analyzer", headers={"Sec-Fetch-Dest": "document"})
        body = resp.get_data(as_text=True)
        assert "app-shell" in body
        assert 'data-initial-path="logs/analyzer"' in body
        assert "logs-view" in body

    def test_data_endpoint_returns_aggregates(self, client):
        resp = client.get("/admin/logs/analyzer/data?range=all&limit=50")
        assert resp.status_code == 200
        payload = resp.get_json()
        for key in ("rows", "scanned", "matched", "levels", "modules", "timeline"):
            assert key in payload, f"missing {key}"
        assert isinstance(payload["rows"], list)

    def test_data_endpoint_honours_filters(self, client):
        payload = client.get("/admin/logs/analyzer/data?level=CRITICAL&limit=20").get_json()
        assert all(row["level"] == "CRITICAL" for row in payload["rows"])

    def test_recent_detections_fragment_renders(self, client):
        resp = client.get("/admin/recent-detections")
        assert resp.status_code == 200
        assert "recent-detections" in resp.get_data(as_text=True)
