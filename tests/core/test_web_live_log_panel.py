# -*- coding: utf-8 -*-
"""The live log panel is a tail at selected severities, not a raw log dump.

It used to render the newest 1000 lines at *every* level, so a DEBUG/WARNING
storm (one line per scanned file) filled the panel and it looked like the scanner
never stopped.  Only the chosen severities are shown now, and the full record
stays available on the Log Analyzer page.
"""

from __future__ import annotations

import os

import pytest

from anteumbra.interfaces.web.log_history import (
    DEFAULT_LIVE_LEVELS,
    LIVE_LOG_LINES,
    allowed_levels,
    filter_levels,
    parse_level,
)

INFO = "[2026-09-13 14:36:41,000] INFO - [site=default] [SCAN][FILE][HIT] 开始全量扫描: access.log"
CRITICAL = "[2026-09-13 14:36:41,100] CRITICAL - [site=default] [SCAN][FILE][HIT] x.php"
WARNING = "[2026-09-13 14:36:41,200] WARNING - [site=default] quarantine_skipped -> x.php"
DEBUG = "[2026-09-13 14:36:41,300] DEBUG - [site=default] [MONITOR][SKIP][DUPLICATE] 跳过目录修改: uploads"
ERROR = "[2026-09-13 14:36:41,400] ERROR - [site=default] something broke"


class TestParseLevel:
    @pytest.mark.parametrize(
        "line,expected",
        [
            (INFO, "INFO"),
            (CRITICAL, "CRITICAL"),
            (WARNING, "WARNING"),
            (DEBUG, "DEBUG"),
            (ERROR, "ERROR"),
            ("a line with no level at all", "INFO"),
            ("[site=default] WARN tolerated", "WARNING"),
        ],
    )
    def test_levels_are_read_from_the_line(self, line, expected):
        assert parse_level(line) == expected


class TestAllowedLevels:
    def test_default_is_info_and_critical(self):
        assert set(DEFAULT_LIVE_LEVELS) == {"INFO", "CRITICAL"}

    def test_debug_is_never_surfaced_even_if_configured(self):
        assert "DEBUG" not in allowed_levels({"web_admin": {"sse_log_levels": ["INFO", "DEBUG"]}})

    def test_config_overrides_the_default(self):
        levels = allowed_levels({"web_admin": {"sse_log_levels": ["CRITICAL"]}})
        assert levels == {"CRITICAL"}

    def test_missing_config_falls_back_to_the_default(self):
        assert allowed_levels({}) == set(DEFAULT_LIVE_LEVELS)
        assert allowed_levels(None) == set(DEFAULT_LIVE_LEVELS)


class TestFilterLevels:
    def test_debug_and_warning_are_dropped_by_default(self):
        kept = filter_levels([INFO, CRITICAL, WARNING, DEBUG, ERROR], DEFAULT_LIVE_LEVELS)
        assert kept == [INFO, CRITICAL]

    def test_none_means_everything(self):
        everything = [INFO, CRITICAL, WARNING, DEBUG, ERROR]
        assert filter_levels(everything, None) == everything

    def test_the_newest_lines_are_kept_not_the_oldest(self):
        lines = [f"[2026-09-13 14:36:4{i},000] DEBUG - noise {i}" for i in range(5)]
        lines.append(CRITICAL)
        kept = filter_levels(lines, DEFAULT_LIVE_LEVELS)
        assert kept == [CRITICAL]


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


class TestHistoryEndpoint:
    def test_history_carries_no_debug_or_warning_lines(self, _app):
        import re

        with _app.test_client() as client:
            with client.session_transaction() as flask_session:
                flask_session["authenticated"] = True
                flask_session["username"] = "admin"
            body = client.get("/admin/logs/history").get_data(as_text=True)

        rendered = re.findall(r'<div class="log-line[^"]*">(.*?)</div>', body)
        assert rendered, "history endpoint returned nothing"
        assert len(rendered) <= LIVE_LOG_LINES
        noisy = [line for line in rendered if "DEBUG" in line or "WARNING" in line]
        assert not noisy, f"history leaked non-selected severities: {noisy[:3]}"
