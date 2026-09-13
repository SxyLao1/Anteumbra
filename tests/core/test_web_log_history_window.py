# -*- coding: utf-8 -*-
"""The live panel must actually deliver the tail it promises.

A fixed read window looked fine while the newest bytes of the log were INFO
lines.  Once the analyzer's per-file steps became DEBUG, the last 500 KB of a
busy log held barely half of ``LIVE_LOG_LINES`` matching lines and the panel
silently showed a short list.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from anteumbra.interfaces.web.log_history import (
    DEFAULT_LIVE_LEVELS,
    LIVE_LOG_LINES,
    LOG_READ_WINDOWS,
    collect_log_history,
)


class _LoggingStub:
    def __init__(self, paths: list[Path]):
        self._paths = paths

    def get_site_history_paths(self, _site):
        return tuple(self._paths)


class _ConfigStub:
    def __init__(self, websites):
        self._websites = websites

    def get_enabled_websites(self):
        return list(self._websites)


class _SseStub:
    def __init__(self, lines=()):
        self._lines = list(lines)

    def get_log_buffer(self):
        return list(self._lines)


def _runtime(log_path: Path, *, sse_lines=()):
    website = SimpleNamespace(site_id="default", name="Default Website")
    return SimpleNamespace(
        config=_ConfigStub([website]),
        logging=_LoggingStub([log_path]),
        sse=_SseStub(sse_lines),
    )


def _write_log(path: Path, *, info_lines: int, debug_lines: int) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index in range(info_lines):
            handle.write(
                f"[2026-09-13 10:00:{index % 60:02d},000] INFO - [site=default] hit {index}\n"
            )
        for index in range(debug_lines):
            handle.write(
                f"[2026-09-13 14:00:{index % 60:02d},000] DEBUG - [site=default] step {index}\n"
            )


def test_read_windows_grow_and_end_at_the_cap():
    assert LOG_READ_WINDOWS[0] < LOG_READ_WINDOWS[-1]
    assert tuple(sorted(LOG_READ_WINDOWS)) == LOG_READ_WINDOWS


def test_panel_is_filled_even_when_the_newest_window_is_debug_heavy(tmp_path):
    log_path = tmp_path / "monitor.log"
    # The newest ~1.5 MB are DEBUG-only, so the first window cannot fill the
    # panel and the reader has to grow.
    _write_log(log_path, info_lines=2000, debug_lines=15000)
    assert log_path.stat().st_size > LOG_READ_WINDOWS[0]

    lines = collect_log_history(
        _runtime(log_path), limit=LIVE_LOG_LINES, levels=DEFAULT_LIVE_LEVELS
    )

    assert len(lines) == LIVE_LOG_LINES
    assert not [line for line in lines if "DEBUG" in line]
    assert all(" INFO " in line for line in lines)


def test_history_is_still_capped_at_the_requested_limit(tmp_path):
    log_path = tmp_path / "monitor.log"
    _write_log(log_path, info_lines=4000, debug_lines=0)

    lines = collect_log_history(_runtime(log_path), limit=250, levels=DEFAULT_LIVE_LEVELS)

    assert len(lines) == 250


def test_sse_lines_are_removed_after_being_counted(tmp_path):
    log_path = tmp_path / "monitor.log"
    _write_log(log_path, info_lines=10, debug_lines=0)
    runtime = _runtime(log_path, sse_lines=["[SSE] streamed INFO noise"])

    lines = collect_log_history(runtime, limit=LIVE_LOG_LINES, levels=DEFAULT_LIVE_LEVELS)

    assert lines
    assert not [line for line in lines if "[SSE]" in line]


def test_unreadable_history_does_not_break_the_panel(tmp_path):
    missing = tmp_path / "absent.log"

    lines = collect_log_history(_runtime(missing), limit=LIVE_LOG_LINES, levels=DEFAULT_LIVE_LEVELS)

    assert lines == []
