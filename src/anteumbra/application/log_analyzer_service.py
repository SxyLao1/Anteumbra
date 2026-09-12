# -*- coding: utf-8 -*-
"""Structured analysis of runtime log lines for the Log Analyzer page.

The runtime writes several dialects into the monitor log:

    [2026-09-12 01:40:09] SCAN    [HIT] E:\\www\\shell.php
    [STDOUT][01:40:09] CRITICAL local_detection -> E:\\www\\shell.php
    [NOTIFIER][LOCAL_ONLY][WARNING] [Anteumbra WARNING] 2026-09-12 01:40:09
    NotifierHandler: queued alert level=WARNING
    Task queue depth is 1

``parse_line`` normalizes all of them into ``{time, level, module, marker,
hit, text}``; ``analyze_lines`` filters and aggregates a batch for the UI.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Iterable

__all__ = ["LEVELS", "RANGE_KEYS", "analyze_lines", "parse_line", "range_bounds"]

LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")

# Presets offered by the analyzer UI: key -> window (None = no lower bound).
RANGE_KEYS: dict[str, timedelta | None] = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}

# Modules the runtime actually emits; the first matching token wins.
MODULES = (
    "MONITOR",
    "MANUAL_SCANNER",
    "SCANNER",
    "SCAN",
    "QUARANTINE",
    "REGISTRY",
    "NOTIFIER",
    "SECURITY",
    "ALERT",
    "YARA",
    "PROFILE",
    "WAL",
    "PLUGIN",
    "SIEM",
    "CONFIG",
    "API",
    "WEB",
    "STDOUT",
)

_MARKERS = ("MATCH", "HIT", "SUCCESS", "FAILED", "FAIL", "START", "STOP", "SKIP", "SAFE")
_LEVEL_WORDS = ("CRITICAL", "ERROR", "WARNING", "WARN", "INFO", "DEBUG")

_FULL_STAMP = re.compile(r"^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
_TIME_ONLY = re.compile(r"^(?:\[[A-Za-z0-9_.:-]{2,24}\])?\[(\d{2}:\d{2}:\d{2})\]")
_ANY_STAMP = re.compile(r"\[?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\]?")
_TAG = re.compile(r"\[([A-Za-z0-9_.:-]{2,24})\]")
_BARE_MODULE = re.compile(r"\b([A-Z][A-Z0-9_]{1,23})\b")
_LEVEL_ASSIGNMENT = re.compile(r"\blevel=(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG)\b")
_SEVERITY_TOKEN = re.compile(r"\b(CRITICAL|ERROR|WARNING|DEBUG)\b")
_STAMP_SEARCH_LIMIT = 160


def _normalize_level(word: str) -> str:
    upper = word.upper()
    return "WARNING" if upper == "WARN" else upper


def _level_from_line(line: str) -> str:
    assigned = _LEVEL_ASSIGNMENT.search(line)
    if assigned:
        return _normalize_level(assigned.group(1))
    for tag in _TAG.findall(line):
        upper = tag.upper()
        if upper in _LEVEL_WORDS:
            return _normalize_level(upper)
    bare = _SEVERITY_TOKEN.search(line)
    if bare:
        return _normalize_level(bare.group(1))
    return "INFO"


def _module_from_line(line: str) -> str:
    for token in _TAG.findall(line):
        upper = token.upper()
        if upper in MODULES:
            return upper
    # "… 2026-09-12 01:40:09] SCAN    [HIT] …" — the module can be a bare token
    # anywhere after the stamp, not only at the very start of the line.
    for match in _BARE_MODULE.finditer(line):
        token = match.group(1)
        if token in MODULES:
            return token
    return "SYSTEM"


def _marker_from_line(line: str) -> str | None:
    for tag in _TAG.findall(line):
        upper = tag.upper()
        if upper in _MARKERS and upper not in _LEVEL_WORDS:
            return upper
    return None


def parse_line(raw_line: str, *, today: datetime | None = None) -> dict[str, Any]:
    """Normalize one log line into the analyzer's row shape.

    Some runtime records carry their timestamp mid-line
    (``[NOTIFIER][LOCAL_ONLY][WARNING] [Anteumbra WARNING] 2026-09-12 …``), and
    their continuation lines carry none at all — those are filled in by
    ``analyze_lines`` from the previous stamped row.
    """
    text = str(raw_line).rstrip("\n")
    when: datetime | None = None
    stamp = _FULL_STAMP.match(text)
    if stamp:
        try:
            when = datetime.strptime(f"{stamp.group(1)} {stamp.group(2)}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            when = None
    else:
        short = _TIME_ONLY.match(text)
        if short:
            base = today or datetime.now()
            try:
                parsed = datetime.strptime(short.group(1), "%H:%M:%S")
                when = base.replace(
                    hour=parsed.hour, minute=parsed.minute, second=parsed.second, microsecond=0
                )
            except ValueError:
                when = None
        else:
            inline = _ANY_STAMP.search(text[:_STAMP_SEARCH_LIMIT])
            if inline:
                try:
                    when = datetime.strptime(
                        f"{inline.group(1)} {inline.group(2)}", "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    when = None
    marker = _marker_from_line(text)
    return {
        "time": when.strftime("%Y-%m-%d %H:%M:%S") if when else "",
        "epoch": when.timestamp() if when else None,
        "inherited": False,
        "level": _level_from_line(text),
        "module": _module_from_line(text),
        "marker": marker,
        "hit": marker in ("MATCH", "HIT"),
        "text": text,
    }


def _inherit_timestamps(rows: list[dict[str, Any]]) -> int:
    """Give continuation lines the timestamp of the record they belong to.

    Returns the number of rows that could not be dated at all (leading lines
    before the first stamped record), which the UI reports separately.
    """
    last_epoch: float | None = None
    last_time = ""
    undated = 0
    for row in rows:
        if row["epoch"] is not None:
            last_epoch = row["epoch"]
            last_time = row["time"]
            continue
        if last_epoch is None:
            undated += 1
            continue
        row["epoch"] = last_epoch
        row["time"] = last_time
        row["inherited"] = True
    return undated


def range_bounds(range_key: str, *, now: datetime | None = None) -> tuple[float | None, float]:
    """Return ``(lower_epoch | None, upper_epoch)`` for a preset range key."""
    reference = now or datetime.now()
    window = RANGE_KEYS.get(str(range_key or "all").lower(), None)
    upper = reference.timestamp()
    if window is None:
        return None, upper
    return (reference - window).timestamp(), upper


def analyze_lines(
    lines: Iterable[str],
    *,
    range_key: str = "all",
    from_epoch: float | None = None,
    to_epoch: float | None = None,
    level: str = "all",
    module: str = "all",
    keyword: str = "",
    hits_only: bool = False,
    limit: int = 500,
    buckets: int = 48,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Filter and aggregate log lines for the analyzer page.

    Undated lines survive only while no time bound is active, so a narrow range
    never hides the runtime's untimestamped notices without saying so.
    """
    parsed = [parse_line(line, today=now) for line in lines]
    scanned = len(parsed)
    undated = _inherit_timestamps(parsed)

    lower, upper = range_bounds(range_key, now=now)
    if from_epoch is not None:
        lower = from_epoch
    if to_epoch is not None:
        upper = to_epoch
    has_time_filter = lower is not None or str(range_key or "all").lower() != "all"

    wanted_level = str(level or "all").upper()
    wanted_module = str(module or "all").upper()
    terms = [term for term in str(keyword or "").lower().split() if term]

    def keep(row: dict[str, Any]) -> bool:
        if has_time_filter:
            epoch = row["epoch"]
            if epoch is None:
                return False
            if lower is not None and epoch < lower:
                return False
            if epoch > upper:
                return False
        if wanted_level != "ALL" and row["level"] != wanted_level:
            return False
        if wanted_module != "ALL" and row["module"] != wanted_module:
            return False
        if hits_only and not row["hit"]:
            return False
        if terms:
            haystack = row["text"].lower()
            if not all(term in haystack for term in terms):
                return False
        return True

    matched = [row for row in parsed if keep(row)]
    capped = max(1, min(int(limit or 500), 2000))
    rows = matched[-capped:]

    level_counts = Counter(row["level"] for row in matched)
    module_counts = Counter(row["module"] for row in matched)
    marker_counts = Counter(row["marker"] for row in matched if row["marker"])

    return {
        "rows": rows,
        "scanned": scanned,
        "matched": len(matched),
        "returned": len(rows),
        "truncated": len(matched) > len(rows),
        "levels": {name: level_counts.get(name, 0) for name in LEVELS},
        "modules": dict(module_counts.most_common(12)),
        "markers": dict(marker_counts.most_common(12)),
        "hits": sum(1 for row in matched if row["hit"]),
        "errors": level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0),
        "warnings": level_counts.get("WARNING", 0),
        "undated": undated,
        "timeline": _timeline(matched, lower=lower, upper=upper, buckets=buckets, now=now),
        "range": {"key": range_key, "from": lower, "to": upper},
    }


def _timeline(
    rows: list[dict[str, Any]],
    *,
    lower: float | None,
    upper: float,
    buckets: int,
    now: datetime | None,
) -> list[dict[str, Any]]:
    """Bucket matched rows over the active window, or over their own span."""
    stamps = [row["epoch"] for row in rows if row["epoch"] is not None]
    if not stamps:
        return []
    start = lower if lower is not None else min(stamps)
    end = upper if upper >= start else max(stamps)
    if end - start < 1:
        end = start + 1
    size = (end - start) / max(1, buckets)
    series = []
    for index in range(buckets):
        bucket_start = start + index * size
        bucket_end = bucket_start + size
        window_rows = [
            row
            for row in rows
            if row["epoch"] is not None and bucket_start <= row["epoch"] < bucket_end
        ]
        series.append(
            {
                "start": bucket_start,
                "label": datetime.fromtimestamp(bucket_start).strftime(
                    "%m-%d %H:%M" if size >= 3600 else "%H:%M"
                ),
                "total": len(window_rows),
                "errors": sum(1 for row in window_rows if row["level"] in ("ERROR", "CRITICAL")),
            }
        )
    return series
