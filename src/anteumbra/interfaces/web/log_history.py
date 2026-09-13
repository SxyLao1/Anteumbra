"""Runtime-backed monitor log collection and HTML rendering."""

from __future__ import annotations

import html
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.domain.site import SiteIdentity

logger = logging.getLogger(__name__)
_LOG_TIMESTAMP = re.compile(r"^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)\]")
_LEVEL = re.compile(r"\b(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\b")

# The live panel is a tail, not an analysis surface: it shows this set and the
# full record is read on the Log Analyzer page.  Overridable per deployment via
# web_admin.sse_log_levels.
DEFAULT_LIVE_LEVELS: tuple[str, ...] = ("INFO", "CRITICAL")

# How many lines the live panel holds.  The shell, the history endpoint and the
# client-side append all use this one number so the panel does not silently
# shrink or grow as it switches from the initial load to the stream.
LIVE_LOG_LINES = 1000

# How much of a site log to read, from the end.  A fixed small window looked
# right until the newest part of the log was DEBUG-heavy (the analyzer's
# per-file steps are DEBUG by design): 500 KB then held ~570 INFO/CRITICAL
# lines, so a panel that promises 1000 showed half that.  The window grows
# until the tail can be filled, and the last entry is the hard cap.
LOG_READ_WINDOWS: tuple[int, ...] = (512 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024)


def parse_level(line: str) -> str:
    """Return the severity of one log line, defaulting to INFO."""
    match = _LEVEL.search(line.upper())
    if not match:
        return "INFO"
    level = match.group(1)
    return "WARNING" if level == "WARN" else level


def allowed_levels(
    config: Any | None = None,
    *,
    default: Iterable[str] = DEFAULT_LIVE_LEVELS,
) -> set[str]:
    """Resolve the levels the live panel shows for this deployment."""
    levels = default
    if config is not None:
        try:
            raw = config.get("web_admin", {}).get("sse_log_levels")
        except AttributeError:
            raw = None
        if raw:
            levels = raw
    resolved = {str(level).upper() for level in levels}
    # DEBUG is never surfaced here even if listed; it is the flood source.
    resolved.discard("DEBUG")
    resolved.discard("TRACE")
    return resolved


def filter_levels(lines: Iterable[str], levels: Iterable[str] | None) -> list[str]:
    """Keep only the requested severities; ``None`` keeps everything."""
    if levels is None:
        return list(lines)
    wanted = {str(level).upper() for level in levels}
    return [line for line in lines if parse_level(line) in wanted]


def collect_log_history(
    runtime: RuntimeContainer,
    *,
    websites: Iterable[Any] | None = None,
    limit: int = 1000,
    levels: Iterable[str] | None = None,
    log: logging.Logger | None = None,
) -> list[str]:
    """Collect bounded site logs and SSE history through runtime-owned ports.

    Reading grows through ``LOG_READ_WINDOWS`` until the filtered, de-duplicated
    tail actually reaches ``limit``: the panel promises a full tail of the newest
    lines at the requested severities, and the newest bytes of a log are not
    guaranteed to hold that many.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    reporter = log or logger
    selected = list(runtime.config.get_enabled_websites() if websites is None else websites)
    files = _history_files(runtime, selected)
    buffered = _sse_history(runtime, reporter)

    tail: list[str] = []
    for window in LOG_READ_WINDOWS:
        candidates = _site_history(files, window, reporter)
        candidates.extend(buffered)
        # Filter and de-duplicate before taking the tail so the panel is filled
        # with the newest lines at the requested severities rather than with
        # whatever happened to be last.
        tail = _chronological_tail(
            filter_levels((line for line in candidates if "[SSE]" not in line), levels),
            limit,
        )
        if len(tail) >= limit:
            break
    return tail


def _history_files(
    runtime: RuntimeContainer,
    selected: Iterable[Any],
) -> list[tuple[SiteIdentity, Path]]:
    """Resolve each site's history paths once, however often they are read."""
    files: list[tuple[SiteIdentity, Path]] = []
    for website in selected:
        site = SiteIdentity.from_values(website.site_id, website.name)
        files.extend((site, Path(path)) for path in runtime.logging.get_site_history_paths(site))
    return files


def _site_history(
    files: Iterable[tuple[SiteIdentity, Path]],
    window: int,
    reporter: logging.Logger,
) -> list[str]:
    lines: list[str] = []
    for site, path in files:
        try:
            lines.extend(_qualify_site_lines(_tail_lines(path, window), site.site_id))
        except OSError:
            reporter.warning(
                "Failed to read site monitor history %s",
                path,
                exc_info=True,
            )
    return lines


def _sse_history(runtime: RuntimeContainer, reporter: logging.Logger) -> list[str]:
    try:
        return list(runtime.sse.get_log_buffer())
    except (OSError, RuntimeError, TypeError, ValueError):
        reporter.warning("Failed to read SSE log history", exc_info=True)
        return []


def render_log_history(
    lines: Iterable[str],
    *,
    empty_message: str | None = None,
) -> str:
    """Render escaped log lines with presentation-only severity classes."""
    parts: list[str] = []
    for raw_line in lines:
        line = str(raw_line).strip()
        if not line or "[SSE]" in line:
            continue
        parts.append(f'<div class="log-line {_level_class(line)}">{html.escape(line)}</div>')
    if parts:
        return "".join(parts)
    if empty_message is None:
        return ""
    return f'<div class="log-line info">{html.escape(empty_message)}</div>'


def _tail_lines(path: Path, max_bytes: int = 500 * 1024) -> list[str]:
    with path.open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        start = max(0, size - max_bytes)
        stream.seek(start)
        content = stream.read()
    if start:
        _, separator, content = content.partition(b"\n")
        if not separator:
            return []
    return content.decode("utf-8", errors="ignore").splitlines()


def _qualify_site_lines(lines: Iterable[str], site_id: str) -> list[str]:
    marker = f"[site={site_id}]"
    qualified: list[str] = []
    for line in lines:
        if "[site=" in line.lower():
            qualified.append(line)
            continue
        prefix, separator, message = line.partition(" - ")
        if separator:
            qualified.append(f"{prefix}{separator}{marker} {message}")
        else:
            qualified.append(f"{marker} {line}")
    return qualified


def _chronological_tail(lines: Iterable[str], limit: int) -> list[str]:
    unique = list(dict.fromkeys(lines))
    timestamped: list[tuple[str, int, str]] = []
    unstructured: list[str] = []
    for index, line in enumerate(unique):
        match = _LOG_TIMESTAMP.match(line)
        if match:
            timestamped.append((match.group(1), index, line))
        else:
            unstructured.append(line)
    ordered = [line for _, _, line in sorted(timestamped)]
    ordered.extend(unstructured)
    return ordered[-limit:]


def _level_class(line: str) -> str:
    return {
        "CRITICAL": "critical",
        "ERROR": "error",
        "WARNING": "warn",
        "DEBUG": "debug",
        "TRACE": "debug",
    }.get(parse_level(line), "info")


__all__ = [
    "DEFAULT_LIVE_LEVELS",
    "LIVE_LOG_LINES",
    "LOG_READ_WINDOWS",
    "allowed_levels",
    "collect_log_history",
    "filter_levels",
    "parse_level",
    "render_log_history",
]
