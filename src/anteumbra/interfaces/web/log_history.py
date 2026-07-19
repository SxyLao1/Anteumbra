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
_LOG_TIMESTAMP = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)\]"
)


def collect_log_history(
    runtime: RuntimeContainer,
    *,
    websites: Iterable[Any] | None = None,
    limit: int = 1000,
    log: logging.Logger | None = None,
) -> list[str]:
    """Collect bounded site logs and SSE history through runtime-owned ports."""
    if limit < 1:
        raise ValueError("limit must be positive")
    reporter = log or logger
    selected = runtime.config.get_enabled_websites() if websites is None else websites
    lines: list[str] = []

    for website in selected:
        site = SiteIdentity.from_values(website.site_id, website.name)
        for path in runtime.logging.get_site_history_paths(site):
            try:
                lines.extend(_qualify_site_lines(_tail_lines(path), site.site_id))
            except OSError:
                reporter.warning(
                    "Failed to read site monitor history %s",
                    path,
                    exc_info=True,
                )

    try:
        lines.extend(runtime.sse.get_log_buffer())
    except (OSError, RuntimeError, TypeError, ValueError):
        reporter.warning("Failed to read SSE log history", exc_info=True)

    return _chronological_tail(
        (line for line in lines if "[SSE]" not in line),
        limit,
    )


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
        parts.append(
            f'<div class="log-line {_level_class(line)}">{html.escape(line)}</div>'
        )
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
    upper = line.upper()
    if "CRITICAL" in upper:
        return "critical"
    if "ERROR" in upper:
        return "error"
    if "WARNING" in upper or "WARN" in upper:
        return "warn"
    if "DEBUG" in upper:
        return "debug"
    return "info"


__all__ = ["collect_log_history", "render_log_history"]
