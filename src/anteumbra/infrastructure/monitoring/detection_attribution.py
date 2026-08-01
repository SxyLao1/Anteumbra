"""Infrastructure adapters for attributing a local detection to a source IP."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from anteumbra.infrastructure.monitoring import log_analyzer

DEFAULT_SOURCE_IP = "127.0.0.1"
LOCAL_SOURCE_IPS = {DEFAULT_SOURCE_IP, "::1"}


def resolve_first_seen_ip(
    file_path: Path,
    *,
    website: Any,
    logger: logging.Logger,
    waf_log: Path = Path("data/waf_events.jsonl"),
    analyzer_factory: Callable[..., Any] | None = None,
) -> str:
    """Resolve WAF first, then an explicitly enabled access-log analyzer."""
    source_ip = _resolve_from_waf(file_path, waf_log, logger)
    if source_ip != DEFAULT_SOURCE_IP:
        return source_ip

    log_config = getattr(website, "log_config", {}) or {}
    if not log_config.get("log_monitor_enabled", False):
        return DEFAULT_SOURCE_IP

    return _resolve_from_access_log(
        file_path,
        website,
        logger,
        analyzer_factory=analyzer_factory or log_analyzer.LogAnalyzer,
    )


def _resolve_from_waf(
    file_path: Path,
    waf_log: Path,
    logger: logging.Logger,
) -> str:
    if not waf_log.exists():
        return DEFAULT_SOURCE_IP

    try:
        lines = waf_log.read_text(encoding="utf-8").splitlines()
        now = datetime.now()
        for line in reversed(lines[-200:]):
            source_ip, delta = _match_recent_waf_event(line, now)
            if source_ip is None:
                continue
            logger.info(
                "[MONITOR] Resolved attacker IP from WAF: %s -> %s (time-window match, Δ=%.1fs)",
                source_ip,
                file_path.name.lower(),
                delta,
            )
            return source_ip
    except Exception:
        logger.debug("Failed to parse WAF event log for IP resolution", exc_info=True)
    return DEFAULT_SOURCE_IP


def _match_recent_waf_event(line: str, now: datetime) -> tuple[str | None, float]:
    if not line.strip():
        return None, 0.0
    event = json.loads(line.strip())
    source_ip = event.get("src_ip", "")
    if not source_ip or source_ip in LOCAL_SOURCE_IPS:
        return None, 0.0
    timestamp = event.get("timestamp", "")
    if not timestamp:
        return None, 0.0

    try:
        event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        delta = abs((now - event_time).total_seconds())
    except (ValueError, TypeError, AttributeError):
        return None, 0.0
    if delta > 15:
        return None, 0.0

    method = event.get("method", "") or event.get("http_method", "")
    if method.upper() not in ("POST", "PUT", ""):
        return None, 0.0
    return source_ip, delta


def _resolve_from_access_log(
    file_path: Path,
    website: Any,
    logger: logging.Logger,
    *,
    analyzer_factory: Callable[..., Any],
) -> str:
    try:
        result = analyzer_factory(website, logger).analyze_shell_access(file_path)
        if not result or not result.get("suspicious_ips"):
            return DEFAULT_SOURCE_IP

        suspicious_ips = result["suspicious_ips"]
        best_ip = max(suspicious_ips, key=suspicious_ips.get)
        if not best_ip or best_ip in LOCAL_SOURCE_IPS:
            return DEFAULT_SOURCE_IP
        logger.info(
            "[MONITOR] Resolved attacker IP from access log: %s -> %s (hits: %s, log: %s)",
            best_ip,
            file_path.name.lower(),
            suspicious_ips[best_ip],
            result.get("log_path", "?"),
        )
        return best_ip
    except Exception:
        logger.debug("LogAnalyzer failed to resolve attacker IP", exc_info=True)
        return DEFAULT_SOURCE_IP


__all__ = ["DEFAULT_SOURCE_IP", "resolve_first_seen_ip"]
