"""Application service for configured web access-log analysis."""

from __future__ import annotations

from typing import Any, Iterable


def analyze_access_logs(websites: Iterable[Any]) -> list[dict[str, Any]]:
    """Analyze each enabled website's configured access log independently."""
    from anteumbra.infrastructure.detection.log_heuristic import LogHeuristicEngine
    from anteumbra.infrastructure.monitoring.log_analyzer import resolve_access_log_path

    results: list[dict[str, Any]] = []
    for website in websites:
        name = str(getattr(website, "name", "Unknown Website"))
        config = dict(getattr(website, "log_config", {}) or {})
        raw_path = str(config.get("access_log_path", "")).strip()
        result: dict[str, Any] = {
            "website": name,
            "configured_path": raw_path,
            "selected_path": "",
            "status": "disabled",
            "stats": {},
            "events": [],
            "error": "",
        }

        if not config.get("log_monitor_enabled", False):
            results.append(result)
            continue
        if not raw_path:
            result["status"] = "missing"
            result["error"] = "access_log_path is empty"
            results.append(result)
            continue

        try:
            log_path = resolve_access_log_path(raw_path)
            if log_path is None:
                result["status"] = "missing"
                result["error"] = "log file does not exist or wildcard has no matches"
                results.append(result)
                continue

            engine = LogHeuristicEngine()
            events = engine.feed_file(log_path)
            result.update({
                "selected_path": str(log_path),
                "status": "ok",
                "stats": engine.get_stats(),
                "events": events[-200:],
            })
        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)
        results.append(result)

    return results
