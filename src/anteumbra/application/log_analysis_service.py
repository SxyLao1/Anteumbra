"""Application service for configured web access-log analysis."""

from __future__ import annotations

from typing import Any, Callable, Iterable


class AccessLogAnalysisService:
    """Analyze configured access logs through injected adapters."""

    def __init__(
        self,
        path_resolver: Callable[[str], Any],
        engine_factory: Callable[[], Any],
    ) -> None:
        self._path_resolver = path_resolver
        self._engine_factory = engine_factory

    def analyze(self, websites: Iterable[Any]) -> list[dict[str, Any]]:
        """Analyze each enabled website's configured access log independently."""
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
                result.update(status="missing", error="access_log_path is empty")
                results.append(result)
                continue
            try:
                log_path = self._path_resolver(raw_path)
                if log_path is None:
                    result.update(
                        status="missing",
                        error="log file does not exist or wildcard has no matches",
                    )
                    results.append(result)
                    continue
                engine = self._engine_factory()
                events = engine.feed_file(log_path)
                result.update(
                    selected_path=str(log_path),
                    status="ok",
                    stats=engine.get_stats(),
                    events=events[-200:],
                )
            except Exception as exc:
                result.update(status="error", error=str(exc))
            results.append(result)
        return results
