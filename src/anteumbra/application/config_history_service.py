"""Config reload history service."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from anteumbra.infrastructure.utils.path_utils import normalize_path

logger = logging.getLogger(__name__)


class ConfigHistoryLogger:
    """Persist and read config hot-reload history."""

    def __init__(self, history_file: str | Path | None = None):
        path = history_file if history_file is not None else "data/config_history.json"
        self.history_file = normalize_path(path)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

        if not self.history_file.exists():
            self._write_data({"history": []})

    def log_reload(
        self,
        config_snapshot: dict[str, Any],
        changed_keys: list[str],
        reload_duration_ms: float,
    ) -> bool:
        """Record a config reload event without storing sensitive values."""
        try:
            data = self._read_data()
            now = datetime.now()
            record = {
                "timestamp": now.isoformat(),
                "timestamp_display": now.strftime("%Y-%m-%d %H:%M:%S"),
                "changed_keys": changed_keys,
                "duration_ms": round(reload_duration_ms, 2),
                "config_summary": {
                    "websites_count": len(config_snapshot.get("website", [])),
                    "notifier_enabled": config_snapshot.get("notifier", {}).get("enabled", False),
                    "yara_rules_count": self._count_yara_rules(),
                    "registry_async_enabled": config_snapshot.get("registry", {}).get("async_save_enabled", False),
                },
                "user_triggered": False,
            }

            data["history"].insert(0, record)
            data["history"] = data["history"][:50]
            self._write_data(data)
            return True
        except Exception:
            logger.exception("Failed to record config reload history")
            return False

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent config reload history records."""
        try:
            data = self._read_data()
            return data.get("history", [])[:limit]
        except Exception:
            logger.exception("Failed to read config reload history")
            return []

    def clear_history(self) -> bool:
        """Clear persisted config reload history."""
        try:
            self._write_data({"history": []})
            return True
        except Exception:
            logger.exception("Failed to clear config reload history")
            return False

    def _read_data(self) -> dict[str, Any]:
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {"history": []}
        if not isinstance(data, dict) or not isinstance(data.get("history"), list):
            return {"history": []}
        return data

    def _write_data(self, data: dict[str, Any]) -> None:
        temp_file = self.history_file.with_suffix(".tmp")
        temp_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp_file.replace(self.history_file)

    def _count_yara_rules(self) -> int:
        try:
            rules_dir = normalize_path("rules/webshell")
            return len(list(rules_dir.glob("*.yar")))
        except Exception:
            logger.debug("Failed to count YARA rules", exc_info=True)
            return 0


ConfigWatcherLogger = ConfigHistoryLogger

_history_logger: ConfigHistoryLogger | None = None


def get_config_history_logger() -> ConfigHistoryLogger:
    """Return the process-wide config history logger."""
    global _history_logger
    if _history_logger is None:
        _history_logger = ConfigHistoryLogger()
    return _history_logger


def get_config_watcher_logger() -> ConfigHistoryLogger:
    """Compatibility alias for legacy callers."""
    return get_config_history_logger()
