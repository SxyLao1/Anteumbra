"""Runtime-owned configuration reload history."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class ConfigHistoryLogger:
    """Persist reload history at paths supplied by the composition root."""

    def __init__(
        self,
        history_file: str | Path,
        *,
        rules_dir: str | Path | None = None,
    ) -> None:
        self.history_file = Path(history_file).expanduser().resolve()
        self.rules_dir = (
            Path(rules_dir).expanduser().resolve()
            if rules_dir is not None
            else None
        )
        self._lock = threading.RLock()
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.history_file.exists():
            self._write_data({"history": []})

    def log_reload(
        self,
        config_snapshot: dict[str, Any],
        changed_keys: list[str],
        reload_duration_ms: float,
    ) -> bool:
        """Record a reload event without storing sensitive values."""
        try:
            with self._lock:
                data = self._read_data()
                now = datetime.now()
                record = {
                    "timestamp": now.isoformat(),
                    "timestamp_display": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "changed_keys": list(changed_keys),
                    "duration_ms": round(reload_duration_ms, 2),
                    "config_summary": {
                        "websites_count": self._website_count(config_snapshot),
                        "notifier_enabled": config_snapshot.get(
                            "notifier", {}
                        ).get("enabled", False),
                        "yara_rules_count": self._count_yara_rules(),
                        "registry_async_enabled": config_snapshot.get(
                            "registry", {}
                        ).get("async_save_enabled", False),
                    },
                    "user_triggered": False,
                }
                data["history"].insert(0, record)
                data["history"] = data["history"][:50]
                self._write_data(data)
            return True
        except (OSError, TypeError, ValueError):
            logger.exception("Failed to record config reload history")
            return False

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent config reload history records."""
        try:
            with self._lock:
                data = self._read_data()
                return data.get("history", [])[: max(0, int(limit))]
        except (OSError, TypeError, ValueError):
            logger.exception("Failed to read config reload history")
            return []

    def clear_history(self) -> bool:
        """Clear persisted config reload history."""
        try:
            with self._lock:
                self._write_data({"history": []})
            return True
        except OSError:
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
        temp_file = self.history_file.with_suffix(
            f"{self.history_file.suffix}.tmp"
        )
        temp_file.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temp_file.replace(self.history_file)

    def _count_yara_rules(self) -> int:
        if self.rules_dir is None:
            return 0
        try:
            return sum(1 for _path in self.rules_dir.glob("*.yar"))
        except OSError:
            logger.debug("Failed to count YARA rules", exc_info=True)
            return 0

    @staticmethod
    def _website_count(config_snapshot: Mapping[str, Any]) -> int:
        websites = config_snapshot.get("website", [])
        if isinstance(websites, Mapping):
            return 1
        if isinstance(websites, list):
            return len(websites)
        return 0


__all__ = ["ConfigHistoryLogger"]
