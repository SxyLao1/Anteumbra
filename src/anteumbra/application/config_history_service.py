"""Runtime-owned configuration reload history."""

from __future__ import annotations

import json
import logging
import re
import shutil
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: A backup is only ever addressed by the name this module produced, so the
#: pattern doubles as the path-traversal guard for the admin revision routes.
BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.\d{8}-\d{6}(?:-\d+)?\.bak$")


class ConfigHistoryLogger:
    """Persist reload history at paths supplied by the composition root."""

    def __init__(
        self,
        history_file: str | Path,
        *,
        rules_dir: str | Path | None = None,
    ) -> None:
        self.history_file = Path(history_file).expanduser().resolve()
        self.rules_dir = Path(rules_dir).expanduser().resolve() if rules_dir is not None else None
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
                    "config_summary": self._snapshot_summary(config_snapshot),
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

    def record_change(
        self,
        changed_keys: list[str],
        *,
        source: str = "ui",
        detail: str = "",
        duration_ms: float | None = None,
        config_snapshot: Mapping[str, Any] | None = None,
        record_id: str = "",
    ) -> str:
        """Record an operator-driven configuration change.

        ``log_reload`` describes the runtime noticing a new file; this describes
        someone *deciding* to change one, which is what a version history has to
        show ("who changed what, when").  The record carries only key names - a
        config value can be a secret, and this file is a plain JSON document.
        Returns the record id (its timestamp) so the caller can point at it.
        """
        try:
            with self._lock:
                data = self._read_data()
                now = datetime.now()
                identifier = record_id or now.isoformat()
                record = {
                    "id": identifier,
                    "timestamp": identifier,
                    "timestamp_display": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "changed_keys": [str(key) for key in changed_keys],
                    "changed_count": len(changed_keys),
                    "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
                    "source": str(source or "ui"),
                    "detail": str(detail or ""),
                    "user_triggered": True,
                    "config_summary": self._snapshot_summary(config_snapshot),
                }
                data["history"].insert(0, record)
                data["history"] = data["history"][:200]
                self._write_data(data)
            return identifier
        except (OSError, TypeError, ValueError):
            logger.exception("Failed to record config change history")
            return ""

    def _snapshot_summary(self, config_snapshot: Mapping[str, Any] | None) -> dict[str, Any]:
        if not isinstance(config_snapshot, Mapping):
            return {}
        return {
            "websites_count": self._website_count(config_snapshot),
            "notifier_enabled": config_snapshot.get("notifier", {}).get("enabled", False),
            "yara_rules_count": self._count_yara_rules(),
            "registry_async_enabled": config_snapshot.get("registry", {}).get(
                "async_save_enabled", False
            ),
        }

    def _read_data(self) -> dict[str, Any]:
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {"history": []}
        if not isinstance(data, dict) or not isinstance(data.get("history"), list):
            return {"history": []}
        return data

    def _write_data(self, data: dict[str, Any]) -> None:
        temp_file = self.history_file.with_suffix(f"{self.history_file.suffix}.tmp")
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


@dataclass(frozen=True)
class ConfigRevision:
    """One entry of the configuration version history.

    ``kind`` says what the entry can actually answer: a ``backup`` owns the file
    content, so it can be diffed, restored and downloaded; a ``change`` is a
    history record and only remembers *which* keys moved, so the UI must say so
    instead of pretending it can restore something it never stored.
    """

    revision_id: str
    kind: str
    timestamp: str
    display_time: str
    source: str
    changed_count: int
    changed_keys: tuple[str, ...]
    restoreable: bool
    detail: str = ""
    size_bytes: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "revision_id": self.revision_id,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "display_time": self.display_time,
            "source": self.source,
            "changed_count": self.changed_count,
            "changed_keys": list(self.changed_keys),
            "restoreable": self.restoreable,
            "detail": self.detail,
            "size_bytes": self.size_bytes,
        }


class ConfigRevisionStore:
    """Timestamped ``config.toml`` backups plus the recorded change history.

    Two independent sources describe the same file over time.  The runtime logs
    a record whenever it reloads a config it did not write, and every write from
    the admin UI keeps a ``config.toml.<stamp>.bak`` copy beside the file.  Only
    the copies hold content, so the store reports which entries can be restored
    rather than letting the UI offer an action it cannot complete.
    """

    #: How many backups are kept; older ones are pruned on write.
    KEEP_BACKUPS = 60

    def __init__(
        self,
        config_path: str | Path,
        history: ConfigHistoryLogger | None = None,
        *,
        keep: int | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.history = history
        self.keep = self.KEEP_BACKUPS if keep is None else max(1, int(keep))
        self._lock = threading.RLock()

    # -- backups -----------------------------------------------------------

    def backup_suffix(self) -> str:
        return f"{self.config_path.name}."

    def backup_path(self) -> Path:
        """A free, timestamped sibling path for a config backup."""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        candidate = self.config_path.with_name(f"{self.config_path.name}.{stamp}.bak")
        index = 1
        while candidate.exists():
            candidate = self.config_path.with_name(f"{self.config_path.name}.{stamp}-{index}.bak")
            index += 1
        return candidate

    def backup_current(self) -> Path | None:
        """Copy the live file aside before it is replaced."""
        if not self.config_path.exists():
            return None
        target = self.backup_path()
        shutil.copy2(self.config_path, target)
        self._prune()
        return target

    def _prune(self) -> None:
        backups = sorted(
            (path for path in self._backup_files()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for stale in backups[self.keep :]:
            try:
                stale.unlink()
            except OSError:
                logger.debug("Failed to prune config backup %s", stale, exc_info=True)

    def _backup_files(self) -> list[Path]:
        try:
            return [
                path
                for path in self.config_path.parent.glob(f"{self.config_path.name}.*.bak")
                if path.is_file() and BACKUP_NAME_RE.match(path.name)
            ]
        except OSError:
            logger.debug("Failed to list config backups", exc_info=True)
            return []

    def is_backup_name(self, name: str) -> bool:
        """Whether ``name`` is a backup of this config (and not a path)."""
        if not name or "/" in name or "\\" in name or not BACKUP_NAME_RE.match(name):
            return False
        return name.startswith(self.backup_suffix())

    def resolve(self, revision_id: str) -> Path | None:
        """The backup a ``backup:<name>`` revision id points at, if it exists."""
        prefix, _, name = str(revision_id).partition(":")
        if prefix != "backup" or not self.is_backup_name(name):
            return None
        path = self.config_path.with_name(name)
        return path if path.is_file() else None

    def read(self, revision_id: str) -> str | None:
        """The backup's content, byte for byte.

        Read as bytes on purpose: ``read_text`` translates ``\\r\\n`` to ``\\n``,
        and a restore writes this text straight back - a Windows checkout would
        come out of a rollback with every line ending rewritten.
        """
        path = self.resolve(revision_id)
        if path is None:
            return None
        try:
            return path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            logger.debug("Failed to read config backup %s", path, exc_info=True)
            return None

    # -- merged history ----------------------------------------------------

    def list_revisions(self, limit: int = 100) -> list[ConfigRevision]:
        """Every revision, newest first: recorded changes and file copies."""
        revisions: list[ConfigRevision] = []
        for path in self._backup_files():
            try:
                stat = path.stat()
            except OSError:  # pragma: no cover - the file vanished mid-listing
                continue
            stamp = _stamp_from_name(path.name, self.config_path.name)
            revisions.append(
                ConfigRevision(
                    revision_id=f"backup:{path.name}",
                    kind="backup",
                    timestamp=stamp or datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    display_time=_display_time(stamp, stat.st_mtime),
                    # The plugin-control endpoint and this editor are the only
                    # writers that keep a copy, so a copy means a UI write.
                    source="ui",
                    changed_count=0,
                    changed_keys=(),
                    restoreable=True,
                    size_bytes=stat.st_size,
                )
            )
        for record in self.history.get_history(limit=1000) if self.history else []:
            if not isinstance(record, Mapping):
                continue
            keys = [str(key) for key in record.get("changed_keys", []) or []]
            source = str(record.get("source") or "").strip()
            if not source:
                # Records written before this field existed: the runtime logs
                # its own reloads, so anything else was an operator action.
                source = "ui" if record.get("user_triggered") else "runtime"
            revisions.append(
                ConfigRevision(
                    revision_id=f"change:{record.get('timestamp', '')}",
                    kind="change",
                    timestamp=str(record.get("timestamp", "")),
                    display_time=str(
                        record.get("timestamp_display") or record.get("timestamp", "")
                    ),
                    source=source,
                    changed_count=int(record.get("changed_count") or len(keys)),
                    changed_keys=tuple(keys),
                    restoreable=False,
                    detail=str(record.get("detail") or ""),
                )
            )
        revisions.sort(key=lambda item: item.timestamp, reverse=True)
        return revisions[: max(0, int(limit))]


def _stamp_from_name(name: str, config_name: str) -> str:
    """``config.toml.20260812-101112.bak`` -> ``2026-08-12T10:11:12``."""
    prefix = f"{config_name}."
    if not name.startswith(prefix) or not name.endswith(".bak"):
        return ""
    raw = name[len(prefix) : -len(".bak")]
    raw = raw.split("-", 2)
    if len(raw) < 2:
        return ""
    try:
        parsed = datetime.strptime(f"{raw[0]}-{raw[1]}", "%Y%m%d-%H%M%S")
    except ValueError:
        return ""
    return parsed.isoformat()


def _display_time(stamp: str, fallback: float) -> str:
    if stamp:
        try:
            return datetime.fromisoformat(stamp).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:  # pragma: no cover - stamp comes from strftime
            pass
    return datetime.fromtimestamp(fallback).strftime("%Y-%m-%d %H:%M:%S")


__all__ = ["BACKUP_NAME_RE", "ConfigHistoryLogger", "ConfigRevision", "ConfigRevisionStore"]
