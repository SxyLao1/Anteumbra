"""Runtime-owned write-ahead log for Registry recovery."""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from anteumbra.domain.runtime import EventPublisherPort


class WalError(RuntimeError):
    """Base class for WAL persistence failures."""


class WalWriteError(WalError):
    """Raised when a WAL record cannot be durably written."""


class WalReplayError(WalError):
    """Raised when replay cannot safely consume the WAL."""


class WalManager:
    """Own one Registry WAL and its complete recovery lifecycle.

    Operations and completion markers are append-only. A transaction that was
    persisted to the Registry but not marked complete may be replayed, so the
    replay callback must apply the supplied final state idempotently.
    """

    _FORMAT_VERSION = 2

    def __init__(
        self,
        path: str | Path,
        *,
        settings_loader: Callable[[], Mapping[str, Any]] | None = None,
        event_publisher: EventPublisherPort | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.path = Path(path)
        self.dead_letter_path = self.path.with_name(
            f"{self.path.stem}.dead_letter{self.path.suffix}"
        )
        self._settings_loader = settings_loader
        self._events = event_publisher
        self._logger = logger or logging.getLogger("monitor.wal_manager")
        self._lock = threading.RLock()
        self._replay_lock = threading.Lock()
        self._replaying = False

    @property
    def is_replaying(self) -> bool:
        """Return whether this manager is currently replaying entries."""
        with self._lock:
            return self._replaying

    def write_entry(
        self,
        operation: str,
        file_path: str | Path | None = None,
        features: list[str] | None = None,
        ip: str | None = None,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> str:
        """Durably append one pending operation and return its transaction ID."""
        operation = str(operation).strip()
        if not operation:
            raise ValueError("WAL operation must not be empty")

        transaction_id = uuid.uuid4().hex
        entry: dict[str, Any] = {
            "version": self._FORMAT_VERSION,
            "kind": "operation",
            "transaction_id": transaction_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "pid": os.getpid(),
            "thread_id": threading.get_ident(),
        }
        if file_path is not None:
            entry["file_path"] = str(file_path)
        if features is not None:
            entry["features"] = list(features)
        if ip is not None:
            entry["ip"] = ip
        if payload is not None:
            entry["payload"] = dict(payload)

        self._append_json(self.path, entry)
        return transaction_id

    def mark_completed(self, transaction_id: str) -> None:
        """Durably acknowledge a previously appended transaction."""
        if not transaction_id:
            raise ValueError("transaction_id must not be empty")
        marker = {
            "version": self._FORMAT_VERSION,
            "kind": "completed",
            "transaction_id": transaction_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append_json(self.path, marker)
        self._rotate_if_needed()

    def read_entries(self, *, pending_only: bool = False) -> list[dict[str, Any]]:
        """Return defensive copies of valid operation records."""
        with self._lock:
            records, _ = self._read_records()
            operations, completed = self._split_records(records)
            if pending_only:
                operations = [
                    entry
                    for entry in operations
                    if entry["transaction_id"] not in completed
                ]
            return [dict(entry) for entry in operations]

    def replay(
        self,
        callbacks: Mapping[str, Callable[[dict[str, Any]], None]]
        | Callable[[dict[str, Any]], None],
    ) -> int:
        """Replay pending entries once and dead-letter every poison record.

        A callback exception is treated as a poison message: the original entry
        and error are durably copied to the dead-letter file, then the entry is
        acknowledged so the next process start cannot loop over it forever.
        """
        with self._replay_lock:
            with self._lock:
                self._replaying = True
            try:
                records, malformed = self._read_records()
                for raw_line, error in malformed:
                    self._write_dead_letter(
                        {"raw_line": raw_line},
                        reason="malformed_record",
                        error=error,
                    )

                operations, completed = self._split_records(records)
                pending = [
                    entry
                    for entry in operations
                    if entry["transaction_id"] not in completed
                ]
                recovered = 0
                for entry in pending:
                    try:
                        callback = (
                            callbacks.get(entry["operation"])
                            if isinstance(callbacks, Mapping)
                            else callbacks
                        )
                        if callback is None:
                            raise KeyError(f"unknown WAL operation: {entry['operation']}")
                        callback(dict(entry))
                    except Exception as exc:
                        self._logger.error(
                            "WAL transaction %s moved to dead letter: %s",
                            entry["transaction_id"],
                            exc,
                            exc_info=True,
                        )
                        self._write_dead_letter(
                            entry,
                            reason="replay_failed",
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    else:
                        recovered += 1
                    self.mark_completed(entry["transaction_id"])

                if records or malformed:
                    self.archive_current_wal(allow_malformed=True)
                self._emit("wal_replayed", {"recovered_count": recovered})
                return recovered
            except WalError:
                raise
            except Exception as exc:
                raise WalReplayError(f"WAL replay failed: {exc}") from exc
            finally:
                with self._lock:
                    self._replaying = False

    def archive_current_wal(self, *, allow_malformed: bool = False) -> Path | None:
        """Archive a fully acknowledged WAL and create a fresh empty file."""
        with self._lock:
            if not self.path.exists() or self.path.stat().st_size == 0:
                return None
            records, malformed = self._read_records()
            operations, completed = self._split_records(records)
            pending_ids = {
                entry["transaction_id"]
                for entry in operations
                if entry["transaction_id"] not in completed
            }
            if pending_ids:
                raise WalWriteError(
                    "refusing to archive WAL with pending transactions: "
                    + ", ".join(sorted(pending_ids)[:5])
                )
            if malformed and not allow_malformed:
                raise WalWriteError("refusing to archive WAL with malformed records")

            archive = self._next_archive_path()
            try:
                self.path.replace(archive)
                self._write_header()
            except OSError as exc:
                raise WalWriteError(f"cannot archive WAL {self.path}: {exc}") from exc
            self._cleanup_archives()
            self._emit("wal_archived", {"archive_path": str(archive)})
            return archive

    def get_info(self) -> dict[str, Any]:
        """Return current file information and pending transaction count."""
        with self._lock:
            if not self.path.exists():
                return {}
            stat = self.path.stat()
            return {
                "name": self.path.name,
                "path": str(self.path),
                "size_mb": round(stat.st_size / 1024 / 1024, 2),
                "mtime": stat.st_mtime,
                "pending": len(self.read_entries(pending_only=True)),
                "dead_letter_path": str(self.dead_letter_path),
            }

    def list_archives(self) -> list[dict[str, Any]]:
        """List archived WAL files, newest first."""
        with self._lock:
            if not self.path.parent.exists():
                return []
            archives: list[dict[str, Any]] = []
            for archive in self.path.parent.glob(f"{self.path.name}.*"):
                if archive == self.dead_letter_path:
                    continue
                try:
                    stat = archive.stat()
                except OSError as exc:
                    self._logger.warning("Cannot stat WAL archive %s: %s", archive, exc)
                    continue
                archives.append(
                    {
                        "name": archive.name,
                        "size_mb": round(stat.st_size / 1024 / 1024, 2),
                        "mtime": stat.st_mtime,
                    }
                )
            return sorted(archives, key=lambda item: item["mtime"], reverse=True)

    def get_status(self) -> tuple[str, str, float]:
        """Return the status level, display text, and current size in MB."""
        info = self.get_info()
        if not info:
            return "normal", "WAL ready (0.0MB)", 0.0
        size_mb = float(info["size_mb"])
        threshold = self._settings()["rotate_threshold_mb"]
        status = "normal" if size_mb < threshold else "warning"
        text = (
            f"WAL active ({size_mb:.1f}MB)"
            if status == "normal"
            else f"WAL near rotation threshold ({size_mb:.1f}MB)"
        )
        return status, text, size_mb

    def _append_json(self, path: Path, value: Mapping[str, Any]) -> None:
        with self._lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8", buffering=1) as handle:
                    handle.write(json.dumps(dict(value), ensure_ascii=False) + "\n")
                    handle.flush()
                    if sys.platform != "win32":
                        os.fsync(handle.fileno())
            except (OSError, TypeError, ValueError) as exc:
                raise WalWriteError(f"cannot append WAL record to {path}: {exc}") from exc

    def _read_records(
        self,
    ) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
        if not self.path.exists():
            return [], []
        records: list[dict[str, Any]] = []
        malformed: list[tuple[str, str]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise WalReplayError(f"cannot read WAL {self.path}: {exc}") from exc

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                value = json.loads(line)
                records.append(self._normalize_record(value, line_number))
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                malformed.append((raw_line, f"line {line_number}: {exc}"))
        return records, malformed

    def _normalize_record(self, value: Any, line_number: int) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError("record must be a JSON object")
        kind = value.get("kind")
        if kind == "completed":
            transaction_id = str(value["transaction_id"]).strip()
            if not transaction_id:
                raise ValueError("empty completion transaction_id")
            return dict(value, transaction_id=transaction_id)
        if kind == "operation":
            transaction_id = str(value["transaction_id"]).strip()
            operation = str(value["operation"]).strip()
            if not transaction_id or not operation:
                raise ValueError("empty operation transaction metadata")
            return dict(
                value,
                transaction_id=transaction_id,
                operation=operation,
            )

        # Legacy records had no kind or transaction ID. A deterministic ID
        # keeps them replayable once without changing their payload shape.
        operation = str(value.get("operation", "")).strip()
        if not operation:
            raise KeyError("operation")
        transaction_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{self.path}:{line_number}:{json.dumps(value, sort_keys=True)}",
        ).hex
        return {
            **value,
            "version": 1,
            "kind": "operation",
            "transaction_id": transaction_id,
            "operation": operation,
        }

    @staticmethod
    def _split_records(
        records: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], set[str]]:
        operations = [record for record in records if record.get("kind") == "operation"]
        completed = {
            str(record["transaction_id"])
            for record in records
            if record.get("kind") == "completed"
        }
        return operations, completed

    def _write_dead_letter(
        self,
        entry: Mapping[str, Any],
        *,
        reason: str,
        error: str,
    ) -> None:
        envelope = {
            "dead_lettered_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "error": error,
            "entry": dict(entry),
        }
        self._append_json(self.dead_letter_path, envelope)
        self._emit("wal_dead_lettered", {"reason": reason, "error": error})

    def _write_header(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                f"# WAL started at {datetime.now(timezone.utc).isoformat()}\n",
                encoding="utf-8",
            )
        except OSError as exc:
            raise WalWriteError(f"cannot initialize WAL {self.path}: {exc}") from exc

    def _next_archive_path(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        candidate = self.path.with_name(f"{self.path.name}.{stamp}")
        counter = 1
        while candidate.exists():
            candidate = self.path.with_name(
                f"{self.path.name}.{stamp}.{counter:03d}"
            )
            counter += 1
        return candidate

    def _rotate_if_needed(self) -> None:
        with self._lock:
            if self._replaying or not self.path.exists():
                return
            threshold = self._settings()["rotate_threshold_mb"] * 1024 * 1024
            if self.path.stat().st_size <= threshold:
                return
            if self.read_entries(pending_only=True):
                return
            self.archive_current_wal()

    def _cleanup_archives(self) -> None:
        settings = self._settings()
        cutoff = time.time() - settings["retention_days"] * 86400
        archives = []
        for archive in self.path.parent.glob(f"{self.path.name}.*"):
            try:
                if archive.stat().st_mtime < cutoff:
                    archive.unlink()
                else:
                    archives.append(archive)
            except OSError as exc:
                self._logger.warning("Cannot clean WAL archive %s: %s", archive, exc)
        archives.sort(key=lambda item: item.stat().st_mtime, reverse=True)
        for archive in archives[settings["max_archives"] :]:
            try:
                archive.unlink()
            except OSError as exc:
                self._logger.warning("Cannot remove WAL archive %s: %s", archive, exc)

    def _settings(self) -> dict[str, float | int]:
        raw: Mapping[str, Any] = {}
        if self._settings_loader is not None:
            raw = self._settings_loader()
        try:
            threshold = max(0.01, float(raw.get("wal_rotate_threshold_mb", 10)))
            retention = max(1, int(raw.get("wal_cleanup_days", 7)))
            max_archives = max(1, int(raw.get("wal_cleanup_count", 20)))
        except (TypeError, ValueError) as exc:
            raise WalError(f"invalid WAL settings: {exc}") from exc
        return {
            "rotate_threshold_mb": threshold,
            "retention_days": retention,
            "max_archives": max_archives,
        }

    def _emit(self, event_type: str, extra: Mapping[str, Any]) -> None:
        if self._events is None:
            return
        try:
            self._events.publish(
                event_type,
                "wal_manager",
                {"event_type": event_type, **dict(extra)},
            )
        except Exception:
            self._logger.warning("WAL event publish failed: %s", event_type, exc_info=True)
