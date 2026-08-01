"""JSON authority and best-effort shadow adapters for SuspiciousRegistry."""

from __future__ import annotations

import copy
import json
import logging
import os
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from anteumbra.domain import Repository


class RegistryJsonStore:
    """Read and atomically replace the primary and backup JSON snapshots."""

    def __init__(
        self,
        path: Path,
        *,
        atomic_writer: Callable[[Path, str], None] | None = None,
    ) -> None:
        self.path = path
        self.backup_path = path.with_name(f"{path.name}.bak")
        self._atomic_writer = atomic_writer or self._atomic_write

    def candidates(self) -> tuple[tuple[Path, str], ...]:
        return ((self.path, "primary"), (self.backup_path, "backup"))

    @staticmethod
    def read(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))

    def persist(self, records: list[dict[str, Any]]) -> None:
        serialized = json.dumps(records, ensure_ascii=False, indent=2)
        self._atomic_writer(self.backup_path, serialized)
        self._atomic_writer(self.path, serialized)

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{threading.get_ident()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                if sys.platform != "win32":
                    os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


class RegistryShadowStore:
    """Synchronize a recoverable SQLite shadow without owning authority."""

    def __init__(
        self,
        repository: Repository | None,
        logger: logging.Logger,
        record_id: Callable[[Mapping[str, Any]], str],
    ) -> None:
        self._repository = repository
        self._logger = logger
        self._record_id = record_id

    def sync(
        self,
        records: list[dict[str, Any]],
        previous: list[dict[str, Any]],
    ) -> None:
        if self._repository is None:
            return
        current_ids = {self._record_id(record) for record in records}
        previous_ids = {self._record_id(record) for record in previous}
        try:
            shadow_ids: set[str] = set()
            for shadow_record in self._repository.list_all(limit=1_000_000):
                if not isinstance(shadow_record, Mapping):
                    continue
                shadow_id = str(shadow_record.get("record_id") or "").strip()
                if not shadow_id:
                    try:
                        shadow_id = self._record_id(shadow_record)
                    except (KeyError, TypeError):
                        continue
                shadow_ids.add(shadow_id)
            for stale_id in (previous_ids | shadow_ids) - current_ids:
                self._repository.delete(stale_id)
            for record in records:
                self._repository.save(
                    self._record_id(record), copy.deepcopy(record)
                )
        except Exception:
            self._logger.warning(
                "Registry SQLite shadow synchronization failed; JSON remains authoritative",
                exc_info=True,
            )

    def recover(self) -> list[dict[str, Any]]:
        if self._repository is None:
            return []
        return self._repository.list_all(limit=999_999)

    def close(self) -> None:
        close = getattr(self._repository, "close", None)
        if callable(close):
            close()
