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
from anteumbra.infrastructure.registry_errors import RegistryDataError


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


class RegistrySqlStore:
    """Authoritative SQLite record storage with periodic JSON snapshots.

    One row per change, so a write costs the same whether the Registry holds a
    thousand records or ten thousand.  Rewriting the whole file per detection
    cost 28 ms at 940 records and grew linearly with the record count (measured
    206 ms at 10,000), all of it inside the Registry lock.
    """

    def __init__(
        self,
        repository: Repository,
        json_store: "RegistryJsonStore",
        logger: logging.Logger,
        record_id: Callable[[Mapping[str, Any]], str],
        *,
        snapshot_every: int = 1000,
    ) -> None:
        self._repository = repository
        self._json_store = json_store
        self._logger = logger
        self._record_id = record_id
        self._snapshot_every = max(1, snapshot_every)
        self._pending = 0

    def load(self) -> list[dict[str, Any]]:
        """Return every stored record; an empty list means nothing is stored yet."""
        return [
            dict(row)
            for row in self._repository.list_all(limit=1_000_000)
            if isinstance(row, Mapping)
        ]

    def upsert(self, record: Mapping[str, Any]) -> bool:
        """Store one record; returns whether a JSON snapshot is now due."""
        self._repository.save(self._record_id(record), dict(record))
        self._pending += 1
        if self._pending < self._snapshot_every:
            return False
        self._pending = 0
        return True

    def replace_all(self, records: list[dict[str, Any]]) -> None:
        """Rewrite every row and drop the ones that are gone (cold paths)."""
        current = {self._record_id(record) for record in records}
        for row in self.load():
            # Delete by the stored key, never a recomputed one: a row saved
            # under an older identity would otherwise survive the rewrite.
            stored_id = str(row.get("record_id") or "").strip()
            if not stored_id:
                try:
                    stored_id = self._record_id(row)
                except (KeyError, TypeError):
                    continue
            if stored_id not in current:
                self._repository.delete(stored_id)
        for record in records:
            self._repository.save(self._record_id(record), dict(record))
        self._pending = 0

    def snapshot(self, records: list[dict[str, Any]]) -> None:
        """Write the readable JSON file operators and scripts inspect."""
        try:
            self._json_store.persist(records)
        except OSError:
            self._logger.warning(
                "Registry JSON snapshot failed; SQLite still holds every record",
                exc_info=True,
            )

    def close(self, records: list[dict[str, Any]]) -> None:
        self.snapshot(records)
        close = getattr(self._repository, "close", None)
        if callable(close):
            close()


class RegistryStorage:
    """Own how Registry records reach disk.

    * SQLite-authoritative (a repository is configured, e.g. backend "both"):
      one row per change; the JSON file stays as a periodic snapshot.
    * JSON-only (the default deployment): the whole file is rewritten per
      change, exactly as before.
    """

    def __init__(
        self,
        *,
        json_store: RegistryJsonStore,
        shadow_store: RegistryShadowStore,
        sql_store: RegistrySqlStore | None,
        logger: logging.Logger,
        record_id: Callable[[Mapping[str, Any]], str],
        authority_marker: Path | None = None,
    ) -> None:
        self._json_store = json_store
        self._shadow_store = shadow_store
        self._sql_store = sql_store
        self._logger = logger
        self._record_id = record_id
        self._marker = authority_marker
        self._authority = bool(authority_marker is not None and authority_marker.exists())

    @property
    def sqlite_authoritative(self) -> bool:
        """True once SQLite holds the records and is the store of record."""
        return self._sql_store is not None and self._authority

    def claim_authority(self) -> None:
        """Record that SQLite now holds every record, so it can be trusted.

        The switch is explicit and one-time on purpose: a database that happens
        to contain rows — a leftover test file, a half-written store — must never
        silently become the source of truth for a Registry whose readable
        snapshot holds more.
        """
        self._authority = self._sql_store is not None
        if self._marker is None or not self._authority:
            return
        try:
            self._marker.parent.mkdir(parents=True, exist_ok=True)
            self._marker.write_text("sqlite\n", encoding="utf-8")
        except OSError:
            self._logger.warning(
                "Registry could not record its SQLite authority marker", exc_info=True
            )

    def load(self, normalize: Callable[[Any], tuple[list[dict[str, Any]], bool]]):
        """Load records, migrating the JSON snapshot on the first SQLite start.

        The stored rows win once they are authoritative, but any record only the
        JSON snapshot knows about is adopted rather than dropped: a
        half-populated store must never erase history still sitting in the file.
        """
        if self.sqlite_authoritative:
            rows = self._sqlite_rows()
            if rows:
                records, normalized = normalize(rows)
                kept, adopted = self._adopt_json_only_records(records, normalize)
                return kept, normalized or adopted
            self._logger.warning(
                "Registry SQLite store is marked authoritative but empty; re-reading JSON"
            )

        records, normalized = self._load_json(normalize)
        if self._sql_store is not None and records:
            self._logger.info(
                "Registry migrated %d records from the JSON snapshot into SQLite",
                len(records),
            )
            return records, True
        if self._sql_store is not None:
            self.claim_authority()
        return records, normalized

    def _adopt_json_only_records(self, records, normalize):
        known = {self._record_id(record) for record in records}
        kept, normalized = records, False
        for candidate in self._json_candidates():
            try:
                extra, _ = normalize(self._json_store.read(candidate))
            except (OSError, json.JSONDecodeError, RegistryDataError):
                return kept, normalized
            adopted = [record for record in extra if self._record_id(record) not in known]
            if adopted:
                self._logger.warning(
                    "Registry adopted %d record(s) present only in the JSON snapshot",
                    len(adopted),
                )
                kept = kept + adopted
                normalized = True
            return kept, normalized
        return kept, normalized

    def _json_candidates(self) -> tuple[Path, ...]:
        return tuple(path for path, _source in self._json_store.candidates())

    def _sqlite_rows(self) -> list[dict[str, Any]]:
        if self._sql_store is None:  # pragma: no cover - guarded by callers
            return []
        try:
            return self._sql_store.load()
        except Exception:
            self._logger.warning(
                "Registry SQLite read failed; falling back to the JSON snapshot",
                exc_info=True,
            )
            return []

    def _load_json(self, normalize) -> tuple[list[dict[str, Any]], bool]:
        failures: list[str] = []
        backup_path = self._json_store.backup_path
        for candidate, source in self._json_store.candidates():
            if not candidate.exists():
                continue
            try:
                records, normalized = normalize(self._json_store.read(candidate))
            except (OSError, json.JSONDecodeError, RegistryDataError) as exc:
                failures.append(f"{source}: {exc}")
                continue
            if candidate == backup_path:
                self._logger.warning("Registry primary recovered from backup %s", candidate)
                normalized = True
            return records, normalized

        try:
            shadow_records = self._shadow_store.recover()
            if shadow_records:
                records, _ = normalize(shadow_records)
                self._logger.warning(
                    "Registry recovered %d records from SQLite shadow", len(records)
                )
                return records, True
        except Exception as exc:
            failures.append(f"shadow: {exc}")

        if failures:
            raise RegistryDataError(
                "Registry has no valid recovery source: " + "; ".join(failures)
            )
        return [], False

    def snapshot(self, records: list[dict[str, Any]]) -> None:
        """Refresh the readable JSON file without touching SQLite rows."""
        if self._sql_store is None:
            return
        self._sql_store.snapshot(records)

    def persist_all(
        self,
        records: list[dict[str, Any]],
        *,
        previous: list[dict[str, Any]],
    ) -> None:
        """Write every record (cold paths: compaction, migration, replay)."""
        if self._sql_store is not None:
            self._sql_store.replace_all(records)
            self._sql_store.snapshot(records)
            self.claim_authority()
            return
        self._json_store.persist(records)
        self._shadow_store.sync(records, previous)

    def commit_upsert(self, record: Mapping[str, Any], records: list[dict[str, Any]]) -> None:
        """Write one record (hot path)."""
        if self._sql_store is None:  # pragma: no cover - caller branches first
            return
        if self._sql_store.upsert(record):
            self._sql_store.snapshot(records)

    def close(self, records: list[dict[str, Any]]) -> None:
        if self._sql_store is not None:
            self._sql_store.close(records)
            return
        self._shadow_store.close()


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
                self._repository.save(self._record_id(record), copy.deepcopy(record))
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
