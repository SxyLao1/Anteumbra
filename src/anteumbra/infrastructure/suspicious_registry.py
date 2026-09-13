"""Runtime-owned suspicious-file Registry with atomic JSON persistence."""

from __future__ import annotations

import copy
import json
import logging
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from anteumbra.domain import Repository, registry_records
from anteumbra.domain.runtime import ConfigProviderPort, EventPublisherPort
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.registry_errors import (
    RegistryDataError,
    RegistryPersistenceError,
)
from anteumbra.infrastructure.registry_events import RegistryEventNotifier
from anteumbra.infrastructure.registry_storage import (
    RegistryJsonStore,
    RegistryShadowStore,
    RegistrySqlStore,
    RegistryStorage,
)
from anteumbra.infrastructure.utils.path_utils import path_to_key
from anteumbra.infrastructure.wal_manager import WalManager


class SuspiciousRegistry:
    """Own one Registry dataset and all of its persistence dependencies."""

    _SHADOW_STORAGE_FIELDS = frozenset({"id", "record_id", "raw_json", "created_at", "updated_at"})

    def __init__(
        self,
        path: str | Path,
        *,
        config: ConfigProviderPort,
        wal: WalManager,
        event_publisher: EventPublisherPort,
        change_callback: Callable[[], Any] | None = None,
        shadow_repository: Repository | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.path = Path(path)
        self.backup_path = self.path.with_name(f"{self.path.name}.bak")
        self._config = config
        self._wal = wal
        self._events = event_publisher
        self._change_callback = change_callback
        self._shadow = shadow_repository
        self._logger = logger or logging.getLogger("monitor.suspicious_registry")
        self._json_store = RegistryJsonStore(
            self.path,
            atomic_writer=lambda path, content: self._atomic_write(path, content),
        )
        self._shadow_store = RegistryShadowStore(
            shadow_repository, self._logger, registry_records.record_id
        )
        self._sql_store = (
            RegistrySqlStore(
                shadow_repository,
                self._json_store,
                self._logger,
                registry_records.record_id,
            )
            if shadow_repository is not None
            else None
        )
        self._storage = RegistryStorage(
            json_store=self._json_store,
            shadow_store=self._shadow_store,
            sql_store=self._sql_store,
            logger=self._logger,
            record_id=registry_records.record_id,
            authority_marker=self.path.with_name(f"{self.path.name}.sqlite-authority"),
        )
        self._event_notifier = RegistryEventNotifier(event_publisher, self._logger, change_callback)
        self._lock = threading.RLock()
        records, normalized = self._load_records()
        self._records = records
        if normalized:
            self._persist(records, previous=[])
        elif self._storage.sqlite_authoritative:
            # Keep the readable file in step with the authoritative store even
            # when nothing needed migrating.
            self._storage.snapshot(self._records)

    def add(
        self,
        file_path: str | Path,
        features: list[str],
        first_seen_ip: str | None = None,
        detection_source: str = "passive",
        site_id: str | None = None,
        site_name: str | None = None,
        *,
        site: SiteIdentity | None = None,
        content_hash: str = "",
        alert_emitted: bool = False,
    ) -> None:
        """Create or refresh one detection within its explicit site boundary.

        ``alert_emitted`` records whether this pass raised an alert. When it did
        not, because a standing alert already covers this content, the alert
        state is left alone rather than cleared — that is what keeps a re-scan
        quiet while a file that was deleted and returned is still reported.
        """
        identity = self._resolve_site(file_path, site, site_id, site_name)
        key = path_to_key(file_path)
        now = self._now()
        with self._lock:
            # Mutate in place: copying the whole record list per detection made
            # every write cost grow with the Registry size (measured 19 ms of
            # deepcopy alone at 940 records).  Readers take the lock and copy.
            index = self._find_index(self._records, key, identity.site_id)
            if index is None:
                record = registry_records.create_detection_record(
                    key,
                    features,
                    first_seen_ip,
                    detection_source,
                    identity,
                    now,
                    content_hash,
                    alert_emitted,
                )
                records = [*self._records, record]
            else:
                record = self._records[index]
                records = self._records
                registry_records.refresh_detection_record(
                    record,
                    features,
                    first_seen_ip,
                    detection_source,
                    identity,
                    now,
                    content_hash,
                    alert_emitted,
                )
            self._commit_upsert(
                records,
                record,
                event_type="record_added",
                event_payload={
                    "file_path": key,
                    "features": list(features),
                    "first_seen_ip": first_seen_ip,
                    "detection_source": detection_source,
                    **identity.as_dict(),
                },
            )

    def get_all(
        self,
        include_deleted: bool = False,
        include_false_positive: bool = False,
        site_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return a newest-first defensive snapshot matching the filters."""
        normalized_site_id = self._normalize_site_id(site_id) if site_id else None
        with self._lock:
            return registry_records.project_records(
                self._records,
                include_deleted=include_deleted,
                include_false_positive=include_false_positive,
                site_id=normalized_site_id,
            )

    def get(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return one record resolved within a site, including inactive states."""
        key = path_to_key(file_path)
        target_site = self._site_id_for_lookup(file_path, site_id)
        with self._lock:
            index = self._find_index(self._records, key, target_site)
            return copy.deepcopy(self._records[index]) if index is not None else None

    def is_suspicious(self, file_path: str | Path, site_id: str | None = None) -> bool:
        """Return whether a Registry record exists for the path and site."""
        return self.get(file_path, site_id) is not None

    def mark_alerted(
        self, file_path: str | Path, site_id: str | None = None, content_hash: str = ""
    ) -> bool:
        """Mark one record as having emitted its alert, and for which content."""
        return self._update_record(
            file_path,
            site_id,
            operation="mark_alerted",
            mutate=lambda record: registry_records.mark_alerted(record, content_hash),
        )

    def was_alerted(
        self, file_path: str | Path, content_hash: str, site_id: str | None = None
    ) -> bool:
        """Return whether a standing alert already covers this exact content."""
        record = self.get(file_path, site_id)
        return bool(record) and registry_records.alert_covers_content(record, content_hash)

    def clear_alert_state(self, file_path: str | Path, site_id: str | None = None) -> bool:
        """Re-arm alerting so the next detection of this file reports again."""
        return self._update_record(
            file_path,
            site_id,
            operation="clear_alert",
            mutate=registry_records.clear_alert_state,
        )

    def mark_quarantined(
        self,
        file_path: str | Path,
        quarantine_id: str,
        site_id: str | None = None,
    ) -> bool:
        """Link a Registry record to a quarantine object."""
        if not str(quarantine_id).strip():
            raise ValueError("quarantine_id must not be empty")
        now = self._now()
        return self._update_record(
            file_path,
            site_id,
            operation="mark_quarantined",
            mutate=lambda record: registry_records.mark_quarantined(
                record, str(quarantine_id), now
            ),
            extra={"quarantine_id": str(quarantine_id)},
        )

    def mark_restored(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> bool:
        """Clear quarantine state after a successful restore."""
        now = self._now()
        return self._update_record(
            file_path,
            site_id,
            operation="mark_restored",
            mutate=lambda record: registry_records.mark_restored(record, now),
        )

    def mark_false_positive(
        self,
        file_path: str | Path,
        reason: str = "",
        site_id: str | None = None,
    ) -> bool:
        """Mark one record as a reviewed false positive."""
        now = self._now()
        return self._update_record(
            file_path,
            site_id,
            operation="mark_false_positive",
            mutate=lambda record: registry_records.mark_false_positive(record, str(reason), now),
            extra={"reason": str(reason)},
        )

    def unmark_false_positive(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> bool:
        """Return a reviewed false positive to the active threat set."""
        now = self._now()
        return self._update_record(
            file_path,
            site_id,
            operation="unmark_false_positive",
            mutate=lambda record: registry_records.unmark_false_positive(record, now),
        )

    def increment_access(
        self,
        file_path: str | Path,
        ip: str,
        site_id: str | None = None,
    ) -> None:
        """Increment communication count, creating a site-owned record if absent."""
        identity = self._resolve_site(file_path, None, site_id, None)
        key = path_to_key(file_path)
        with self._lock:
            records = copy.deepcopy(self._records)
            index = self._find_index(records, key, identity.site_id)
            if index is None:
                record = registry_records.create_access_record(key, ip, identity, self._now())
                records.append(record)
            else:
                record = records[index]
                registry_records.increment_access(record, ip)
            self._commit_upsert(
                records,
                record,
                event_type="registry_changed",
                event_payload={
                    "operation": "increment_access",
                    "file_path": key,
                    "ip": ip,
                    **identity.as_dict(),
                },
            )

    def remove(
        self,
        file_path: str | Path,
        site_id: str | None = None,
        *,
        site: SiteIdentity | None = None,
        reason: str = "",
    ) -> bool:
        """Mark a physically removed file without crossing site boundaries.

        Called when the watcher sees the file deleted outside the product (an
        operator in Explorer, a shell command, or an attacker cleaning up).  The
        record is retained and only changes state, so the threat history survives
        the file it describes.
        """
        resolved_site_id = site.site_id if site is not None else site_id
        now = self._now()

        return self._update_record(
            file_path,
            resolved_site_id,
            operation="remove",
            mutate=lambda record: registry_records.mark_removed(record, now, reason),
        )

    def mark_present(
        self,
        file_path: str | Path,
        site_id: str | None = None,
        *,
        site: SiteIdentity | None = None,
    ) -> bool:
        """Clear a previously recorded removal once the path exists again.

        Cheap and idempotent on purpose: watcher events call this for every
        touched path, so only a record stored as missing is worth a write.
        """
        resolved_site_id = site.site_id if site is not None else site_id
        key = path_to_key(file_path)
        target_site = self._site_id_for_lookup(file_path, resolved_site_id)
        with self._lock:
            index = self._find_index(self._records, key, target_site)
            if index is None or bool(self._records[index].get("file_exists", True)):
                return False
        now = self._now()
        return self._update_record(
            file_path,
            resolved_site_id,
            operation="mark_present",
            mutate=lambda record: registry_records.mark_present(record, now),
        )

    def reconcile_filesystem(self, site_id: str | None = None) -> dict[str, int]:
        """Align stored ``file_exists`` with the real filesystem.

        Only filesystem-observed absences are reversed: a record the operator
        soft-deleted has no ``missing_reason`` and is left alone.
        """
        normalized_site_id = self._normalize_site_id(site_id) if site_id else None
        now = self._now()
        counters = {"checked": 0, "marked_missing": 0, "marked_present": 0}
        with self._lock:
            records = copy.deepcopy(self._records)
            changed = False
            for record in records:
                if normalized_site_id is not None and record.get("site_id") != normalized_site_id:
                    continue
                key = record.get("file_path")
                if not key:
                    continue
                counters["checked"] += 1
                try:
                    exists = Path(key).is_file()
                except OSError:
                    continue
                stored = bool(record.get("file_exists", True))
                if stored and not exists:
                    registry_records.mark_removed(record, now, "gone-while-stopped")
                    counters["marked_missing"] += 1
                    changed = True
                elif (
                    not stored
                    and exists
                    and record.get("missing_reason")
                    and not record.get("quarantine_id")
                ):
                    registry_records.mark_present(record, now)
                    counters["marked_present"] += 1
                    changed = True
            if changed:
                self._persist(records, previous=self._records)
                self._records = records
        return counters

    def soft_delete_record(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> bool:
        """Explicitly soft-delete a record while retaining audit history."""
        now = self._now()
        return self._update_record(
            file_path,
            site_id,
            operation="soft_delete",
            mutate=lambda record: registry_records.mark_soft_deleted(record, now),
        )

    def compact(self, compact_days: int | None = None) -> dict[str, int]:
        """Permanently remove old inactive records and return compaction stats."""
        if compact_days is None:
            raw = self._config.get().get("filesizes", {}).get("registry_compact_days", 30)
            try:
                compact_days = int(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid registry_compact_days: {raw!r}") from exc
        if compact_days < 0:
            raise ValueError("compact_days must not be negative")
        cutoff = datetime.now(timezone.utc) - timedelta(days=compact_days)
        with self._lock:
            records = [
                copy.deepcopy(record)
                for record in self._records
                if bool(record.get("file_exists", True))
                or registry_records.parse_timestamp(record.get("detected_at")) > cutoff
            ]
            original_count = len(self._records)
            if len(records) != original_count:
                self._commit_replace_all(
                    records,
                    event_payload={
                        "operation": "compact",
                        "cleaned": original_count - len(records),
                    },
                )
            return {
                "total": original_count,
                "cleaned": original_count - len(records),
                "remaining": len(records),
            }

    def migrate_site_metadata(self) -> int:
        """Re-resolve and persist ownership for historical records."""
        with self._lock:
            records = copy.deepcopy(self._records)
            changed = 0
            for record in records:
                identity = self._config.resolve_site_identity(
                    record["file_path"],
                    site_id=record.get("site_id"),
                    site_name=record.get("site_name"),
                )
                if any(record.get(key) != value for key, value in identity.as_dict().items()):
                    record.update(identity.as_dict())
                    changed += 1
            if changed:
                self._commit_replace_all(
                    records,
                    event_payload={"operation": "migrate_sites", "changed": changed},
                )
            return changed

    def reload(self) -> None:
        """Explicitly discard memory state and reload the authoritative files."""
        with self._lock:
            records, normalized = self._load_records()
            if normalized:
                self._persist(records, previous=self._records)
            self._records = records

    def replay_wal(self) -> int:
        """Replay pending Registry transactions through idempotent final states."""
        return self._wal.replay(self._apply_replay_entry)

    def close(self) -> None:
        """Flush a final snapshot and close whatever storage owns a handle."""
        with self._lock:
            self._storage.close(self._records)

    def _update_record(
        self,
        file_path: str | Path,
        site_id: str | None,
        *,
        operation: str,
        mutate: Callable[[dict[str, Any]], None],
        extra: Mapping[str, Any] | None = None,
    ) -> bool:
        key = path_to_key(file_path)
        target_site = self._site_id_for_lookup(file_path, site_id)
        with self._lock:
            index = self._find_index(self._records, key, target_site)
            if index is None:
                return False
            record = self._records[index]
            mutate(record)
            self._commit_upsert(
                self._records,
                record,
                event_type="registry_changed",
                event_payload={
                    "operation": operation,
                    "file_path": key,
                    "site_id": record["site_id"],
                    "site_name": record["site_name"],
                    **dict(extra or {}),
                },
            )
            return True

    def _commit_upsert(
        self,
        records: list[dict[str, Any]],
        record: dict[str, Any],
        *,
        event_type: str,
        event_payload: Mapping[str, Any],
    ) -> None:
        if self._storage.sqlite_authoritative:
            # SQLite's journal is the durability boundary here; the Registry WAL
            # would only add two fsyncs per detection for a replay nobody needs.
            try:
                self._storage.commit_upsert(record, records)
            except Exception as exc:
                raise RegistryPersistenceError(f"Registry commit failed: {exc}") from exc
            self._records = records
            self._notify(event_type, event_payload)
            return

        transaction_id = self._wal.write_entry(
            "registry_upsert", payload={"record": copy.deepcopy(record)}
        )
        try:
            self._persist(records, previous=self._records)
        except Exception as exc:
            raise RegistryPersistenceError(
                f"Registry commit failed; WAL transaction {transaction_id} is pending"
            ) from exc
        self._records = records
        try:
            self._wal.mark_completed(transaction_id)
        except Exception as exc:
            raise RegistryPersistenceError(
                f"Registry committed but WAL transaction {transaction_id} was not acknowledged"
            ) from exc
        self._notify(event_type, event_payload)

    def _commit_replace_all(
        self,
        records: list[dict[str, Any]],
        *,
        event_payload: Mapping[str, Any],
    ) -> None:
        transaction_id = self._wal.write_entry(
            "registry_replace_all", payload={"records": copy.deepcopy(records)}
        )
        previous = self._records
        try:
            self._persist(records, previous=previous)
        except Exception as exc:
            raise RegistryPersistenceError(
                f"Registry commit failed; WAL transaction {transaction_id} is pending"
            ) from exc
        self._records = records
        try:
            self._wal.mark_completed(transaction_id)
        except Exception as exc:
            raise RegistryPersistenceError(
                f"Registry committed but WAL transaction {transaction_id} was not acknowledged"
            ) from exc
        self._notify("registry_changed", event_payload)

    def _persist(
        self,
        records: list[dict[str, Any]],
        *,
        previous: list[dict[str, Any]],
    ) -> None:
        try:
            self._storage.persist_all(records, previous=previous)
        except OSError as exc:
            raise RegistryPersistenceError(
                f"cannot atomically write Registry at {self.path}: {exc}"
            ) from exc

    def _load_records(self) -> tuple[list[dict[str, Any]], bool]:
        # Stored rows may predate a re-keying and hold the same record twice;
        # the newest copy wins and the next write heals the store.
        return self._storage.load(
            lambda raw: self._normalize_records(raw, on_duplicate="keep-latest")
        )

    def _normalize_records(
        self, raw: Any, *, on_duplicate: str = "error"
    ) -> tuple[list[dict[str, Any]], bool]:
        normalized = isinstance(raw, dict)
        if isinstance(raw, dict):
            values = []
            for key, value in raw.items():
                if not isinstance(value, dict):
                    raise RegistryDataError(f"record {key!r} is not an object")
                values.append({"file_path": key, **value})
        elif isinstance(raw, list):
            values = raw
        else:
            raise RegistryDataError("Registry root must be an array or object")

        records: list[dict[str, Any]] = []
        positions: dict[str, int] = {}
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise RegistryDataError(f"record {index} is not an object")
            if not str(value.get("file_path") or "").strip():
                raise RegistryDataError(f"record {index} has no file_path")
            record = copy.deepcopy(value)
            storage_fields = self._SHADOW_STORAGE_FIELDS.intersection(record)
            if storage_fields:
                normalized = True
                for field in storage_fields:
                    record.pop(field, None)
            key = path_to_key(record["file_path"])
            identity = self._config.resolve_site_identity(
                key,
                site_id=record.get("site_id"),
                site_name=record.get("site_name"),
            )
            record["file_path"] = key
            identity_values = identity.as_dict()
            if any(record.get(field) != value for field, value in identity_values.items()):
                normalized = True
            record.update(identity_values)
            record["features"] = self._normalize_features(record.get("features"))
            for field, default in (
                ("alerted", False),
                ("file_exists", True),
                ("marked_false_positive", False),
            ):
                coerced = bool(record.get(field, default))
                normalized = normalized or record.get(field, default) is not coerced
                record[field] = coerced
            record.setdefault("detected_at", self._now())
            record.setdefault("first_seen_ip", None)
            record.setdefault("communication_count", 0)
            record.setdefault("deleted_at", None)
            record.setdefault("content_hash", "")
            record.setdefault("alerted_hash", "")
            record.setdefault("missing_at", None)
            record.setdefault("missing_reason", "")
            record.setdefault("detection_source", "passive")
            record.setdefault("false_positive_reason", "")
            record.setdefault("false_positive_at", None)
            record.setdefault("quarantine_id", None)
            record_id = self._record_id(record)
            if record_id in positions:
                if on_duplicate == "error":
                    raise RegistryDataError(f"duplicate Registry identity: {record_id}")
                normalized = True
                existing = records[positions[record_id]]
                if str(record.get("detected_at") or "") > str(existing.get("detected_at") or ""):
                    records[positions[record_id]] = record
                self._logger.warning(
                    "Registry kept the newest of two records stored under %s", record_id
                )
                continue
            positions[record_id] = len(records)
            records.append(record)
        return records, normalized

    def _apply_replay_entry(self, entry: dict[str, Any]) -> None:
        operation = str(entry.get("operation", ""))
        payload = entry.get("payload") or {}
        with self._lock:
            if operation == "registry_upsert":
                normalized, _ = self._normalize_records([payload["record"]])
                record = normalized[0]
                records = copy.deepcopy(self._records)
                index = self._find_index(records, record["file_path"], record["site_id"])
                if index is None:
                    records.append(record)
                else:
                    records[index] = record
                self._persist(records, previous=self._records)
                self._records = records
                return
            if operation == "registry_replace_all":
                records, _ = self._normalize_records(payload["records"])
                self._persist(records, previous=self._records)
                self._records = records
                return
            self._apply_legacy_replay(entry)

    def _apply_legacy_replay(self, entry: dict[str, Any]) -> None:
        operation = str(entry.get("operation", "")).lower()
        file_path = entry.get("file_path")
        if not file_path:
            raise RegistryDataError("legacy WAL entry has no file_path")
        identity = self._config.resolve_site_identity(str(file_path))
        key = path_to_key(file_path)
        records = copy.deepcopy(self._records)
        index = self._find_index(records, key, identity.site_id)
        if operation == "add":
            if index is None:
                records.append(
                    {
                        "file_path": key,
                        "detected_at": self._now(),
                        "features": self._normalize_features(entry.get("features")),
                        "alerted": False,
                        "file_exists": True,
                        "first_seen_ip": entry.get("ip"),
                        "communication_count": 0,
                        "deleted_at": None,
                        "detection_source": "passive",
                        "marked_false_positive": False,
                        "false_positive_reason": "",
                        "false_positive_at": None,
                        "quarantine_id": None,
                        **identity.as_dict(),
                    }
                )
            else:
                records[index]["features"] = self._normalize_features(entry.get("features"))
                records[index]["file_exists"] = True
        elif operation == "increment":
            if index is None:
                raise RegistryDataError("legacy increment target does not exist")
            records[index]["communication_count"] = (
                int(records[index].get("communication_count", 0)) + 1
            )
        elif operation == "remove":
            if index is None:
                raise RegistryDataError("legacy remove target does not exist")
            records[index]["file_exists"] = False
            records[index]["deleted_at"] = self._now()
        elif operation == "alerted":
            if index is None:
                raise RegistryDataError("legacy alerted target does not exist")
            records[index]["alerted"] = True
        else:
            raise RegistryDataError(f"unknown legacy WAL operation: {operation}")
        records, _ = self._normalize_records(records)
        self._persist(records, previous=self._records)
        self._records = records

    def _notify(self, event_type: str, payload: Mapping[str, Any]) -> None:
        self._event_notifier.notify(event_type, payload)

    def _resolve_site(
        self,
        file_path: str | Path,
        site: SiteIdentity | None,
        site_id: str | None,
        site_name: str | None,
    ) -> SiteIdentity:
        if site is not None:
            return site
        return self._config.resolve_site_identity(
            str(file_path), site_id=site_id, site_name=site_name
        )

    def _site_id_for_lookup(self, file_path: str | Path, site_id: str | None) -> str:
        if site_id:
            return self._normalize_site_id(site_id)
        return self._config.resolve_site_identity(str(file_path)).site_id

    @staticmethod
    def _find_index(records: list[dict[str, Any]], file_path: str, site_id: str) -> int | None:
        for index, record in enumerate(records):
            if record.get("file_path") == file_path and record.get("site_id") == site_id:
                return index
        return None

    @staticmethod
    def _record_id(record: Mapping[str, Any]) -> str:
        return registry_records.record_id(record)

    @staticmethod
    def _normalize_site_id(site_id: str) -> str:
        normalized = str(site_id).strip().lower()
        if not normalized:
            raise ValueError("site_id must not be empty")
        return normalized

    @staticmethod
    def _normalize_features(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return [value] if value else []
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        return [str(value)]

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        """Compatibility injection point for atomic JSON write failures."""
        RegistryJsonStore._atomic_write(path, content)
