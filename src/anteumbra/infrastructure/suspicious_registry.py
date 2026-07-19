"""Runtime-owned suspicious-file Registry with atomic JSON persistence."""

from __future__ import annotations

import copy
import json
import logging
import os
import sys
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from anteumbra.domain import Repository
from anteumbra.domain.runtime import ConfigProviderPort, EventPublisherPort
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.utils.path_utils import path_to_key
from anteumbra.infrastructure.wal_manager import WalManager


class RegistryError(RuntimeError):
    """Base class for Registry failures."""


class RegistryDataError(RegistryError):
    """Raised when no valid authoritative or recovery data can be loaded."""


class RegistryPersistenceError(RegistryError):
    """Raised when a Registry mutation cannot be durably persisted."""


class SuspiciousRegistry:
    """Own one Registry dataset and all of its persistence dependencies."""

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
        self._lock = threading.RLock()
        records, normalized = self._load_records()
        self._records = records
        if normalized:
            self._persist(records, previous=[])

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
    ) -> None:
        """Create or refresh one detection within its explicit site boundary."""
        identity = self._resolve_site(file_path, site, site_id, site_name)
        key = path_to_key(file_path)
        now = self._now()
        with self._lock:
            records = copy.deepcopy(self._records)
            index = self._find_index(records, key, identity.site_id)
            if index is None:
                record = {
                    "file_path": key,
                    "detected_at": now,
                    "features": list(features),
                    "alerted": False,
                    "file_exists": True,
                    "first_seen_ip": first_seen_ip,
                    "communication_count": 0,
                    "deleted_at": None,
                    "detection_source": detection_source,
                    "marked_false_positive": False,
                    "false_positive_reason": "",
                    "false_positive_at": None,
                    "quarantine_id": None,
                    **identity.as_dict(),
                }
                records.append(record)
            else:
                record = records[index]
                existing_source = str(record.get("detection_source") or "passive")
                record.update(
                    {
                        "file_exists": True,
                        "deleted_at": None,
                        "alerted": False,
                        "communication_count": 0,
                        "first_seen_ip": first_seen_ip
                        if first_seen_ip
                        else record.get("first_seen_ip"),
                        "detected_at": now,
                        "features": list(features),
                        "detection_source": detection_source
                        if detection_source == "active"
                        else existing_source,
                        **identity.as_dict(),
                    }
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
            records = [
                copy.deepcopy(record)
                for record in self._records
                if (include_deleted or bool(record.get("file_exists", True)))
                and (
                    include_false_positive
                    or not bool(record.get("marked_false_positive", False))
                )
                and (
                    normalized_site_id is None
                    or record.get("site_id") == normalized_site_id
                )
            ]
        records.sort(key=lambda item: str(item.get("detected_at", "")), reverse=True)
        return records

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

    def mark_alerted(self, file_path: str | Path, site_id: str | None = None) -> bool:
        """Mark one record as having emitted its alert."""
        return self._update_record(
            file_path,
            site_id,
            operation="mark_alerted",
            mutate=lambda record: record.update(alerted=True),
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
            mutate=lambda record: record.update(
                file_exists=False,
                quarantine_id=str(quarantine_id),
                quarantined_at=now,
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
            mutate=lambda record: record.update(
                file_exists=True,
                quarantine_id=None,
                restored_at=now,
                deleted_at=None,
            ),
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
            mutate=lambda record: record.update(
                marked_false_positive=True,
                false_positive_at=now,
                false_positive_reason=str(reason),
            ),
            extra={"reason": str(reason)},
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
                record = {
                    "file_path": key,
                    "detected_at": self._now(),
                    "features": ["AUTO_CREATED_BY_ACCESS"],
                    "alerted": False,
                    "file_exists": True,
                    "first_seen_ip": ip,
                    "communication_count": 1,
                    "deleted_at": None,
                    "detection_source": "log_heuristic",
                    "marked_false_positive": False,
                    "false_positive_reason": "",
                    "false_positive_at": None,
                    "quarantine_id": None,
                    **identity.as_dict(),
                }
                records.append(record)
            else:
                record = records[index]
                record["communication_count"] = int(
                    record.get("communication_count", 0)
                ) + 1
                if not record.get("first_seen_ip"):
                    record["first_seen_ip"] = ip
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
    ) -> bool:
        """Mark a physically removed file without crossing site boundaries."""
        resolved_site_id = site.site_id if site is not None else site_id
        now = self._now()

        def mutate(record: dict[str, Any]) -> None:
            record["file_exists"] = False
            if not record.get("quarantine_id"):
                record["deleted_at"] = now

        return self._update_record(
            file_path,
            resolved_site_id,
            operation="remove",
            mutate=mutate,
        )

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
            mutate=lambda record: record.update(
                file_exists=False,
                deleted_at=now,
            ),
        )

    def compact(self, compact_days: int | None = None) -> dict[str, int]:
        """Permanently remove old inactive records and return compaction stats."""
        if compact_days is None:
            raw = self._config.get().get("filesizes", {}).get(
                "registry_compact_days", 30
            )
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
                or self._parse_timestamp(record.get("detected_at")) > cutoff
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
        """Close the injected shadow repository when it owns such a method."""
        close = getattr(self._shadow, "close", None)
        if callable(close):
            close()

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
            records = copy.deepcopy(self._records)
            index = self._find_index(records, key, target_site)
            if index is None:
                return False
            record = records[index]
            mutate(record)
            self._commit_upsert(
                records,
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
        transaction_id = self._wal.write_entry(
            "registry_upsert", payload={"record": copy.deepcopy(record)}
        )
        previous = self._records
        try:
            self._persist(records, previous=previous)
        except Exception as exc:
            raise RegistryPersistenceError(
                f"Registry JSON commit failed; WAL transaction {transaction_id} is pending"
            ) from exc
        self._records = copy.deepcopy(records)
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
                f"Registry JSON commit failed; WAL transaction {transaction_id} is pending"
            ) from exc
        self._records = copy.deepcopy(records)
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
        serialized = json.dumps(records, ensure_ascii=False, indent=2)
        try:
            self._atomic_write(self.backup_path, serialized)
            self._atomic_write(self.path, serialized)
        except OSError as exc:
            raise RegistryPersistenceError(
                f"cannot atomically write Registry at {self.path}: {exc}"
            ) from exc
        self._shadow_sync(records, previous)

    def _shadow_sync(
        self,
        records: list[dict[str, Any]],
        previous: list[dict[str, Any]],
    ) -> None:
        if self._shadow is None:
            return
        current_ids = {self._record_id(record) for record in records}
        previous_ids = {self._record_id(record) for record in previous}
        try:
            for record in records:
                self._shadow.save(self._record_id(record), copy.deepcopy(record))
            for stale_id in previous_ids - current_ids:
                self._shadow.delete(stale_id)
        except Exception:
            self._logger.warning(
                "Registry SQLite shadow synchronization failed; JSON remains authoritative",
                exc_info=True,
            )

    def _load_records(self) -> tuple[list[dict[str, Any]], bool]:
        failures: list[str] = []
        for candidate, source in (
            (self.path, "primary"),
            (self.backup_path, "backup"),
        ):
            if not candidate.exists():
                continue
            try:
                raw = json.loads(candidate.read_text(encoding="utf-8"))
                records, normalized = self._normalize_records(raw)
            except (OSError, json.JSONDecodeError, RegistryDataError) as exc:
                failures.append(f"{source}: {exc}")
                continue
            if candidate == self.backup_path:
                self._logger.warning("Registry primary recovered from backup %s", candidate)
                normalized = True
            return records, normalized

        if self._shadow is not None:
            try:
                shadow_records = self._shadow.list_all(limit=999_999)
                if shadow_records:
                    records, _ = self._normalize_records(shadow_records)
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

    def _normalize_records(self, raw: Any) -> tuple[list[dict[str, Any]], bool]:
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
        seen: set[str] = set()
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise RegistryDataError(f"record {index} is not an object")
            if not str(value.get("file_path") or "").strip():
                raise RegistryDataError(f"record {index} has no file_path")
            record = copy.deepcopy(value)
            key = path_to_key(record["file_path"])
            identity = self._config.resolve_site_identity(
                key,
                site_id=record.get("site_id"),
                site_name=record.get("site_name"),
            )
            record["file_path"] = key
            record.update(identity.as_dict())
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
            record.setdefault("detection_source", "passive")
            record.setdefault("false_positive_reason", "")
            record.setdefault("false_positive_at", None)
            record.setdefault("quarantine_id", None)
            record_id = self._record_id(record)
            if record_id in seen:
                raise RegistryDataError(f"duplicate Registry identity: {record_id}")
            seen.add(record_id)
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
                index = self._find_index(
                    records, record["file_path"], record["site_id"]
                )
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
                records[index]["features"] = self._normalize_features(
                    entry.get("features")
                )
                records[index]["file_exists"] = True
        elif operation == "increment":
            if index is None:
                raise RegistryDataError("legacy increment target does not exist")
            records[index]["communication_count"] = int(
                records[index].get("communication_count", 0)
            ) + 1
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
        self._persist(records, previous=self._records)
        self._records = records

    def _notify(self, event_type: str, payload: Mapping[str, Any]) -> None:
        try:
            self._events.publish(event_type, "suspicious_registry", dict(payload))
        except Exception:
            self._logger.warning(
                "Registry event publish failed: %s", event_type, exc_info=True
            )
        if self._change_callback is not None:
            try:
                self._change_callback()
            except Exception:
                self._logger.warning("Registry change callback failed", exc_info=True)

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

    def _site_id_for_lookup(
        self, file_path: str | Path, site_id: str | None
    ) -> str:
        if site_id:
            return self._normalize_site_id(site_id)
        return self._config.resolve_site_identity(str(file_path)).site_id

    @staticmethod
    def _find_index(
        records: list[dict[str, Any]], file_path: str, site_id: str
    ) -> int | None:
        for index, record in enumerate(records):
            if record.get("file_path") == file_path and record.get("site_id") == site_id:
                return index
        return None

    @staticmethod
    def _record_id(record: Mapping[str, Any]) -> str:
        return f"{record['site_id']}:{record['file_path']}"

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
    def _parse_timestamp(value: Any) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return datetime.min.replace(tzinfo=timezone.utc)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

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
