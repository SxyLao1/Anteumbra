"""Runtime-owned quarantine file and metadata store."""

from __future__ import annotations

import copy
import json
import logging
import os
import shutil
import sys
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from anteumbra.domain import Repository
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.utils.path_utils import normalize_path


class QuarantineError(RuntimeError):
    """Base class for quarantine storage failures."""


class QuarantineDataError(QuarantineError):
    """Raised when quarantine metadata has no valid recovery source."""


class QuarantinePersistenceError(QuarantineError):
    """Raised when quarantine metadata cannot be committed."""


class QuarantineStore:
    """Own quarantined files, authoritative JSON metadata, and restore guards."""

    _VALID_STATUSES = {"quarantined", "restored", "deleted"}

    def __init__(
        self,
        directory: str | Path,
        *,
        site_resolver: Callable[..., SiteIdentity],
        shadow_repository: Repository | None = None,
        restored_ttl: float = 30.0,
        logger: logging.Logger | None = None,
    ) -> None:
        if restored_ttl <= 0:
            raise ValueError("restored_ttl must be positive")
        self.directory = Path(directory)
        self.db_path = self.directory / "quarantine.json"
        self.backup_path = self.directory / "quarantine.json.bak"
        self._site_resolver = site_resolver
        self._shadow = shadow_repository
        self._restored_ttl = float(restored_ttl)
        self._logger = logger or logging.getLogger("monitor.quarantine")
        self._lock = threading.RLock()
        self._recently_restored: dict[str, float] = {}
        self.directory.mkdir(parents=True, exist_ok=True)
        records, normalized = self._load_records()
        self._records = records
        if normalized:
            self._persist(records, previous=[])
        self._report_orphans()

    def quarantine_file(
        self,
        file_path: str | Path,
        rule_name: str,
        features: list[str],
        original_path: str | Path | None = None,
        *,
        site: SiteIdentity,
    ) -> dict[str, Any] | None:
        """Move a file into quarantine and atomically commit its metadata."""
        with self._lock:
            source = normalize_path(file_path)
            if not source.exists():
                self._logger.warning("Quarantine source does not exist: %s", source)
                return None
            if not source.is_file():
                raise ValueError(f"quarantine source is not a file: {source}")

            now = datetime.now(timezone.utc)
            quarantine_id = f"Q-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
            target_dir = self.directory / now.strftime("%Y-%m-%d")
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / f"{quarantine_id}_{source.name}"
            file_size = source.stat().st_size
            original = normalize_path(original_path or source)
            record = {
                "quarantine_id": quarantine_id,
                "original_path": str(original),
                "quarantine_path": str(target),
                "quarantine_time": now.isoformat(),
                "rule_name": str(rule_name),
                "features": [str(item) for item in features],
                "file_size": file_size,
                "status": "quarantined",
                **site.as_dict(),
            }

            previous = self._records
            records = [copy.deepcopy(record), *copy.deepcopy(previous)]
            try:
                shutil.move(str(source), str(target))
            except FileNotFoundError:
                self._logger.warning("Quarantine source disappeared before move: %s", source)
                return None
            try:
                self._persist(records, previous=previous)
            except Exception as commit_error:
                try:
                    source.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists() and not source.exists():
                        shutil.move(str(target), str(source))
                except Exception as rollback_error:
                    raise QuarantinePersistenceError(
                        "quarantine metadata commit and file rollback both failed "
                        f"for {quarantine_id}: {rollback_error}"
                    ) from commit_error
                raise
            self._records = records
            return copy.deepcopy(record)

    def rollback_quarantine(self, quarantine_id: str) -> dict[str, Any]:
        """Undo a newly committed quarantine operation."""
        with self._lock:
            index = self._index_for(quarantine_id)
            record = self._records[index]
            if record.get("status") != "quarantined":
                raise ValueError(f"quarantine cannot be rolled back from {record.get('status')}")
            quarantine_path = normalize_path(record["quarantine_path"])
            original_path = normalize_path(record["original_path"])
            self._validate_move(quarantine_path, original_path, "roll back quarantine")
            previous = self._records
            records = [
                copy.deepcopy(item) for position, item in enumerate(previous) if position != index
            ]
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(original_path))
            try:
                self._persist(records, previous=previous)
            except Exception as commit_error:
                try:
                    quarantine_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(original_path), str(quarantine_path))
                except Exception as rollback_error:
                    raise QuarantinePersistenceError(
                        "quarantine rollback commit and compensation both failed "
                        f"for {quarantine_id}: {rollback_error}"
                    ) from commit_error
                raise
            self._records = records
            return copy.deepcopy(record)

    def restore_file(self, quarantine_id: str) -> dict[str, Any]:
        """Restore a quarantined file and commit its restored status."""
        with self._lock:
            index = self._index_for(quarantine_id)
            current = self._records[index]
            if current.get("status") != "quarantined":
                raise ValueError(f"file is not quarantined: {current.get('status')}")
            quarantine_path = normalize_path(current["quarantine_path"])
            original_path = normalize_path(current["original_path"])
            self._validate_move(quarantine_path, original_path, "restore quarantine")
            restore_key = self._restore_key(original_path)
            self._recently_restored[restore_key] = time.monotonic() + self._restored_ttl

            previous = self._records
            records = copy.deepcopy(previous)
            record = records[index]
            record.update(
                status="restored",
                restore_time=datetime.now(timezone.utc).isoformat(),
            )
            original_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(quarantine_path), str(original_path))
                self._persist(records, previous=previous)
            except Exception as commit_error:
                self._recently_restored.pop(restore_key, None)
                try:
                    if original_path.exists() and not quarantine_path.exists():
                        quarantine_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(original_path), str(quarantine_path))
                except Exception as rollback_error:
                    raise QuarantinePersistenceError(
                        "restore commit and file rollback both failed "
                        f"for {quarantine_id}: {rollback_error}"
                    ) from commit_error
                raise
            self._records = records
            return copy.deepcopy(record)

    def rollback_restore(self, quarantine_id: str) -> dict[str, Any]:
        """Move a restored file back when its linked Registry update fails."""
        with self._lock:
            index = self._index_for(quarantine_id)
            current = self._records[index]
            if current.get("status") != "restored":
                raise ValueError(f"restore cannot be rolled back from {current.get('status')}")
            quarantine_path = normalize_path(current["quarantine_path"])
            original_path = normalize_path(current["original_path"])
            self._validate_move(original_path, quarantine_path, "roll back restore")

            previous = self._records
            records = copy.deepcopy(previous)
            record = records[index]
            record["status"] = "quarantined"
            record.pop("restore_time", None)
            quarantine_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(original_path), str(quarantine_path))
            try:
                self._persist(records, previous=previous)
            except Exception as commit_error:
                try:
                    original_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(quarantine_path), str(original_path))
                except Exception as rollback_error:
                    raise QuarantinePersistenceError(
                        "restore rollback commit and compensation both failed "
                        f"for {quarantine_id}: {rollback_error}"
                    ) from commit_error
                raise
            self._records = records
            self._recently_restored.pop(self._restore_key(original_path), None)
            return copy.deepcopy(record)

    def delete_quarantine(self, quarantine_id: str) -> dict[str, Any]:
        """Permanently delete a stored file while retaining its audit record."""
        with self._lock:
            index = self._index_for(quarantine_id)
            current = self._records[index]
            quarantine_path = normalize_path(current["quarantine_path"])
            pending_path: Path | None = None
            if quarantine_path.exists():
                pending_path = quarantine_path.with_name(
                    f"{quarantine_path.name}.delete-pending-{uuid.uuid4().hex[:8]}"
                )
                quarantine_path.replace(pending_path)

            previous = self._records
            records = copy.deepcopy(previous)
            record = records[index]
            record.update(
                status="deleted",
                delete_time=datetime.now(timezone.utc).isoformat(),
            )
            try:
                self._persist(records, previous=previous)
                if pending_path is not None:
                    pending_path.unlink()
            except Exception as delete_error:
                try:
                    if pending_path is not None and pending_path.exists():
                        pending_path.replace(quarantine_path)
                    self._persist(previous, previous=records)
                except Exception as rollback_error:
                    raise QuarantinePersistenceError(
                        "quarantine deletion and compensation both failed "
                        f"for {quarantine_id}: {rollback_error}"
                    ) from delete_error
                raise
            self._records = records
            return copy.deepcopy(record)

    def is_recently_restored(self, file_path: str | Path) -> bool:
        """Return whether a restored path is still inside the suppression TTL."""
        key = self._restore_key(normalize_path(file_path))
        now = time.monotonic()
        with self._lock:
            expired = [
                path for path, deadline in self._recently_restored.items() if deadline <= now
            ]
            for path in expired:
                self._recently_restored.pop(path, None)
            return self._recently_restored.get(key, 0.0) > now

    def list_records(
        self,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
        site_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return a filtered, paginated defensive snapshot."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must not be negative")
        normalized_site = str(site_id).strip().lower() if site_id else None
        with self._lock:
            records = [
                copy.deepcopy(record)
                for record in self._records
                if (status is None or record.get("status") == status)
                and (normalized_site is None or record.get("site_id") == normalized_site)
            ]
        records.sort(key=lambda item: str(item.get("quarantine_time", "")), reverse=True)
        return records[offset : offset + limit]

    def get_detail(self, quarantine_id: str) -> dict[str, Any] | None:
        """Return one quarantine record by ID."""
        with self._lock:
            for record in self._records:
                if record.get("quarantine_id") == quarantine_id:
                    return copy.deepcopy(record)
        return None

    def get_stats(self, site_id: str | None = None) -> dict[str, int]:
        """Aggregate quarantine statuses globally or for one site."""
        records = self.list_records(limit=1_000_000, site_id=site_id)
        return {
            "total": len(records),
            "quarantined": sum(record.get("status") == "quarantined" for record in records),
            "restored": sum(record.get("status") == "restored" for record in records),
            "deleted": sum(record.get("status") == "deleted" for record in records),
        }

    def migrate_site_metadata(self) -> int:
        """Resolve and persist missing or stale site ownership."""
        with self._lock:
            records = copy.deepcopy(self._records)
            changed = 0
            for record in records:
                identity = self._site_resolver(
                    record.get("original_path", ""),
                    site_id=record.get("site_id"),
                    site_name=record.get("site_name"),
                )
                if any(record.get(key) != value for key, value in identity.as_dict().items()):
                    record.update(identity.as_dict())
                    changed += 1
            if changed:
                self._persist(records, previous=self._records)
                self._records = records
            return changed

    def close(self) -> None:
        """Release the injected shadow repository."""
        close = getattr(self._shadow, "close", None)
        if callable(close):
            close()

    def _persist(
        self,
        records: list[dict[str, Any]],
        *,
        previous: list[dict[str, Any]],
    ) -> None:
        content = json.dumps(records, ensure_ascii=False, indent=2)
        try:
            self._atomic_write(self.db_path, content)
        except OSError as exc:
            raise QuarantinePersistenceError(
                f"cannot commit quarantine metadata at {self.db_path}: {exc}"
            ) from exc
        try:
            self._atomic_write(self.backup_path, content)
        except OSError:
            self._logger.warning(
                "Quarantine backup refresh failed; primary JSON remains authoritative",
                exc_info=True,
            )
        self._shadow_sync(records, previous)

    def _load_records(self) -> tuple[list[dict[str, Any]], bool]:
        failures: list[str] = []
        for path, source in (
            (self.db_path, "primary"),
            (self.backup_path, "backup"),
        ):
            if not path.exists():
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                records, normalized = self._normalize_records(raw)
            except (OSError, json.JSONDecodeError, QuarantineDataError) as exc:
                failures.append(f"{source}: {exc}")
                continue
            if path == self.backup_path:
                self._logger.warning("Quarantine metadata recovered from backup")
                normalized = True
            return records, normalized

        if self._shadow is not None:
            try:
                raw = self._shadow.list_all(limit=999_999)
                if raw:
                    records, _ = self._normalize_records(raw)
                    self._logger.warning(
                        "Quarantine recovered %d records from SQLite shadow",
                        len(records),
                    )
                    return records, True
            except Exception as exc:
                failures.append(f"shadow: {exc}")
        if failures:
            raise QuarantineDataError(
                "quarantine metadata has no valid recovery source: " + "; ".join(failures)
            )
        return [], False

    def _normalize_records(self, raw: Any) -> tuple[list[dict[str, Any]], bool]:
        if isinstance(raw, dict):
            values = list(raw.values())
            normalized = True
        elif isinstance(raw, list):
            values = raw
            normalized = False
        else:
            raise QuarantineDataError("quarantine root must be an array or object")

        by_id: dict[str, dict[str, Any]] = {}
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise QuarantineDataError(f"quarantine record {index} is not an object")
            record = copy.deepcopy(value)
            quarantine_id = str(record.get("quarantine_id") or "").strip()
            if not quarantine_id:
                raise QuarantineDataError(f"quarantine record {index} has no ID")
            if not record.get("original_path") or not record.get("quarantine_path"):
                raise QuarantineDataError(f"quarantine record {quarantine_id} has incomplete paths")
            status = str(record.get("status") or "quarantined")
            if status not in self._VALID_STATUSES:
                raise QuarantineDataError(
                    f"quarantine record {quarantine_id} has invalid status {status!r}"
                )
            identity = self._site_resolver(
                record["original_path"],
                site_id=record.get("site_id"),
                site_name=record.get("site_name"),
            )
            record.update(identity.as_dict())
            record["quarantine_id"] = quarantine_id
            record["status"] = status
            record["features"] = self._normalize_features(record.get("features"))
            record.setdefault("rule_name", "unknown")
            record.setdefault("file_size", 0)
            record.setdefault("quarantine_time", datetime.now(timezone.utc).isoformat())
            if record != value:
                normalized = True
            existing = by_id.get(quarantine_id)
            if existing is None or self._record_score(record) > self._record_score(existing):
                by_id[quarantine_id] = record
            if existing is not None:
                normalized = True
        return list(by_id.values()), normalized

    def _shadow_sync(
        self,
        records: list[dict[str, Any]],
        previous: list[dict[str, Any]],
    ) -> None:
        if self._shadow is None:
            return
        current_ids = {str(record["quarantine_id"]) for record in records}
        previous_ids = {str(record["quarantine_id"]) for record in previous}
        try:
            for record in records:
                self._shadow.save(record["quarantine_id"], copy.deepcopy(record))
            for stale_id in previous_ids - current_ids:
                self._shadow.delete(stale_id)
        except Exception:
            self._logger.warning(
                "Quarantine SQLite shadow synchronization failed; JSON remains authoritative",
                exc_info=True,
            )

    def _index_for(self, quarantine_id: str) -> int:
        for index, record in enumerate(self._records):
            if record.get("quarantine_id") == quarantine_id:
                return index
        raise ValueError(f"quarantine record does not exist: {quarantine_id}")

    @staticmethod
    def _validate_move(source: Path, target: Path, operation: str) -> None:
        if target.exists():
            raise FileExistsError(f"cannot {operation}; destination exists: {target}")
        if not source.exists():
            raise FileNotFoundError(f"cannot {operation}; source is missing: {source}")

    @staticmethod
    def _restore_key(path: Path) -> str:
        return os.path.normcase(str(path.resolve()))

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
    def _record_score(record: dict[str, Any]) -> int:
        score = 0
        if record.get("original_path") and not str(record["original_path"]).startswith(
            "(recovered)"
        ):
            score += 4
        if record.get("rule_name") and not str(record["rule_name"]).startswith("(auto-recovered"):
            score += 2
        if record.get("features") not in (None, [], ["(recovered)"]):
            score += 1
        return score

    def _report_orphans(self) -> None:
        known = {
            os.path.normcase(str(normalize_path(record["quarantine_path"])))
            for record in self._records
        }
        orphan_count = 0
        for candidate in self.directory.glob("*/*"):
            if candidate.is_file() and os.path.normcase(str(candidate)) not in known:
                if ".delete-pending-" not in candidate.name:
                    orphan_count += 1
        if orphan_count:
            self._logger.warning(
                "Found %d quarantine files without metadata; left untouched for audit",
                orphan_count,
            )

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
