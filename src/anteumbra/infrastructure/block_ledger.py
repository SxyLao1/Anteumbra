"""Runtime-owned, site-qualified IP blocking audit ledger."""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from anteumbra.domain.blocking import BlockLedgerEntry, canonical_ip
from anteumbra.domain.repository import Repository
from anteumbra.domain.runtime import EventPublisherPort
from anteumbra.domain.site import SiteIdentity

logger = logging.getLogger("monitor.block_ledger")


class BlockLedgerPersistenceError(RuntimeError):
    """The authoritative block ledger could not be read or written safely."""


class BlockLedger:
    """Own the persistence and cache for one runtime's block audit ledger."""

    def __init__(
        self,
        path: str | Path,
        *,
        shadow_repository: Repository | None = None,
        event_publisher: EventPublisherPort | None = None,
        clock: Callable[[], datetime] | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        self.path = Path(path).resolve()
        self._shadow = shadow_repository
        self._events = event_publisher
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._logger = log or logger
        self._lock = threading.RLock()
        self._entries: dict[str, BlockLedgerEntry] = {}
        self._loaded = False
        self._shadow_errors: list[str] = []

    @property
    def shadow_errors(self) -> tuple[str, ...]:
        """Return bounded diagnostics from best-effort shadow operations."""
        with self._lock:
            return tuple(self._shadow_errors)

    def add_entry(
        self,
        ip: str,
        *,
        site: SiteIdentity,
        source: str = "manual",
        reason: str = "",
        profile_id: str = "",
        blocked_by: str = "admin",
        broadcast_results: Sequence[Mapping[str, object]] | None = None,
    ) -> dict[str, object]:
        """Create or update the current audit record for one site/IP pair."""
        canonical = canonical_ip(ip)
        results = list(broadcast_results or ())
        devices = tuple(str(item.get("device", "")) for item in results if item.get("device"))
        if not results:
            broadcast_status = "pending"
        else:
            successful = sum(bool(item.get("success")) for item in results)
            if successful == len(results):
                broadcast_status = "success"
            elif successful:
                broadcast_status = "partial"
            else:
                broadcast_status = "failed"

        with self._lock:
            self._ensure_loaded_locked()
            record_id = f"{site.site_id}|{canonical}"
            existing = self._entries.get(record_id)
            entry = BlockLedgerEntry(
                ip=canonical,
                site=site,
                blocked_at=self._now_iso(),
                source=str(source or "manual"),
                reason=str(reason or (existing.reason if existing else "")),
                notes=existing.notes if existing else "",
                blocked_by=str(blocked_by or "admin"),
                profile_id=str(profile_id or (existing.profile_id if existing else "")),
                broadcast_devices=devices or (existing.broadcast_devices if existing else ()),
                broadcast_status=broadcast_status,
                status="blocked",
            )
            updated = dict(self._entries)
            updated[entry.record_id] = entry
            self._persist_locked(updated, upsert=entry)

        self._emit("block_executed", entry)
        self._logger.info(
            "[BLOCK_LEDGER] site=%s ip=%s source=%s reason=%s",
            site.site_id,
            canonical,
            entry.source,
            entry.reason[:60],
        )
        return entry.as_dict()

    def mark_unblocked(
        self,
        ip: str,
        *,
        site_id: str,
        unblocked_by: str = "admin",
    ) -> bool:
        """Retain the audit record while marking its current state unblocked."""
        canonical = canonical_ip(ip)
        with self._lock:
            self._ensure_loaded_locked()
            record_id = self._record_id(site_id, canonical)
            existing = self._entries.get(record_id)
            if existing is None:
                return False
            entry = BlockLedgerEntry(
                **{
                    **self._entry_init(existing),
                    "status": "unblocked",
                    "unblocked_at": self._now_iso(),
                    "unblocked_by": str(unblocked_by or "admin"),
                }
            )
            updated = dict(self._entries)
            updated[record_id] = entry
            self._persist_locked(updated, upsert=entry)

        self._emit("block_removed", entry)
        return True

    def update_notes(self, ip: str, notes: str, *, site_id: str) -> bool:
        """Update notes only inside the requested site boundary."""
        canonical = canonical_ip(ip)
        with self._lock:
            self._ensure_loaded_locked()
            record_id = self._record_id(site_id, canonical)
            existing = self._entries.get(record_id)
            if existing is None:
                return False
            entry = BlockLedgerEntry(
                **{
                    **self._entry_init(existing),
                    "notes": str(notes),
                }
            )
            updated = dict(self._entries)
            updated[record_id] = entry
            self._persist_locked(updated, upsert=entry)
            return True

    def remove_entry(self, ip: str, *, site_id: str) -> bool:
        """Permanently delete one site-qualified ledger record."""
        canonical = canonical_ip(ip)
        with self._lock:
            self._ensure_loaded_locked()
            record_id = self._record_id(site_id, canonical)
            if record_id not in self._entries:
                return False
            updated = dict(self._entries)
            del updated[record_id]
            self._persist_locked(updated, delete_record_id=record_id)
            return True

    def get_by_ip(self, ip: str, *, site_id: str) -> dict[str, object] | None:
        """Return one record without allowing an ambiguous cross-site lookup."""
        canonical = canonical_ip(ip)
        with self._lock:
            self._ensure_loaded_locked()
            entry = self._entries.get(self._record_id(site_id, canonical))
            return entry.as_dict() if entry else None

    def get_entries(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        source_filter: str = "",
        search: str = "",
        site_id: str | None = None,
        status: str | None = None,
    ) -> tuple[list[dict[str, object]], int]:
        """Return a filtered page; ``site_id=None`` is an explicit aggregate query."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must not be negative")
        with self._lock:
            self._ensure_loaded_locked()
            entries = list(self._entries.values())

        if site_id is not None:
            normalized_site_id = self._normalize_site_id(site_id)
            entries = [item for item in entries if item.site.site_id == normalized_site_id]
        if source_filter and source_filter != "all":
            entries = [item for item in entries if item.source == source_filter]
        if status and status != "all":
            if status not in {"blocked", "unblocked"}:
                raise ValueError(f"invalid ledger status filter: {status!r}")
            entries = [item for item in entries if item.status == status]
        if search:
            query = search.casefold()
            entries = [
                item
                for item in entries
                if query in item.ip.casefold()
                or query in item.reason.casefold()
                or query in item.notes.casefold()
                or query in item.site.site_name.casefold()
            ]
        entries.sort(key=lambda item: item.blocked_at, reverse=True)
        total = len(entries)
        return [item.as_dict() for item in entries[offset : offset + limit]], total

    def get_stats(self, *, site_id: str | None = None) -> dict[str, int]:
        """Return aggregate or explicitly site-scoped ledger counters."""
        entries, _ = self.get_entries(limit=1_000_000, site_id=site_id)
        today = self._clock().date().isoformat()
        return {
            "total": len(entries),
            "auto": sum(item.get("source") == "auto" for item in entries),
            "manual": sum(item.get("source") == "manual" for item in entries),
            "today": sum(str(item.get("blocked_at", "")).startswith(today) for item in entries),
            "blocked": sum(item.get("status") == "blocked" for item in entries),
            "unblocked": sum(item.get("status") == "unblocked" for item in entries),
        }

    def export_ledger(self, fmt: str = "json", *, site_id: str | None = None) -> str:
        """Export aggregate or site-scoped ledger data as JSON or safe CSV."""
        entries, _ = self.get_entries(limit=1_000_000, site_id=site_id)
        normalized_format = str(fmt).strip().lower()
        if normalized_format == "json":
            return json.dumps(entries, indent=2, ensure_ascii=False)
        if normalized_format != "csv":
            raise ValueError("format must be 'json' or 'csv'")

        fields = (
            "site_id",
            "site_name",
            "ip",
            "blocked_at",
            "source",
            "reason",
            "notes",
            "blocked_by",
            "profile_id",
            "broadcast_status",
            "status",
            "unblocked_at",
            "unblocked_by",
        )
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow({key: self._csv_safe(entry.get(key)) for key in fields})
        return output.getvalue()

    def reload(self) -> None:
        """Discard the in-memory snapshot and load authoritative state again."""
        with self._lock:
            self._entries = {}
            self._loaded = False
            self._ensure_loaded_locked()

    def close(self) -> None:
        """Close the injected shadow repository when it owns a close hook."""
        close = getattr(self._shadow, "close", None)
        if callable(close):
            close()

    def _ensure_loaded_locked(self) -> None:
        if self._loaded:
            return

        primary_error: Exception | None = None
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(raw, list):
                    raise ValueError("ledger JSON root must be a list")
                self._entries = self._normalize_entries(raw)
                self._loaded = True
                self._reconcile_shadow_locked()
                return
            except (OSError, ValueError, TypeError) as exc:
                primary_error = exc
                self._logger.error("[BLOCK_LEDGER] Primary JSON load failed: %s", exc)

        recovered = self._recover_shadow_locked()
        if recovered:
            self._write_primary_locked(recovered)
            self._entries = recovered
            self._loaded = True
            self._logger.warning(
                "[BLOCK_LEDGER] Recovered %d records from the SQLite shadow",
                len(recovered),
            )
            return
        if primary_error is not None:
            raise BlockLedgerPersistenceError(
                f"cannot load authoritative block ledger {self.path}: {primary_error}"
            ) from primary_error
        self._entries = {}
        self._loaded = True

    def _normalize_entries(
        self,
        raw_entries: Sequence[Mapping[str, Any]],
    ) -> dict[str, BlockLedgerEntry]:
        normalized: dict[str, BlockLedgerEntry] = {}
        for index, raw in enumerate(raw_entries):
            if not isinstance(raw, Mapping):
                raise ValueError(f"ledger record {index} must be an object")
            try:
                entry = BlockLedgerEntry.from_mapping(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid ledger record {index}: {exc}") from exc
            previous = normalized.get(entry.record_id)
            if previous is None or entry.blocked_at >= previous.blocked_at:
                normalized[entry.record_id] = entry
        return normalized

    def _recover_shadow_locked(self) -> dict[str, BlockLedgerEntry]:
        if self._shadow is None:
            return {}
        try:
            records = self._shadow.list_all(limit=1_000_000)
            return self._normalize_entries(records) if records else {}
        except Exception as exc:
            self._record_shadow_error("load", exc)
            return {}

    def _reconcile_shadow_locked(self) -> None:
        if self._shadow is None:
            return
        try:
            shadow_records = self._shadow.list_all(limit=1_000_000)
            shadow_ids = {
                BlockLedgerEntry.from_mapping(record).record_id
                for record in shadow_records
                if isinstance(record, Mapping)
            }
            for record_id in shadow_ids - self._entries.keys():
                self._shadow.delete(record_id)
            for entry in self._entries.values():
                self._shadow.save(entry.record_id, entry.as_dict())
        except Exception as exc:
            self._record_shadow_error("reconcile", exc)

    def _persist_locked(
        self,
        entries: dict[str, BlockLedgerEntry],
        *,
        upsert: BlockLedgerEntry | None = None,
        delete_record_id: str | None = None,
    ) -> None:
        self._write_primary_locked(entries)
        self._entries = entries
        self._loaded = True
        if self._shadow is None:
            return
        if upsert is not None:
            try:
                self._shadow.save(upsert.record_id, upsert.as_dict())
            except Exception as exc:
                self._record_shadow_error("save", exc)
        if delete_record_id is not None:
            try:
                self._shadow.delete(delete_record_id)
            except Exception as exc:
                self._record_shadow_error("delete", exc)

    def _write_primary_locked(self, entries: Mapping[str, BlockLedgerEntry]) -> None:
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        payload = [
            entry.as_dict()
            for entry in sorted(entries.values(), key=lambda item: item.blocked_at, reverse=True)
        ]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(temporary, self.path)
        except (OSError, TypeError, ValueError) as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                self._logger.debug("Failed to remove block ledger temp file", exc_info=True)
            raise BlockLedgerPersistenceError(
                f"cannot persist authoritative block ledger {self.path}: {exc}"
            ) from exc

    def _emit(self, event_type: str, entry: BlockLedgerEntry) -> None:
        if self._events is None:
            return
        try:
            self._events.publish(event_type, "block_ledger", entry.as_dict())
        except Exception as exc:
            self._logger.warning("Block ledger event publish failed: %s", exc, exc_info=True)

    def _record_shadow_error(self, operation: str, exc: Exception) -> None:
        message = f"{operation}: {type(exc).__name__}: {exc}"
        self._shadow_errors.append(message)
        del self._shadow_errors[:-20]
        self._logger.warning("Block ledger shadow %s failed: %s", operation, exc)

    def _now_iso(self) -> str:
        value = self._clock()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _normalize_site_id(site_id: str) -> str:
        normalized = str(site_id).strip().lower()
        if not normalized:
            raise ValueError("site_id must not be empty")
        return normalized

    @classmethod
    def _record_id(cls, site_id: str, ip: str) -> str:
        return f"{cls._normalize_site_id(site_id)}|{ip}"

    @staticmethod
    def _entry_init(entry: BlockLedgerEntry) -> dict[str, object]:
        return {
            "ip": entry.ip,
            "site": entry.site,
            "blocked_at": entry.blocked_at,
            "source": entry.source,
            "reason": entry.reason,
            "notes": entry.notes,
            "blocked_by": entry.blocked_by,
            "profile_id": entry.profile_id,
            "broadcast_devices": entry.broadcast_devices,
            "broadcast_status": entry.broadcast_status,
            "status": entry.status,
            "unblocked_at": entry.unblocked_at,
            "unblocked_by": entry.unblocked_by,
        }

    @staticmethod
    def _csv_safe(value: object) -> object:
        if value is None:
            return ""
        text = str(value)
        return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text
