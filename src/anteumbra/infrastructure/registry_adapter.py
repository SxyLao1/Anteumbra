# -*- coding: utf-8 -*-
"""
v2.0-alpha: RegistryRepository — adapts legacy suspicious_registry to Repository interface.

This is the BRIDGE between old code and new architecture.
Old code continues to use suspicious_registry.* functions.
New code (and eventually all code) uses this Repository implementation.

Migration path:
  1. ✅ Create this adapter (new code can use Repository)
  2. ⬜ Update callers one by one (scanner, monitor, admin_bp, etc.)
  3. ⬜ Once all callers migrated, retire suspicious_registry.py internals
"""
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from anteumbra.domain import Repository, EventRepository
from anteumbra.domain.entities import FileRecord, DetectionSource

logger = logging.getLogger(__name__)

# ── Adapter: wraps existing module ──────────────────────

class RegistryRepository(Repository):
    """Repository implementation backed by the existing suspicious_registry module.

    This is an ADAPTER — it doesn't replace the underlying storage,
    it just provides the Repository interface on top of it.
    """

    def __init__(self):
        self._lock = threading.Lock()

    # ── Repository interface ────────────────────────────

    def save(self, record_id: str, data: Dict[str, Any]) -> None:
        """Save a record. Wraps suspicious_registry.add() with immediate sync."""
        from anteumbra.infrastructure.suspicious_registry import add as registry_add
        from anteumbra.infrastructure.suspicious_registry import _load_registry, _save_registry_sync
        file_path = Path(data.get("file_path", record_id))
        features = data.get("features", [])
        first_seen_ip = data.get("first_seen_ip")
        detection_source = data.get("detection_source", "passive")
        registry_add(file_path, features, first_seen_ip, detection_source)
        # Force immediate write to disk (async save is for production batching)
        _save_registry_sync(_load_registry())

    @staticmethod
    def _norm(path: str) -> str:
        """Normalize path for case-insensitive comparison (Windows-safe)."""
        return path.replace("\\", "/").lower()

    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Get a single record by file path (case-insensitive)."""
        from anteumbra.infrastructure.suspicious_registry import get_all, _clear_memory_cache
        _clear_memory_cache()
        target = self._norm(record_id)
        records = get_all(include_deleted=True)
        for r in records:
            if self._norm(r.get("file_path", "")) == target:
                return dict(r)
        return None

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        from anteumbra.infrastructure.suspicious_registry import get_all, _clear_memory_cache
        _clear_memory_cache()
        records = get_all(include_deleted=False)
        return [dict(r) for r in records[offset:offset + limit]]

    def query(self, filters: Dict[str, Any],
              limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        from anteumbra.infrastructure.suspicious_registry import get_all, _clear_memory_cache
        _clear_memory_cache()
        records = get_all(include_deleted=filters.get("include_deleted", False))
        results = []
        for r in records:
            match = True
            for k, v in filters.items():
                if k == "include_deleted":
                    continue
                if r.get(k) != v:
                    match = False
                    break
            if match:
                results.append(dict(r))
        return results[offset:offset + limit]

    def delete(self, record_id: str) -> bool:
        from anteumbra.infrastructure.suspicious_registry import remove
        return remove(record_id)

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        from anteumbra.infrastructure.suspicious_registry import get_all
        if filters:
            return len(self.query(filters, limit=999999))
        return len(get_all(include_deleted=False))

    # ── Domain-specific methods ─────────────────────────

    def save_entity(self, entity: FileRecord) -> None:
        """Save a FileRecord entity."""
        self.save(entity.file_path, entity.to_dict())

    def get_entity(self, file_path: str) -> Optional[FileRecord]:
        """Get a FileRecord entity by path."""
        data = self.get(file_path)
        if data:
            return FileRecord.from_dict(data)
        return None

    def get_active(self) -> List[FileRecord]:
        """Get all active (non-quarantined, non-FP, non-deleted) records as entities."""
        from anteumbra.infrastructure.suspicious_registry import get_all
        records = get_all(include_deleted=False, include_false_positive=False)
        return [
            FileRecord.from_dict(dict(r))
            for r in records
            if not r.get("quarantine_id")
        ]

    def mark_quarantined(self, file_path: str, quarantine_id: str) -> bool:
        """Mark a file as quarantined."""
        from anteumbra.infrastructure.suspicious_registry import mark_quarantined
        return mark_quarantined(file_path, quarantine_id)

    def mark_deleted(self, file_path: str) -> bool:
        """Mark a file as physically deleted."""
        from anteumbra.infrastructure.suspicious_registry import _load_registry, _save_registry
        from anteumbra.infrastructure.utils.path_utils import path_to_key
        key = path_to_key(file_path)
        registry = _load_registry()
        for item in registry:
            if item.get("file_path") == key:
                item["file_exists"] = False
                item["deleted_at"] = datetime.now(timezone.utc).isoformat()
                _save_registry(registry)
                return True
        return False

    def increment_access(self, file_path: str, ip: str) -> None:
        """Increment communication count for a file."""
        from anteumbra.infrastructure.suspicious_registry import _increment_access_direct
        from anteumbra.infrastructure.suspicious_registry import _load_registry
        registry = _load_registry()
        _increment_access_direct(registry, Path(file_path), ip)
        from anteumbra.infrastructure.suspicious_registry import _save_registry_sync
        _save_registry_sync(registry)

    def get_stats(self) -> Dict[str, int]:
        """Get registry statistics."""
        from anteumbra.infrastructure.suspicious_registry import get_all
        active = get_all(include_deleted=False)
        total = get_all(include_deleted=True)
        quarantined = sum(1 for r in total if r.get("quarantine_id"))
        fp_count = sum(1 for r in total if r.get("marked_false_positive"))
        deleted = sum(1 for r in total if r.get("deleted_at"))
        return {
            "active": len(active) - quarantined,
            "total": len(total),
            "quarantined": quarantined,
            "false_positives": fp_count,
            "deleted": deleted,
        }


# ── Singleton ──────────────────────────────────────────

_registry_repo: Optional[RegistryRepository] = None
_repo_lock = threading.Lock()


def get_registry_repository() -> RegistryRepository:
    """Get singleton RegistryRepository instance."""
    global _registry_repo
    if _registry_repo is None:
        with _repo_lock:
            if _registry_repo is None:
                _registry_repo = RegistryRepository()
    return _registry_repo
