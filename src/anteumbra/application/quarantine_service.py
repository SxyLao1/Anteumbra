"""Application service coordinating quarantine and Registry consistency."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

from anteumbra.domain.quarantine import QuarantineStorePort
from anteumbra.domain.runtime import DetectionRegistryPort
from anteumbra.domain.site import SiteIdentity


class QuarantineConsistencyError(RuntimeError):
    """Raised when quarantine storage and Registry cannot commit together."""


class QuarantineService:
    """Coordinate physical quarantine state with site-qualified Registry state."""

    def __init__(
        self,
        store: QuarantineStorePort,
        registry: DetectionRegistryPort,
        *,
        site_resolver: Callable[..., SiteIdentity],
        logger: logging.Logger | None = None,
    ) -> None:
        self._store = store
        self._registry = registry
        self._site_resolver = site_resolver
        self._logger = logger or logging.getLogger(__name__)
        self._lock = threading.RLock()

    def quarantine_file(
        self,
        file_path: str | Path,
        rule_name: str,
        features: list[str],
        original_path: str | Path | None = None,
        site_id: str | None = None,
        site_name: str | None = None,
        *,
        site: SiteIdentity | None = None,
    ) -> dict[str, Any] | None:
        """Quarantine a file and atomically link its Registry record."""
        identity = self._resolve_site(
            original_path or file_path,
            site=site,
            site_id=site_id,
            site_name=site_name,
        )
        with self._lock:
            record = self._store.quarantine_file(
                file_path,
                rule_name,
                features,
                original_path,
                site=identity,
            )
            if record is None:
                return None

            try:
                marked = self._registry.mark_quarantined(
                    record["original_path"],
                    record["quarantine_id"],
                    identity.site_id,
                )
            except Exception as registry_error:
                self._compensate_quarantine(record["quarantine_id"], registry_error)
            if not marked:
                self._compensate_quarantine(record["quarantine_id"], None)
            return record

    def restore_file(self, quarantine_id: str) -> dict[str, Any]:
        """Restore a file and clear a matching Registry quarantine link."""
        with self._lock:
            record = self._store.get_detail(quarantine_id)
            if record is None:
                return self._store.restore_file(quarantine_id)

            original_path = record["original_path"]
            site_id = record["site_id"]
            linked_record = self._registry.get(original_path, site_id)
            should_update_registry = bool(
                linked_record
                and linked_record.get("quarantine_id") == quarantine_id
            )

            restored = self._store.restore_file(quarantine_id)
            if not should_update_registry:
                return restored

            try:
                marked = self._registry.mark_restored(original_path, site_id)
            except Exception as registry_error:
                self._compensate_restore(quarantine_id, registry_error)
            if not marked:
                self._compensate_restore(quarantine_id, None)
            return restored

    def delete_quarantine(self, quarantine_id: str) -> dict[str, Any]:
        """Permanently delete a quarantined file and retain its audit record."""
        with self._lock:
            return self._store.delete_quarantine(quarantine_id)

    def is_recently_restored(self, file_path: str | Path) -> bool:
        """Return whether a restored path is still suppressed from rescanning."""
        return self._store.is_recently_restored(file_path)

    def list_records(
        self,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
        site_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return a filtered defensive snapshot of quarantine records."""
        return self._store.list_records(status, limit, offset, site_id)

    def get_detail(self, quarantine_id: str) -> dict[str, Any] | None:
        """Return one quarantine record."""
        return self._store.get_detail(quarantine_id)

    def get_stats(self, site_id: str | None = None) -> dict[str, int]:
        """Return quarantine aggregate counts."""
        return self._store.get_stats(site_id)

    def migrate_site_metadata(self) -> int:
        """Persist corrected site ownership for historical records."""
        with self._lock:
            return self._store.migrate_site_metadata()

    def close(self) -> None:
        """Release resources owned by the quarantine store."""
        self._store.close()

    def _resolve_site(
        self,
        file_path: str | Path,
        *,
        site: SiteIdentity | None,
        site_id: str | None,
        site_name: str | None,
    ) -> SiteIdentity:
        if site is not None:
            return site
        return self._site_resolver(
            str(file_path),
            site_id=site_id,
            site_name=site_name,
        )

    def _compensate_quarantine(
        self,
        quarantine_id: str,
        registry_error: Exception | None,
    ) -> NoReturn:
        try:
            self._store.rollback_quarantine(quarantine_id)
        except Exception as rollback_error:
            self._logger.critical(
                "Registry update and quarantine rollback both failed for %s",
                quarantine_id,
                exc_info=True,
            )
            raise QuarantineConsistencyError(
                "Registry update failed and quarantine rollback could not restore "
                f"{quarantine_id}: {rollback_error}"
            ) from rollback_error

        error = QuarantineConsistencyError(
            f"Registry update failed; quarantine {quarantine_id} was rolled back"
        )
        if registry_error is not None:
            raise error from registry_error
        raise error

    def _compensate_restore(
        self,
        quarantine_id: str,
        registry_error: Exception | None,
    ) -> NoReturn:
        try:
            self._store.rollback_restore(quarantine_id)
        except Exception as rollback_error:
            self._logger.critical(
                "Registry restore update and file rollback both failed for %s",
                quarantine_id,
                exc_info=True,
            )
            raise QuarantineConsistencyError(
                "Registry restore update failed and compensation could not restore "
                f"{quarantine_id}: {rollback_error}"
            ) from rollback_error

        error = QuarantineConsistencyError(
            f"Registry restore update failed; restore {quarantine_id} was rolled back"
        )
        if registry_error is not None:
            raise error from registry_error
        raise error


__all__ = ["QuarantineConsistencyError", "QuarantineService"]
