"""Quarantine persistence contracts owned by the domain boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from anteumbra.domain.site import SiteIdentity


class QuarantineStorePort(Protocol):
    """Persist quarantined files without exposing an infrastructure backend."""

    def quarantine_file(
        self,
        file_path: str | Path,
        rule_name: str,
        features: list[str],
        original_path: str | Path | None = None,
        *,
        site: SiteIdentity,
    ) -> dict[str, Any] | None:
        """Move a file into quarantine and commit its metadata."""

    def rollback_quarantine(self, quarantine_id: str) -> dict[str, Any]:
        """Undo a newly committed quarantine operation."""

    def restore_file(self, quarantine_id: str) -> dict[str, Any]:
        """Restore one quarantined file."""

    def rollback_restore(self, quarantine_id: str) -> dict[str, Any]:
        """Compensate a restore operation."""

    def delete_quarantine(self, quarantine_id: str) -> dict[str, Any]:
        """Permanently delete a quarantined file while retaining its audit row."""

    def is_recently_restored(self, file_path: str | Path) -> bool:
        """Return whether a path is inside the restore suppression window."""

    def list_records(
        self,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
        site_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return filtered quarantine records."""

    def get_detail(self, quarantine_id: str) -> dict[str, Any] | None:
        """Return one quarantine record."""

    def get_stats(self, site_id: str | None = None) -> dict[str, int]:
        """Return aggregate quarantine status counts."""

    def migrate_site_metadata(self) -> int:
        """Persist corrected ownership for historical records."""

    def close(self) -> None:
        """Release resources owned by the store."""


class QuarantineGuardPort(Protocol):
    """Minimal restore guard required by file monitoring."""

    def is_recently_restored(self, file_path: str | Path) -> bool:
        """Return whether a path is inside the restore suppression window."""
