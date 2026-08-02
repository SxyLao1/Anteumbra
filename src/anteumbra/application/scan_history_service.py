"""Application service for durable manual-scan history."""

from __future__ import annotations

from typing import Any

from anteumbra.domain.service_ports import ScanHistoryStorePort


class ScanHistoryService:
    """Project scanner results into a stable, durable web-facing record."""

    def __init__(self, store: ScanHistoryStorePort) -> None:
        self._store = store

    def record(self, result: Any) -> None:
        """Persist the bounded result projection produced by a manual scan."""
        end_time = getattr(result, "end_time", 0)
        start_time = getattr(result, "start_time", 0)
        self._store.save(
            result.scan_id,
            {
                "scan_id": result.scan_id,
                "target_dir": result.target_dir,
                "start_time": start_time,
                "end_time": end_time,
                "status": result.status,
                "site_id": getattr(result, "site_id", ""),
                "site_name": getattr(result, "site_name", ""),
                "total_files": result.total_files,
                "scanned_files": result.scanned_files,
                "new_findings": result.new_findings,
                "known_findings": result.known_findings,
                "clean": result.clean,
                "errors": result.errors,
                "duration": round(end_time - start_time, 1) if end_time else 0,
                "findings": list(result.findings[:200]),
            },
        )

    def list_summaries(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the fields required by the scanner history list."""
        fields = (
            "scan_id",
            "target_dir",
            "site_id",
            "site_name",
            "start_time",
            "end_time",
            "status",
            "total_files",
            "scanned_files",
            "new_findings",
            "known_findings",
            "clean",
            "duration",
        )
        text_fields = {"scan_id", "target_dir", "site_id", "site_name", "status"}
        return [
            {field: record.get(field, "" if field in text_fields else 0) for field in fields}
            for record in self._store.list_records(limit)
        ]

    def get_result(self, scan_id: str) -> dict[str, Any] | None:
        """Return one durable scan result after storage validates its identifier."""
        return self._store.get(scan_id)
