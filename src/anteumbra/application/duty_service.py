"""Read-only duty queue projection for the admin overview.

The queue deliberately projects registry facts instead of persisting an
operator workflow.  In particular, a quarantine id is evidence that the file
entered quarantine; it is not evidence that the incident has been resolved.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from anteumbra.application.site_read_model import site_fields, site_names

DUTY_VIEWS = ("active", "missing", "quarantined", "reviewed", "unknown")
DUTY_PAGE_SIZE = 12


def _features(value: Any) -> list[str]:
    """Normalize registry list fields, including JSON text from SQLite."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    return [str(value)] if value else []


def _communication_count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _display_time(value: Any) -> str:
    stamp = str(value or "")
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return stamp or "—"
    # Preserve the distinction between a zoned instant and an older local
    # timestamp; stripping the offset makes a UTC detection look eight hours old.
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return parsed.strftime("%Y-%m-%d %H:%M")


def _quarantine_status(
    quarantine_id: str,
    quarantine_lookup: Callable[[str], dict[str, Any] | None] | None,
) -> str | None:
    """Return the persisted quarantine status, or ``None`` when unproven."""
    if not quarantine_id or not callable(quarantine_lookup):
        return None
    try:
        record = quarantine_lookup(quarantine_id)
    except Exception:
        return None
    if not isinstance(record, dict):
        return None
    status = record.get("status")
    return str(status).strip().lower() if status else None


def _view_for(
    record: dict[str, Any],
    *,
    quarantine_lookup: Callable[[str], dict[str, Any] | None] | None,
) -> str:
    """Classify only facts the registry currently establishes.

    ``file_exists`` can be absent in historical data.  Those records remain
    reachable in ``unknown`` rather than being promoted to active work.
    """
    quarantine_id = str(record.get("quarantine_id") or "").strip()
    if quarantine_id:
        status = _quarantine_status(quarantine_id, quarantine_lookup)
        if status == "quarantined":
            return "quarantined"
        if status not in {"restored", "deleted"}:
            return "unknown"
    if record.get("marked_false_positive"):
        return "reviewed"
    if record.get("file_exists") is True:
        return "active"
    if record.get("file_exists") is False:
        return "missing"
    return "unknown"


def _entry(
    record: dict[str, Any],
    *,
    names_by_id: dict[str, str],
    quarantine_lookup: Callable[[str], dict[str, Any] | None] | None,
) -> dict[str, Any]:
    features = _features(record.get("features"))
    path = str(record.get("file_path") or "")
    fields = site_fields(record, names_by_id=names_by_id)
    view = _view_for(record, quarantine_lookup=quarantine_lookup)
    return {
        "view": view,
        "file_path": path,
        "display_name": str(record.get("display_name") or Path(path).name or "unknown"),
        "detected_at": str(record.get("detected_at") or ""),
        "display_time": _display_time(record.get("detected_at")),
        "rule": features[0] if features else "Unknown",
        "communication_count": _communication_count(record.get("communication_count")),
        "quarantine_id": str(record.get("quarantine_id") or ""),
        "file_exists": record.get("file_exists"),
        **fields,
    }


def _sort_entries(entries: list[dict[str, Any]], view: str) -> None:
    """Keep pages stable; communicating active files precede newer detections."""
    entries.sort(key=lambda entry: (entry["file_path"], entry["site_id"]))
    entries.sort(key=lambda entry: entry["detected_at"], reverse=True)
    if view == "active":
        entries.sort(key=lambda entry: entry["communication_count"] > 0, reverse=True)


def build_duty_queue(
    registry: Any,
    *,
    websites: Iterable[Any] | None = None,
    site_id: str | None = None,
    quarantine_lookup: Callable[[str], dict[str, Any] | None] | None = None,
    view: str = "active",
    page: int = 1,
    per_page: int = DUTY_PAGE_SIZE,
) -> dict[str, Any]:
    """Return one paginated, site-scoped duty queue from registry facts."""
    selected_view = view if view in DUTY_VIEWS else "active"
    normalized_site_id = str(site_id).strip().lower() if site_id else None
    records = registry.get_all(
        include_deleted=True,
        include_false_positive=True,
        site_id=normalized_site_id,
    )
    names_by_id = site_names(websites)
    groups = {name: [] for name in DUTY_VIEWS}
    for raw_record in records:
        entry = _entry(
            dict(raw_record),
            names_by_id=names_by_id,
            quarantine_lookup=quarantine_lookup,
        )
        groups[entry["view"]].append(entry)

    for group_view, entries in groups.items():
        _sort_entries(entries, group_view)

    page_size = max(1, int(per_page))
    selected = groups[selected_view]
    total = len(selected)
    total_pages = max(1, (total + page_size - 1) // page_size)
    current_page = min(max(1, int(page)), total_pages)
    start = (current_page - 1) * page_size
    return {
        "view": selected_view,
        "records": selected[start : start + page_size],
        "counts": {name: len(entries) for name, entries in groups.items()},
        "page": current_page,
        "total_pages": total_pages,
        "total": total,
        "per_page": page_size,
    }
