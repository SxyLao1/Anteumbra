"""Site-aware dashboard read model assembled outside the Flask blueprints."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from anteumbra.application.site_read_model import site_fields, site_names
from anteumbra.domain.site import SiteIdentity


def _recent_events(
    records: list[dict[str, Any]],
    limit: int = 25,
    *,
    names_by_id: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in records[:limit]:
        fields = site_fields(record, names_by_id=names_by_id)
        events.append(
            {
                "time": str(record.get("detected_at", "N/A"))[:16],
                "file": Path(record.get("file_path", "")).name or "unknown",
                "path": str(record.get("file_path", "")),
                "rule": (record.get("features") or ["Unknown"])[0],
                "quarantined": bool(record.get("quarantine_id")),
                "false_positive": bool(record.get("marked_false_positive")),
                **fields,
            }
        )
    return events


def _protection_rate(quarantined: int, total: int) -> float:
    return round((min(quarantined, total) / total * 100), 1) if total else 0.0


def _last_detection(records: list[dict[str, Any]]) -> str:
    """Return the newest detection timestamp of one site, or ``""`` if none."""
    stamps = [str(record.get("detected_at") or "") for record in records]
    return max((stamp for stamp in stamps if stamp), default="")[:16]


def _open_suspicious(records: list[dict[str, Any]]) -> int:
    """Count unreviewed detections whose file is still on disk."""
    return sum(
        1
        for record in records
        if record.get("file_exists") and not record.get("marked_false_positive")
    )


def _memory_shell_suspects(
    site_id: str,
    snapshot_reader: Optional[Callable[[], Optional[dict[str, Any]]]],
) -> Optional[int]:
    """Return the probe's suspect count for one site, or ``None`` when unknown.

    ``None`` means "no figure exists" — the probe plugin never ran for this
    site, or its service is not attached — and the page renders ``-``.  Zero is
    only ever reported when the probe actually ran and found nothing.
    """
    if not callable(snapshot_reader):
        return None
    snapshot = snapshot_reader()
    if not isinstance(snapshot, dict):
        return None
    latest = snapshot.get("latest")
    if not isinstance(latest, dict):
        return None
    outcome = latest.get(site_id)
    if not isinstance(outcome, dict):
        return None
    raw = outcome.get("suspect_count")
    try:
        if raw is None:
            raw = len(outcome.get("report", {}).get("entries", []))
        return int(raw)
    except (TypeError, ValueError):
        return None


def build_dashboard_summary(
    site_id: Optional[str] = None,
    *,
    metrics,
    websites,
    registry,
    quarantine_stats_reader: Callable[..., dict[str, Any]],
    profile_reader: Optional[Callable[[str], Optional[dict[str, Any]]]] = None,
    memory_shell_reader: Optional[Callable[[], Optional[dict[str, Any]]]] = None,
) -> dict[str, Any]:
    """Return aggregate and per-site dashboard data for the admin overview.

    Every per-site figure is read once per site; a figure that cannot be read
    stays ``None`` so the template can show ``-`` instead of a false zero.
    """
    normalized_site_id = str(site_id).strip().lower() if site_id else None
    records = registry.get_all(
        include_deleted=True,
        include_false_positive=True,
        site_id=normalized_site_id,
    )
    quarantine_stats = quarantine_stats_reader(site_id=normalized_site_id)
    metric_sites = metrics.get().get("sites", {})
    names_by_id = site_names(websites)

    identities = {site.site_id: SiteIdentity(site.site_id, site.name) for site in websites}
    for record in records:
        identity = SiteIdentity.from_values(
            record.get("site_id"), record.get("site_name") or "Legacy / unassigned"
        )
        identities.setdefault(identity.site_id, identity)
    if normalized_site_id == "legacy":
        identities.setdefault("legacy", SiteIdentity.legacy())

    sites: list[dict[str, Any]] = []
    for identity in identities.values():
        if normalized_site_id and identity.site_id != normalized_site_id:
            continue
        site_records = [record for record in records if record.get("site_id") == identity.site_id]
        site_quarantine = quarantine_stats_reader(site_id=identity.site_id)
        false_positives = sum(1 for record in site_records if record.get("marked_false_positive"))
        top_profile = profile_reader(identity.site_id) if callable(profile_reader) else None
        sites.append(
            {
                **identity.as_dict(),
                "total_detections": len(site_records),
                "quarantined": site_quarantine.get("quarantined", 0),
                "false_positives": false_positives,
                "protection_rate": _protection_rate(
                    site_quarantine.get("quarantined", 0), len(site_records)
                ),
                "open_suspicious": _open_suspicious(site_records),
                "last_detection": _last_detection(site_records) or None,
                "top_profile": top_profile,
                "memory_shell_suspects": _memory_shell_suspects(
                    identity.site_id, memory_shell_reader
                ),
                "metrics": dict(metric_sites.get(identity.site_id, {})),
            }
        )

    false_positives = sum(1 for record in records if record.get("marked_false_positive"))
    aggregate = {
        "total_detections": len(records),
        "quarantined": quarantine_stats.get("quarantined", 0),
        "false_positives": false_positives,
        "protection_rate": _protection_rate(quarantine_stats.get("quarantined", 0), len(records)),
        "open_suspicious": _open_suspicious(records),
    }
    return {
        "aggregate": aggregate,
        "recent_events": _recent_events(records, names_by_id=names_by_id),
        "sites": sorted(sites, key=lambda item: item["site_id"]),
    }
