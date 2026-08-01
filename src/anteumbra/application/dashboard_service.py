"""Site-aware dashboard read model assembled outside the Flask blueprints."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from anteumbra.domain.site import SiteIdentity


def _recent_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in records[:5]:
        events.append(
            {
                "time": str(record.get("detected_at", "N/A"))[:16],
                "file": Path(record.get("file_path", "")).name or "unknown",
                "rule": (record.get("features") or ["Unknown"])[0],
                "quarantined": bool(record.get("quarantine_id")),
                "false_positive": bool(record.get("marked_false_positive")),
                "site_id": record.get("site_id", "legacy"),
                "site_name": record.get("site_name", "Legacy / unassigned"),
            }
        )
    return events


def _protection_rate(quarantined: int, total: int) -> float:
    return round((min(quarantined, total) / total * 100), 1) if total else 0.0


def build_dashboard_summary(
    site_id: Optional[str] = None,
    *,
    metrics,
    websites,
    registry,
    quarantine_stats_reader: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """Return aggregate and per-site dashboard data without a UI site selector."""
    normalized_site_id = str(site_id).strip().lower() if site_id else None
    records = registry.get_all(
        include_deleted=True,
        include_false_positive=True,
        site_id=normalized_site_id,
    )
    quarantine_stats = quarantine_stats_reader(site_id=normalized_site_id)
    metric_sites = metrics.get().get("sites", {})

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
        sites.append(
            {
                **identity.as_dict(),
                "total_detections": len(site_records),
                "quarantined": site_quarantine.get("quarantined", 0),
                "false_positives": false_positives,
                "protection_rate": _protection_rate(
                    site_quarantine.get("quarantined", 0), len(site_records)
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
    }
    return {
        "aggregate": aggregate,
        "recent_events": _recent_events(records),
        "sites": sorted(sites, key=lambda item: item["site_id"]),
    }
