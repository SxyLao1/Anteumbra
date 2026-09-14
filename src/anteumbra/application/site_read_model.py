"""Site identity and per-site attribution for the admin read models.

Two rules shape this module.

The first is that a row's site label comes from the row.  The active filter is
an operator's current question, not evidence about a record, so a record is
labelled with its own ``site_id``/``site_name`` even while the page shows every
site.  Records persisted before multi-site support carry no site at all; they
are reported as *unassigned* instead of being assigned to whichever site
happens to be in focus.

The second is that a similarity cluster is not owned by a site.  The cluster
engine groups files by content, so one cluster can span roots.  Its members are
therefore counted per site — from the registry, which holds every detected path
and its site, not from the engine's truncated sample — and a cluster that has no
registry member falls back to the subset the engine reports, flagged as such.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Optional

# Site ids that mean "no site".  ``legacy`` is the bucket the resolver uses for
# a path outside every configured root, so it is data, not a real site.
UNASSIGNED_SITE_IDS = frozenset({"legacy"})

SITE_SOURCE_REGISTRY = "registry"
SITE_SOURCE_SAMPLE = "sample"


def site_names(websites: Iterable[Any] | None) -> dict[str, str]:
    """Return ``site_id -> configured name`` for projections missing a name."""
    names: dict[str, str] = {}
    for website in websites or ():
        site_id = str(getattr(website, "site_id", "") or "").strip().lower()
        if not site_id:
            continue
        names[site_id] = str(getattr(website, "name", "") or site_id)
    return names


def site_fields(
    record: Mapping[str, Any],
    *,
    names_by_id: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return one record's site identity without inventing a label.

    ``site_unassigned`` marks a row the templates must render as "unassigned"
    in the active language.  A configured name only fills a *missing* name and
    never replaces the name stored with the record.
    """
    raw_id = str(record.get("site_id") or "").strip().lower()
    if not raw_id or raw_id in UNASSIGNED_SITE_IDS:
        return {"site_id": "", "site_name": "", "site_unassigned": True}
    raw_name = str(record.get("site_name") or "").strip()
    name = raw_name or str((names_by_id or {}).get(raw_id, "")).strip() or raw_id
    return {"site_id": raw_id, "site_name": name, "site_unassigned": False}


def annotate_site(
    records: Iterable[dict[str, Any]],
    *,
    websites: Iterable[Any] | None = None,
) -> list[dict[str, Any]]:
    """Return copies of ``records`` carrying their own resolved site fields."""
    names = site_names(websites)
    annotated: list[dict[str, Any]] = []
    for record in records:
        entry = dict(record)
        entry.update(site_fields(record, names_by_id=names))
        annotated.append(entry)
    return annotated


def cluster_path_indexer(engine: Any) -> Optional[Callable[[list[str]], Mapping[str, Optional[str]]]]:
    """Adapt a cluster-lookup port into a ``path -> cluster_id`` mapping.

    The engine exposes ``get_cluster_for_files`` as its public lookup; nothing
    here reads engine internals.
    """
    lookup = getattr(engine, "get_cluster_for_files", None)
    if not callable(lookup):
        return None

    def _index(paths: list[str]) -> dict[str, Optional[str]]:
        snapshots = lookup(list(paths)) or {}
        return {
            str(path): (getattr(snapshot, "cluster_id", None) if snapshot else None)
            for path, snapshot in snapshots.items()
        }

    return _index


def cluster_site_index(
    records: Iterable[Mapping[str, Any]],
    *,
    cluster_id_for_paths: Optional[Callable[[list[str]], Mapping[str, Optional[str]]]] = None,
    names_by_id: Mapping[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Count every registry record per cluster and per site.

    The registry is the authoritative membership list: it stores one entry per
    detected path, with the site that owns that path.  The cluster engine is
    only asked which cluster a path belongs to, through its public lookup, so
    nothing here depends on engine internals.
    """
    entries = [record for record in records if record.get("file_path")]
    paths = [str(record.get("file_path")) for record in entries]
    lookup = dict(cluster_id_for_paths(paths)) if callable(cluster_id_for_paths) else {}

    index: dict[str, dict[str, Any]] = {}
    for record in entries:
        path = str(record.get("file_path"))
        cluster_id = lookup.get(path)
        if not cluster_id:
            continue
        bucket = index.setdefault(
            str(cluster_id),
            {"counts": {}, "names": {}, "unassigned": 0, "total": 0},
        )
        fields = site_fields(record, names_by_id=names_by_id)
        bucket["total"] += 1
        if fields["site_unassigned"]:
            bucket["unassigned"] += 1
            continue
        site_id = fields["site_id"]
        bucket["counts"][site_id] = bucket["counts"].get(site_id, 0) + 1
        bucket["names"].setdefault(site_id, fields["site_name"])
    return index


def cluster_site_view(
    cluster: Mapping[str, Any],
    index: Mapping[str, Mapping[str, Any]] | None,
    *,
    record_sites: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the per-site attribution shown next to one cluster row.

    Registry counts win.  When the registry knows no member of the cluster —
    for example a cluster built from an access-only record — the engine's
    sample paths are attributed instead and the row is flagged as inferred so
    the page can say so.
    """
    cluster_id = str(cluster.get("cluster_id") or "")
    bucket = (index or {}).get(cluster_id)
    source = SITE_SOURCE_REGISTRY
    if bucket and bucket.get("total"):
        counts = dict(bucket.get("counts") or {})
        names = dict(bucket.get("names") or {})
        unassigned = int(bucket.get("unassigned") or 0)
    else:
        counts, names, unassigned = _sample_counts(cluster, record_sites or {})
        source = SITE_SOURCE_SAMPLE

    entries = [
        {"site_id": site_id, "site_name": names.get(site_id, site_id), "count": count}
        for site_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    if unassigned:
        entries.append({"site_id": "", "site_name": "", "count": unassigned})

    return {
        "site_counts": entries,
        "site_primary": entries[0] if entries else None,
        "site_source": source,
        "site_inferred": source == SITE_SOURCE_SAMPLE and bool(entries),
        "site_multi": len([entry for entry in entries if entry["site_id"]]) > 1,
        "site_total": sum(int(entry["count"]) for entry in entries),
        "site_ids": [entry["site_id"] for entry in entries if entry["site_id"]],
    }


def _sample_counts(
    cluster: Mapping[str, Any],
    record_sites: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, int], dict[str, str], int]:
    """Attribute a cluster's engine-reported samples to their sites.

    A sample the registry does not know is left out rather than counted as
    unassigned: "no record of this path" and "a record with no site" are
    different answers, and only the second one may be labelled unassigned.
    """
    counts: dict[str, int] = {}
    names: dict[str, str] = {}
    unassigned = 0
    for path in cluster.get("sample_paths") or ():
        fields = record_sites.get(str(path))
        if not fields:
            continue
        if fields.get("site_unassigned"):
            unassigned += 1
            continue
        site_id = str(fields.get("site_id") or "")
        counts[site_id] = counts.get(site_id, 0) + 1
        names.setdefault(site_id, str(fields.get("site_name") or site_id))
    return counts, names, unassigned


def site_distribution_label(entries: Iterable[Mapping[str, Any]]) -> str:
    """Return a plain ``site ×count`` summary, for logs and JSON callers."""
    parts = []
    for entry in entries or ():
        name = entry.get("site_name") or entry.get("site_id") or "unassigned"
        parts.append(f"{name} x{int(entry.get('count') or 0)}")
    return ", ".join(parts)
