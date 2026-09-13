"""Pure suspicious-record state transitions and query projection."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from anteumbra.domain.site import SiteIdentity


def create_detection_record(
    file_path: str,
    features: list[str],
    first_seen_ip: str | None,
    detection_source: str,
    identity: SiteIdentity,
    now: str,
    content_hash: str = "",
) -> dict[str, Any]:
    return {
        "file_path": file_path,
        "detected_at": now,
        "features": list(features),
        "alerted": False,
        "file_exists": True,
        # Digest of the last flagged content at this path, so a later "is this
        # the same file again?" question can be answered after the file is gone.
        "content_hash": str(content_hash or ""),
        "missing_at": None,
        "missing_reason": "",
        "first_seen_ip": first_seen_ip,
        "communication_count": 0,
        "deleted_at": None,
        "detection_source": detection_source,
        "marked_false_positive": False,
        "false_positive_reason": "",
        "false_positive_at": None,
        "quarantine_id": None,
        **identity.as_dict(),
    }


def refresh_detection_record(
    record: dict[str, Any],
    features: list[str],
    first_seen_ip: str | None,
    detection_source: str,
    identity: SiteIdentity,
    now: str,
    content_hash: str = "",
) -> None:
    existing_source = str(record.get("detection_source") or "passive")
    record.update(
        {
            "file_exists": True,
            # Detecting the file again means it is present again, so any earlier
            # "missing" state is cleared and the alert is re-armed. That is what
            # makes a deleted-then-re-uploaded webshell alert a second time.
            "missing_at": None,
            "missing_reason": "",
            "content_hash": str(content_hash or record.get("content_hash") or ""),
            "deleted_at": None,
            "alerted": False,
            "communication_count": 0,
            "first_seen_ip": first_seen_ip if first_seen_ip else record.get("first_seen_ip"),
            "detected_at": now,
            "features": list(features),
            "detection_source": detection_source
            if detection_source == "active"
            else existing_source,
            **identity.as_dict(),
        }
    )


def create_access_record(
    file_path: str,
    ip: str,
    identity: SiteIdentity,
    now: str,
) -> dict[str, Any]:
    return create_detection_record(
        file_path,
        ["AUTO_CREATED_BY_ACCESS"],
        ip,
        "log_heuristic",
        identity,
        now,
    ) | {"communication_count": 1}


def increment_access(record: dict[str, Any], ip: str) -> None:
    record["communication_count"] = int(record.get("communication_count", 0)) + 1
    if not record.get("first_seen_ip"):
        record["first_seen_ip"] = ip


def mark_alerted(record: dict[str, Any]) -> None:
    record["alerted"] = True


def mark_quarantined(record: dict[str, Any], quarantine_id: str, now: str) -> None:
    record.update(
        file_exists=False,
        quarantine_id=quarantine_id,
        quarantined_at=now,
    )


def mark_restored(record: dict[str, Any], now: str) -> None:
    record.update(
        file_exists=True,
        quarantine_id=None,
        restored_at=now,
        deleted_at=None,
    )


def mark_false_positive(record: dict[str, Any], reason: str, now: str) -> None:
    record.update(
        marked_false_positive=True,
        false_positive_at=now,
        false_positive_reason=reason,
    )


def unmark_false_positive(record: dict[str, Any], now: str) -> None:
    """Return a reviewed false positive to the active set.

    The timestamp is kept in ``false_positive_cleared_at`` so the audit trail
    still shows that a review happened, while the record counts as active.
    """
    record.update(
        marked_false_positive=False,
        false_positive_cleared_at=now,
    )


def mark_removed(record: dict[str, Any], now: str, reason: str = "") -> None:
    """Record that the file is no longer on disk.

    A threat record is about what was found, not about the file still being
    there, so the record is kept and only its state changes — otherwise a
    webshell that someone deletes would keep showing as active, and a later
    re-upload of the identical file could pass for "already handled".
    ``alerted`` is cleared so the file is reported again if it comes back;
    ``content_hash`` is kept because it still describes what was caught here.
    """
    record.update(
        file_exists=False,
        missing_at=now,
        missing_reason=str(reason or ""),
        alerted=False,
    )
    if not record.get("quarantine_id"):
        record["deleted_at"] = now


def mark_present(record: dict[str, Any], now: str) -> None:
    """Record that the path exists on disk again (re-uploaded or restored).

    Coming back from a recorded disappearance re-arms the alert, because the
    path held a flagged file, then held nothing, and now holds something again.
    A mere presence notification for a path that never went missing is not a
    re-detection and leaves the alert state alone.
    """
    rearmed = bool(record.get("missing_at"))
    record.update(
        file_exists=True,
        missing_at=None,
        missing_reason="",
        deleted_at=None,
    )
    if rearmed:
        record["alerted"] = False
        record["reappeared_at"] = now


def mark_soft_deleted(record: dict[str, Any], now: str) -> None:
    record.update(file_exists=False, deleted_at=now)


def project_records(
    records: list[dict[str, Any]],
    *,
    include_deleted: bool,
    include_false_positive: bool,
    site_id: str | None,
) -> list[dict[str, Any]]:
    projected = [
        copy.deepcopy(record)
        for record in records
        if (include_deleted or bool(record.get("file_exists", True)))
        and (include_false_positive or not bool(record.get("marked_false_positive", False)))
        and (site_id is None or record.get("site_id") == site_id)
    ]
    projected.sort(key=lambda item: str(item.get("detected_at", "")), reverse=True)
    return projected


def record_id(record: Mapping[str, Any]) -> str:
    return f"{record['site_id']}:{record['file_path']}"
