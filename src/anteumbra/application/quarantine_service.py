# -*- coding: utf-8 -*-
"""
v1.0.9: Quarantine Application Service

Thin facade over infrastructure.quarantine.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
import logging
from typing import Any, Dict, List, Optional

from anteumbra.infrastructure.quarantine import (
    quarantine_file,
    rollback_quarantine,
    restore_file as _restore_file,
    rollback_restore,
    delete_quarantine,
    is_recently_restored,
    get_quarantine_list,
    get_quarantine_detail,
    get_quarantine_stats,
    migrate_site_metadata,
)

logger = logging.getLogger(__name__)


class QuarantineConsistencyError(RuntimeError):
    """Raised when quarantine storage and Registry cannot commit together."""


def quarantine_registered_file(
    file_path: str,
    rule_name: str,
    features: List[str],
    original_path: Optional[str] = None,
    site_id: Optional[str] = None,
    site_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Quarantine a detected file and commit its Registry state.

    The infrastructure operation guarantees consistency between the physical
    file and quarantine metadata.  This application operation extends that
    guarantee to the suspicious-file Registry.
    """
    record = quarantine_file(
        file_path,
        rule_name,
        features,
        original_path,
        site_id,
        site_name,
    )
    if record is None:
        return None

    from anteumbra.application.registry_service import mark_quarantined

    registry_site_id = record.get("site_id")
    marked = (
        mark_quarantined(file_path, record["quarantine_id"], registry_site_id)
        if registry_site_id
        else mark_quarantined(file_path, record["quarantine_id"])
    )
    if marked:
        return record

    try:
        rollback_quarantine(record["quarantine_id"])
    except Exception as rollback_error:
        logger.critical(
            "Registry update and quarantine rollback both failed for %s",
            record["quarantine_id"],
            exc_info=True,
        )
        raise QuarantineConsistencyError(
            "Registry update failed and quarantine rollback could not restore "
            f"{record['quarantine_id']}: {rollback_error}"
        ) from rollback_error

    raise QuarantineConsistencyError(
        f"Registry update failed; quarantine {record['quarantine_id']} was rolled back"
    )


def restore_file(quarantine_id: str) -> Dict[str, Any]:
    """Restore a quarantine record and synchronize a linked Registry record."""
    record_before = get_quarantine_detail(quarantine_id)
    if record_before is None:
        return _restore_file(quarantine_id)

    from anteumbra.application.registry_service import get_all, mark_restored
    from anteumbra.infrastructure.utils.path_utils import path_to_key

    original_path = record_before.get("original_path", "")
    registry_key = path_to_key(original_path)
    registry_site_id = record_before.get("site_id")
    has_registry_record = any(
        item.get("file_path") == registry_key
        for item in get_all(
            include_deleted=True,
            include_false_positive=True,
            site_id=registry_site_id,
        )
    )

    restored = _restore_file(quarantine_id)
    if not has_registry_record:
        return restored

    marked = (
        mark_restored(original_path, registry_site_id)
        if registry_site_id
        else mark_restored(original_path)
    )
    if marked:
        return restored

    try:
        rollback_restore(quarantine_id)
    except Exception as rollback_error:
        logger.critical(
            "Registry restore update and file rollback both failed for %s",
            quarantine_id,
            exc_info=True,
        )
        raise QuarantineConsistencyError(
            "Registry restore update failed and compensation could not restore "
            f"{quarantine_id}: {rollback_error}"
        ) from rollback_error

    raise QuarantineConsistencyError(
        f"Registry restore update failed; restore {quarantine_id} was rolled back"
    )

__all__ = [
    "quarantine_file",
    "quarantine_registered_file",
    "QuarantineConsistencyError",
    "restore_file",
    "delete_quarantine",
    "is_recently_restored",
    "get_quarantine_list",
    "get_quarantine_detail",
    "get_quarantine_stats",
    "migrate_site_metadata",
]
