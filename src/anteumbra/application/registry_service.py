# -*- coding: utf-8 -*-
"""
v1.0.9: Registry Application Service

Thin facade over infrastructure.suspicious_registry.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure

Blueprint code should import from here instead of directly from
infrastructure.suspicious_registry.
"""
from typing import Dict, List, Optional, Union
from pathlib import Path

from anteumbra.infrastructure.suspicious_registry import (
    add,
    get_all,
    remove,
    soft_delete_record,
    mark_alerted,
    mark_quarantined,
    mark_restored,
    mark_false_positive,
    is_suspicious,
    compact_registry,
    is_async_save_enabled,
    get_async_save_queue_size,
    get_registry_path,
    clear_memory_cache,
    migrate_site_metadata,
)

__all__ = [
    "add",
    "get_all",
    "remove",
    "soft_delete_record",
    "mark_alerted",
    "mark_quarantined",
    "mark_restored",
    "mark_false_positive",
    "is_suspicious",
    "compact_registry",
    "is_async_save_enabled",
    "get_async_save_queue_size",
    "get_registry_path",
    "clear_memory_cache",
    "migrate_site_metadata",
]
