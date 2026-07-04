# -*- coding: utf-8 -*-
"""
v1.0.9: Quarantine Application Service

Thin facade over infrastructure.quarantine.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from typing import Dict, List, Optional, Any

from anteumbra.infrastructure.quarantine import (
    quarantine_file,
    restore_file,
    delete_quarantine,
    is_recently_restored,
    get_quarantine_list,
    get_quarantine_detail,
    get_quarantine_stats,
)

__all__ = [
    "quarantine_file",
    "restore_file",
    "delete_quarantine",
    "is_recently_restored",
    "get_quarantine_list",
    "get_quarantine_detail",
    "get_quarantine_stats",
]
