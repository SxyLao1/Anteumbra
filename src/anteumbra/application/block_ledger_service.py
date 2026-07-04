# -*- coding: utf-8 -*-
"""
v1.0.9: Block Ledger Application Service

Thin facade over infrastructure.block_ledger.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from typing import Dict, List, Optional

from anteumbra.infrastructure.block_ledger import (
    add_entry,
    update_notes,
    get_entries,
    get_by_ip,
    get_stats,
    export_ledger,
    remove_entry,
)

__all__ = [
    "add_entry",
    "update_notes",
    "get_entries",
    "get_by_ip",
    "get_stats",
    "export_ledger",
    "remove_entry",
]
