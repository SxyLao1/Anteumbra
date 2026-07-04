# -*- coding: utf-8 -*-
"""
v1.0.9: WAL Application Service

Thin facade over infrastructure.wal_manager.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from typing import Dict, List, Optional
from pathlib import Path

from anteumbra.infrastructure.wal_manager import (
    write_entry,
    read_entries,
    archive_current_wal,
    replay,
    is_replaying,
    get_wal_info,
    get_wal_path,
    list_archives,
    get_status_text,
    read_wal_records,
)

__all__ = [
    "write_entry",
    "read_entries",
    "archive_current_wal",
    "replay",
    "is_replaying",
    "get_wal_info",
    "get_wal_path",
    "list_archives",
    "get_status_text",
    "read_wal_records",
]
