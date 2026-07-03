# -*- coding: utf-8 -*-
"""
Trident v1.9.2: 数据仓库实现层

提供 JSON 和 SQLite 两种 Repository 实现。
通过 config.toml [storage] backend 切换：
  - "json"   (默认，向后兼容)
  - "sqlite"  (高性能，WAL 模式)
  - "both"    (双写并行，SQLite 读优先)

v2.0: 新增 get_repository() 工厂函数，供所有持久化模块统一使用。
"""

import logging
import threading
from pathlib import Path
from typing import Dict, Optional, Any

from anteumbra.domain import Repository
from anteumbra.infrastructure.persistence.json_repository import JsonRepository
from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository, DualWriteRepository

logger = logging.getLogger(__name__)

__all__ = ["JsonRepository", "SqliteRepository", "DualWriteRepository", "get_repository"]

# ── Namespace → JSON file / SQLite table mapping ────────────

_NAMESPACE_MAP: Dict[str, tuple] = {
    # (json_file, json_key_field, sqlite_table, sqlite_key_column, sqlite_sort_column)
    "registry":        ("data/suspicious_registry.json", "file_path",    "registry",        "record_id",     "detected_at"),
    "quarantine":      ("data/quarantine/quarantine.json",  "quarantine_id", "quarantine",    "quarantine_id", "created_at"),
    "block_ledger":    ("data/block_ledger.json",          "ip",           "block_ledger",   "ip",            "blocked_at"),
    "threat_profiles": ("data/threat_graph.json",          "profile_id",   "threat_profiles", "profile_id",    "updated_at"),
}

# ── Singleton cache ─────────────────────────────────────────

_repo_cache: Dict[str, Repository] = {}
_repo_lock = threading.Lock()


def get_repository(namespace: str = "registry") -> Repository:
    """Get or create a Repository instance for the given namespace.

    Respects config.toml [storage] backend setting:
      - "json"   (default) — JsonRepository only
      - "sqlite" — SqliteRepository only
      - "both"   — DualWriteRepository (reads SQLite, writes both)

    Namespaces: "registry", "quarantine", "block_ledger", "threat_profiles"
    """
    global _repo_cache

    if namespace in _repo_cache:
        return _repo_cache[namespace]

    with _repo_lock:
        if namespace in _repo_cache:
            return _repo_cache[namespace]

        if namespace not in _NAMESPACE_MAP:
            raise ValueError(f"Unknown repository namespace: {namespace}. "
                             f"Valid: {list(_NAMESPACE_MAP.keys())}")

        json_file, key_field, sqlite_table, sqlite_key, sqlite_sort = _NAMESPACE_MAP[namespace]

        # Read storage backend from config
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            config = ConfigRegistry.get_raw_config()
            backend = config.get("storage", {}).get("backend", "json")
        except Exception:
            backend = "json"

        # Determine DB path from config or default
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            config = ConfigRegistry.get_raw_config()
            db_path = config.get("storage", {}).get("sqlite_path", "data/anteumbra.db")
        except Exception:
            db_path = "data/anteumbra.db"

        logger.info("Repository[%s]: backend=%s json=%s table=%s",
                     namespace, backend, json_file, sqlite_table)

        if backend == "json":
            from anteumbra.infrastructure.utils.path_utils import normalize_path
            repo = JsonRepository(normalize_path(json_file), key_field=key_field)
        elif backend == "sqlite":
            repo = SqliteRepository(db_path, table_name=sqlite_table, key_column=sqlite_key, sort_column=sqlite_sort)
        elif backend == "both":
            from anteumbra.infrastructure.utils.path_utils import normalize_path
            json_repo = JsonRepository(normalize_path(json_file), key_field=key_field)
            sql_repo = SqliteRepository(db_path, table_name=sqlite_table, key_column=sqlite_key, sort_column=sqlite_sort)
            repo = DualWriteRepository(json_repo, sql_repo)
        else:
            logger.warning("Unknown storage.backend '%s', falling back to json", backend)
            from anteumbra.infrastructure.utils.path_utils import normalize_path
            repo = JsonRepository(normalize_path(json_file), key_field=key_field)

        _repo_cache[namespace] = repo
        return repo


def clear_repository_cache():
    """Clear the repository singleton cache (used for testing)."""
    global _repo_cache
    with _repo_lock:
        _repo_cache.clear()
