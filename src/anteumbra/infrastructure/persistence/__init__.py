# -*- coding: utf-8 -*-
"""
Repository implementation layer.

提供 JSON 和 SQLite 两种 Repository 实现。
通过 config.toml [storage] backend 切换：
  - "json"   (向后兼容)
  - "sqlite"  (高性能，WAL 模式)
  - "both"    (双写并行，JSON 权威读取，SQLite 用于检查和迁移)
"""

import logging
import threading
from pathlib import Path
from typing import Dict, Optional, Any

from anteumbra.domain import Repository
from anteumbra.infrastructure.persistence.json_repository import JsonRepository
from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository, DualWriteRepository

logger = logging.getLogger(__name__)

__all__ = [
    "JsonRepository",
    "SqliteRepository",
    "DualWriteRepository",
    "get_repository",
    "get_shadow_repository",
]

# ── Namespace → JSON file / SQLite table mapping ────────────

_NAMESPACE_MAP: Dict[str, tuple] = {
    # (json_file, json_key_field, sqlite_table, sqlite_key_column, sqlite_sort_column)
    "registry":        ("data/suspicious_registry.json", "file_path",    "registry",        "record_id",     "detected_at"),
    "quarantine":      ("data/quarantine/quarantine.json",  "quarantine_id", "quarantine",    "quarantine_id", "created_at"),
    "block_ledger":    ("data/block_ledger.json",          "record_id",    "block_ledger_entries", "record_id", "blocked_at"),
    "threat_profiles": ("data/threat_graph.json",          "profile_id",   "threat_profiles", "profile_id",    "updated_at"),
}

# ── Singleton cache ─────────────────────────────────────────

_repo_cache: Dict[str, Repository] = {}
_shadow_repo_cache: Dict[str, SqliteRepository] = {}
_repo_lock = threading.Lock()


def _storage_settings() -> tuple[str, str]:
    """Return the configured storage backend and SQLite path once per factory call."""
    try:
        from anteumbra.infrastructure.config.registry import ConfigRegistry

        storage = ConfigRegistry.get_raw_config().get("storage", {})
        backend = storage.get("backend", "json")
        db_path = storage.get("db_path") or storage.get(
            "sqlite_path", "data/anteumbra.db"
        )
        return backend, db_path
    except Exception:
        return "json", "data/anteumbra.db"


def get_repository(namespace: str = "registry") -> Repository:
    """Get or create a Repository instance for the given namespace.

    Respects config.toml [storage] backend setting:
      - "json"   (default) — JsonRepository only
      - "sqlite" — SqliteRepository only
      - "both"   — DualWriteRepository (reads JSON, writes both)

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

        backend, db_path = _storage_settings()
        backend = str(backend).strip().lower()

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


def get_shadow_repository(namespace: str = "registry") -> Optional[SqliteRepository]:
    """Return the SQLite shadow store without constructing a JSON repository.

    Core JSON-backed stores own their persistence because compatibility and
    recovery are domain behavior. In ``both`` mode, their SQLite copy must
    therefore be written independently: using a ``DualWriteRepository`` for
    Registry would treat a site-qualified SQLite key as the JSON ``file_path``
    key and corrupt the authoritative JSON record.
    """
    global _shadow_repo_cache

    if namespace not in _NAMESPACE_MAP:
        raise ValueError(f"Unknown repository namespace: {namespace}. "
                         f"Valid: {list(_NAMESPACE_MAP.keys())}")

    backend, db_path = _storage_settings()
    backend = str(backend).strip().lower()
    if backend not in {"sqlite", "both"}:
        return None

    if namespace in _shadow_repo_cache:
        return _shadow_repo_cache[namespace]

    with _repo_lock:
        if namespace in _shadow_repo_cache:
            return _shadow_repo_cache[namespace]

        _, _, sqlite_table, sqlite_key, sqlite_sort = _NAMESPACE_MAP[namespace]
        repo = SqliteRepository(
            db_path,
            table_name=sqlite_table,
            key_column=sqlite_key,
            sort_column=sqlite_sort,
        )
        _shadow_repo_cache[namespace] = repo
        return repo


def clear_repository_cache():
    """Clear the repository singleton cache (used for testing)."""
    global _repo_cache, _shadow_repo_cache
    with _repo_lock:
        for repository in [*_repo_cache.values(), *_shadow_repo_cache.values()]:
            close = getattr(repository, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    logger.debug(
                        "Repository close failed while clearing cache",
                        exc_info=True,
                    )
        _repo_cache.clear()
        _shadow_repo_cache.clear()
