# -*- coding: utf-8 -*-
"""
v1.9.2: SQLite 仓库实现

实现 Repository 和 EventRepository 接口。
特性：
  - WAL 模式（高并发读）
  - 线程安全（threading.local 连接池）
  - 自动建表 + 迁移（首次启动 / 升级）
  - 外键约束（ON DELETE SET NULL）
  - 双写模式兼容（与 JSON 并行写入）

v1.0.4 优化:
  - Registry foreign keys to quarantine and threat profiles
  - 5 条新索引 (profile_id, deleted_at, blocked_at, status, last_seen)
  - 表创建顺序保证引用完整性
  - 自动迁移：检测缺失 FK → 重建受影响的表
"""

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from anteumbra.domain import EventRepository

logger = logging.getLogger(__name__)

# ── SQL Schema ────────────────────────────────────────────
# 表顺序有讲究：被引用的表必须先创建，否则 FK 约束会失败。
# Core entities plus site-qualified block ledger, scan history, and WAL events.

SCHEMA_VERSION = 4  # 递增以触发迁移

SCHEMA = {
    # ── 独立表（被其他表引用）─────────────────────────────
    "quarantine": """
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quarantine_id TEXT UNIQUE NOT NULL,
            original_path TEXT NOT NULL,
            quarantine_path TEXT,
            rule_name TEXT,
            features TEXT,              -- JSON array
            file_size INTEGER DEFAULT 0,
            status TEXT DEFAULT 'quarantined',
            created_at TEXT DEFAULT (datetime('now')),
            restored_at TEXT,
            site_id TEXT,
            site_name TEXT,
            raw_json TEXT
        )
    """,
    "threat_profiles": """
        CREATE TABLE IF NOT EXISTS threat_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id TEXT UNIQUE NOT NULL,
            site_id TEXT,
            site_name TEXT,
            ua_fingerprint TEXT,
            tool_signature TEXT,
            risk_score REAL DEFAULT 0,
            ip_pool TEXT,               -- JSON array
            target_files TEXT,          -- JSON array
            target_urls TEXT,           -- JSON array
            attack_chain TEXT,          -- JSON array
            status TEXT DEFAULT 'active',
            decay_factor REAL DEFAULT 1.0,
            last_seen TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            raw_json TEXT
        )
    """,
    # ── 依赖表（引用 quarantine / threat_profiles）─────────
    "registry": """
        CREATE TABLE IF NOT EXISTS registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT UNIQUE NOT NULL,
            file_path TEXT NOT NULL,
            display_name TEXT,
            detected_at TEXT,
            features TEXT,              -- JSON array
            file_exists INTEGER DEFAULT 1,
            file_size INTEGER DEFAULT 0,
            communication_count INTEGER DEFAULT 0,
            first_seen_ip TEXT,
            alerted INTEGER DEFAULT 0,
            marked_false_positive INTEGER DEFAULT 0,
            false_positive_at TEXT,
            quarantine_id TEXT,
            quarantined_at TEXT,
            profile_id TEXT,
            deleted_at TEXT,
            detection_source TEXT DEFAULT 'passive',
            site_id TEXT,
            site_name TEXT,
            raw_json TEXT,              -- 完整 JSON 备份（兼容性）
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (quarantine_id) REFERENCES quarantine(quarantine_id) ON DELETE SET NULL,
            FOREIGN KEY (profile_id) REFERENCES threat_profiles(profile_id) ON DELETE SET NULL
        )
    """,
    "block_ledger_entries": """
        CREATE TABLE IF NOT EXISTS block_ledger_entries (
            record_id TEXT PRIMARY KEY,
            site_id TEXT NOT NULL,
            site_name TEXT NOT NULL,
            ip TEXT NOT NULL,
            source TEXT DEFAULT 'manual',
            reason TEXT,
            notes TEXT DEFAULT '',
            profile_id TEXT,
            blocked_by TEXT DEFAULT 'system',
            broadcast_devices TEXT,     -- JSON array
            broadcast_status TEXT DEFAULT 'success',
            status TEXT DEFAULT 'blocked',
            blocked_at TEXT DEFAULT (datetime('now')),
            unblocked_at TEXT,
            unblocked_by TEXT,
            raw_json TEXT,
            updated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(site_id, ip)
        )
    """,
    # ── 独立日志表 ──────────────────────────────────────
    "scan_history": """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            target_dir TEXT NOT NULL,
            start_time REAL,
            end_time REAL,
            status TEXT DEFAULT 'completed',
            total_files INTEGER DEFAULT 0,
            scanned_files INTEGER DEFAULT 0,
            new_findings INTEGER DEFAULT 0,
            known_findings INTEGER DEFAULT 0,
            clean INTEGER DEFAULT 0,
            errors INTEGER DEFAULT 0,
            duration REAL DEFAULT 0,
            findings TEXT,              -- JSON array (max 200)
            site_id TEXT,
            site_name TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """,
    "wal_events": """
        CREATE TABLE IF NOT EXISTS wal_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT,
            payload TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """,
}

# 索引（加速常见查询）
INDEXES = [
    # registry — 高频查询列
    "CREATE INDEX IF NOT EXISTS idx_registry_file_path ON registry(file_path)",
    "CREATE INDEX IF NOT EXISTS idx_registry_quarantine ON registry(quarantine_id)",
    "CREATE INDEX IF NOT EXISTS idx_registry_profile ON registry(profile_id)",
    "CREATE INDEX IF NOT EXISTS idx_registry_detected ON registry(detected_at)",
    "CREATE INDEX IF NOT EXISTS idx_registry_deleted ON registry(deleted_at)",
    "CREATE INDEX IF NOT EXISTS idx_registry_site_path ON registry(site_id, file_path)",
    # quarantine
    "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status)",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_site ON quarantine(site_id)",
    # site-qualified block ledger
    "CREATE INDEX IF NOT EXISTS idx_block_ledger_site_ip ON block_ledger_entries(site_id, ip)",
    "CREATE INDEX IF NOT EXISTS idx_block_ledger_source ON block_ledger_entries(source)",
    "CREATE INDEX IF NOT EXISTS idx_block_ledger_time ON block_ledger_entries(blocked_at)",
    # scan_history
    "CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(start_time)",
    "CREATE INDEX IF NOT EXISTS idx_scan_history_site ON scan_history(site_id)",
    # threat_profiles — 排序 + 筛选
    "CREATE INDEX IF NOT EXISTS idx_threat_profiles_score ON threat_profiles(risk_score)",
    "CREATE INDEX IF NOT EXISTS idx_threat_profiles_status ON threat_profiles(status)",
    "CREATE INDEX IF NOT EXISTS idx_threat_profiles_last_seen ON threat_profiles(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_threat_profiles_site ON threat_profiles(site_id)",
]

# 外键期望清单 — 用于迁移检测
_EXPECTED_FOREIGN_KEYS = {
    "registry": {
        ("quarantine_id", "quarantine", "quarantine_id"),
        ("profile_id", "threat_profiles", "profile_id"),
    },
}

_REQUIRED_COLUMNS = {
    "registry": {
        "site_id": "TEXT",
        "site_name": "TEXT",
        "raw_json": "TEXT",
    },
    "quarantine": {
        "site_id": "TEXT",
        "site_name": "TEXT",
        "raw_json": "TEXT",
    },
    "scan_history": {
        "site_id": "TEXT",
        "site_name": "TEXT",
    },
    "threat_profiles": {
        "site_id": "TEXT",
        "site_name": "TEXT",
        "raw_json": "TEXT",
    },
}


# ── SqliteRepository ──────────────────────────────────────


class SqliteRepository(EventRepository):
    """基于 SQLite 的数据仓库，实现 Repository + EventRepository 接口

    v2.0 fix: ``table_name`` parameter routes data to the correct table.
    Previously every namespace (registry, quarantine, block ledger,
    threat_profiles) was hardcoded to INSERT INTO ``registry``.

    v1.0.8 fix: table_name is now validated against an allowlist to prevent
    SQL injection via f-string table name interpolation.
    """

    _ALLOWED_TABLE_NAMES = {
        "registry",
        "quarantine",
        "block_ledger_entries",
        "threat_profiles",
        "scan_history",
        "wal_events",
    }
    _schema_lock = threading.RLock()

    def __init__(
        self,
        db_path: str = "data/anteumbra.db",
        table_name: str = "registry",
        key_column: str = "record_id",
        sort_column: str = "detected_at",
    ):
        if table_name not in self._ALLOWED_TABLE_NAMES:
            raise ValueError(
                f"Invalid table name: {table_name!r}. Allowed: {sorted(self._ALLOWED_TABLE_NAMES)}"
            )
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._table = table_name
        self._key_column = key_column
        self._sort_column = sort_column
        self._local = threading.local()
        self._ensure_schema()
        # Cache column names for the target table (used in save() filtering)
        self._columns = self._discover_columns()

    def _discover_columns(self) -> set:
        """Return the set of column names actually present in ``self._table``."""
        conn = self._get_conn()
        rows = conn.execute(f"PRAGMA table_info({self._table})").fetchall()
        return {r["name"] for r in rows}

    # ── 连接管理 ────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """获取当前线程的数据库连接（自动创建）"""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False, timeout=2.0)
            # SQLite shadows must never hold up authoritative JSON workflows.
            conn.execute("PRAGMA busy_timeout=2000")
            conn.execute("PRAGMA journal_mode=WAL")  # 高并发读
            conn.execute("PRAGMA synchronous=NORMAL")  # 平衡性能/安全
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _ensure_schema(self):
        """建表 + 索引 + 迁移（幂等）"""
        # Schema DDL can acquire an exclusive SQLite lock. Serialize it within
        # this process so concurrent shadow repositories do not block each
        # other during startup or tests.
        with self._schema_lock:
            conn = self._get_conn()
            for table_name, ddl in SCHEMA.items():
                conn.execute(ddl)
            self._ensure_required_columns(conn)
            for idx in INDEXES:
                conn.execute(idx)
            conn.commit()
            self._run_migrations()
        logger.info("SqliteRepository: schema ready at %s", self._db_path)

    @staticmethod
    def _ensure_required_columns(conn) -> None:
        """Add backward-compatible columns before site-aware indexes are created."""
        for table_name, columns in _REQUIRED_COLUMNS.items():
            existing = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            }
            for column_name, declaration in columns.items():
                if column_name not in existing:
                    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {declaration}")

    def _run_migrations(self):
        """检测并添加缺失的外键约束（表重建实现）。

        SQLite 不支持 ALTER TABLE ADD CONSTRAINT FK，
        所以采用 CREATE...INSERT...DROP...RENAME 重建。
        幂等：外键已齐全则跳过。
        """
        conn = self._get_conn()

        for table_name, expected_fks in _EXPECTED_FOREIGN_KEYS.items():
            # 检查当前外键
            existing = conn.execute(f"PRAGMA foreign_key_list({table_name})").fetchall()
            existing_set = {(r["from"], r["table"], r["to"]) for r in existing}

            if existing_set >= expected_fks:
                continue  # 外键已齐全

            logger.info(
                "[MIGRATE] %s — adding %d FK constraint(s) (current: %d)",
                table_name,
                len(expected_fks),
                len(existing_set),
            )

            # 1) 从 SCHEMA 提取 DDL，替换表名生成带 FK 的新表
            ddl = SCHEMA[table_name]
            temp_name = f"{table_name}_v2"
            new_ddl = ddl.replace(
                f"CREATE TABLE IF NOT EXISTS {table_name}", f"CREATE TABLE {temp_name}"
            )

            conn.execute(f"DROP TABLE IF EXISTS {temp_name}")
            conn.execute(new_ddl)

            # 2) 复制数据（列名从旧表 PRAGMA 获取，保证兼容）
            columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            col_names = [c["name"] for c in columns]
            cols_str = ", ".join(col_names)
            conn.execute(
                f"INSERT INTO {temp_name} ({cols_str}) SELECT {cols_str} FROM {table_name}"
            )

            # 3) 替换旧表
            conn.execute(f"DROP TABLE {table_name}")
            conn.execute(f"ALTER TABLE {temp_name} RENAME TO {table_name}")

            # 4) 重建索引
            for idx_sql in INDEXES:
                if table_name in idx_sql:
                    conn.execute(idx_sql)

            logger.info("[MIGRATE] %s — FK constraints added", table_name)

        conn.commit()

    @staticmethod
    def _row_to_data(row) -> Dict[str, Any]:
        """Restore shadowed JSON fields that do not have first-class columns."""
        data = dict(row)
        raw_json = data.get("raw_json")
        if isinstance(raw_json, str) and raw_json:
            try:
                raw_data = json.loads(raw_json)
            except (TypeError, json.JSONDecodeError):
                raw_data = None
            if isinstance(raw_data, dict):
                raw_data.update({key: value for key, value in data.items() if value is not None})
                data = raw_data

        value = data.get("features")
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (TypeError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, list):
                data["features"] = parsed
        return data

    # ── Repository 接口 ──────────────────────────────────

    def save(self, record_id: str, data: Dict[str, Any]) -> None:
        """保存或更新一条记录（自动判断 INSERT vs UPDATE）

        v2.0 fix: Routes to correct table (self._table) and filters unknown
        columns so extra data-dict fields don't cause "no column named X".
        """
        conn = self._get_conn()
        row = dict(data)
        if "raw_json" in self._columns:
            row["raw_json"] = json.dumps(data, ensure_ascii=False, default=str)
        for k, v in row.items():
            if isinstance(v, (list, dict)):
                row[k] = json.dumps(v, ensure_ascii=False, default=str)
        row[self._key_column] = record_id

        # Filter to only columns that actually exist in the table
        known = sorted(c for c in row if c in self._columns)
        placeholders = [f":{c}" for c in known]
        updates = [f"{c}=excluded.{c}" for c in known if c != self._key_column]

        sql = f"INSERT INTO {self._table} ({','.join(known)}) VALUES ({','.join(placeholders)}) ON CONFLICT({self._key_column}) DO UPDATE SET {','.join(updates)}"
        # Append updated_at only if the column exists
        if "updated_at" in self._columns:
            sql += ", updated_at=datetime('now')"
        conn.execute(sql, {c: row[c] for c in known})
        conn.commit()

    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            f"SELECT * FROM {self._table} WHERE {self._key_column}=?", (record_id,)
        ).fetchone()
        return self._row_to_data(row) if row else None

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(
            f"SELECT * FROM {self._table} ORDER BY {self._sort_column} DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [self._row_to_data(row) for row in rows]

    # Whitelist of allowed query columns (prevents SQL injection via filter keys)
    _ALLOWED_COLUMNS = {
        "id",
        "record_id",
        "file_path",
        "display_name",
        "detected_at",
        "file_exists",
        "communication_count",
        "first_seen_ip",
        "alerted",
        "marked_false_positive",
        "quarantine_id",
        "deleted_at",
        "detection_source",
        "status",
        "source",
        "ip",
        "blocked_by",
        "broadcast_status",
        "site_id",
        "site_name",
    }

    def query(
        self, filters: Dict[str, Any], limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        where = []
        params = []
        for k, v in filters.items():
            if k not in self._ALLOWED_COLUMNS:
                raise ValueError(f"Invalid filter column: {k}")
            where.append(f"{k}=?")
            params.append(v)
        sql = f"SELECT * FROM {self._table}"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY {self._sort_column} DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [self._row_to_data(row) for row in rows]

    def delete(self, record_id: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute(f"DELETE FROM {self._table} WHERE {self._key_column}=?", (record_id,))
        conn.commit()
        return cur.rowcount > 0

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        conn = self._get_conn()
        if filters:
            for k in filters:
                if k not in self._ALLOWED_COLUMNS:
                    raise ValueError(f"Invalid filter column: {k}")
            where = " WHERE " + " AND ".join(f"{k}=?" for k in filters)
            params = list(filters.values())
            row = conn.execute(f"SELECT COUNT(*) FROM {self._table}{where}", params).fetchone()
        else:
            row = conn.execute(f"SELECT COUNT(*) FROM {self._table}").fetchone()
        return row[0] if row else 0

    # ── EventRepository 接口 ─────────────────────────────

    def append(self, event: Dict[str, Any]) -> None:
        """追加 WAL 事件"""
        conn = self._get_conn()
        row = {
            "event_type": event.get("event_type", "unknown"),
            "timestamp": event.get("timestamp", ""),
            "source": event.get("source", ""),
            "payload": json.dumps(event.get("payload", {}), ensure_ascii=False, default=str),
        }
        conn.execute(
            "INSERT INTO wal_events (event_type, timestamp, source, payload) VALUES (:event_type, :timestamp, :source, :payload)",
            row,
        )
        conn.commit()

    def replay(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        if since:
            rows = conn.execute(
                "SELECT * FROM wal_events WHERE timestamp > ? ORDER BY timestamp", (since,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM wal_events ORDER BY timestamp").fetchall()
        return [dict(r) for r in rows]

    # ── 扩展方法 ─────────────────────────────────────────

    def save_quarantine(self, qid: str, data: Dict[str, Any]) -> None:
        conn = self._get_conn()
        row = dict(data)
        for k, v in row.items():
            if isinstance(v, (list, dict)):
                row[k] = json.dumps(v, ensure_ascii=False, default=str)
        row["quarantine_id"] = qid
        columns = list(row.keys())
        ph = [f":{c}" for c in columns]
        ups = [f"{c}=excluded.{c}" for c in columns if c != "quarantine_id"]
        conn.execute(
            f"INSERT INTO quarantine ({','.join(columns)}) VALUES ({','.join(ph)}) ON CONFLICT(quarantine_id) DO UPDATE SET {','.join(ups)}",
            row,
        )
        conn.commit()

    def save_scan(self, scan_id: str, data: Dict[str, Any]) -> None:
        conn = self._get_conn()
        row = dict(data)
        for k, v in row.items():
            if isinstance(v, (list, dict)):
                row[k] = json.dumps(v, ensure_ascii=False, default=str)
        row["scan_id"] = scan_id
        columns = list(row.keys())
        ph = [f":{c}" for c in columns]
        conn.execute(
            f"INSERT OR REPLACE INTO scan_history ({','.join(columns)}) VALUES ({','.join(ph)})",
            row,
        )
        conn.commit()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scan_history WHERE scan_id=?", (scan_id,)).fetchone()
        if row:
            d = dict(row)
            if d.get("findings") and isinstance(d["findings"], str):
                try:
                    d["findings"] = json.loads(d["findings"])
                except json.JSONDecodeError:
                    pass
            return d
        return None

    def get_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        """关闭当前线程的数据库连接"""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    @contextmanager
    def transaction(self):
        """事务上下文管理器"""
        conn = self._get_conn()
        try:
            yield
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# ── 双写适配器 ──────────────────────────────────────────


class DualWriteRepository:
    """Write JSON and SQLite, with JSON as the authoritative read store.

    用法：
        from anteumbra.infrastructure.persistence.json_repository import JsonRepository
        json_repo = JsonRepository(Path("data/registry.json"), key_field="file_path")
        sql_repo = SqliteRepository("data/anteumbra.db")
        repo = DualWriteRepository(json_repo, sql_repo)
    """

    def __init__(self, json_repo, sql_repo):
        self._json = json_repo
        self._sql = sql_repo

    def save(self, record_id: str, data: Dict[str, Any]) -> None:
        self._json.save(record_id, data)
        try:
            self._sql.save(record_id, data)
        except Exception as e:
            logger.warning("DualWrite: SQLite save failed for %s: %s", record_id, e)

    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        record = self._json.get(record_id)
        if record is not None:
            return record
        try:
            return self._sql.get(record_id)
        except Exception:
            logger.debug("SQLite fallback get failed for record %s", record_id, exc_info=True)
            return None

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        try:
            return self._json.list_all(limit, offset)
        except Exception:
            return self._sql.list_all(limit, offset)

    def query(
        self, filters: Dict[str, Any], limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        try:
            return self._json.query(filters, limit, offset)
        except Exception:
            return self._sql.query(filters, limit, offset)

    def delete(self, record_id: str) -> bool:
        ok = self._json.delete(record_id)
        try:
            self._sql.delete(record_id)
        except Exception:
            logger.debug(
                "SQLite delete failed for record %s, JSON delete was OK", record_id, exc_info=True
            )
        return ok

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        try:
            return self._json.count(filters)
        except Exception:
            return self._sql.count(filters)

    def close(self) -> None:
        """Release the SQLite connection when a repository cache is cleared."""
        self._sql.close()
