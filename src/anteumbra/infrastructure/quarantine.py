# -*- coding: utf-8 -*-
"""
@Time: 2026-06-09
@Auth: SxyLao1
@File: quarantine.py
@IDE: PyCharm
@Motto: HACK THE REAL

v1.7.9 新增：WebShell 自动隔离模块
- 检测到 WebShell 后自动移动到隔离目录
- 保留原文件目录结构（quarantine/ 内用相对路径）
- 隔离记录持久化到 JSON，支持恢复和永久删除
- 线程安全（RLock）
"""
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from anteumbra.infrastructure.utils.path_utils import normalize_path
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol

logger = logging.getLogger("monitor.quarantine")

# ============================================================================
# 全局状态
# ============================================================================
_quarantine_lock = threading.RLock()
_quarantine_dir: Optional[Path] = None
_quarantine_db: Optional[Path] = None

# v1.7.9: 恢复文件白名单 — 刚恢复的文件30秒内不被重新隔离
_recently_restored: dict = {}  # {normalized_path: expire_timestamp}
_restored_ttl = 30  # 秒


def _get_quarantine_dir() -> Path:
    """获取隔离目录路径，不存在则自动创建"""
    global _quarantine_dir
    if _quarantine_dir is None:
        from anteumbra.infrastructure.config.registry import ConfigRegistry
        config = ConfigRegistry.get_raw_config()
        quarantine_dir_name = config.get("quarantine_dir", "quarantine")
        _quarantine_dir = normalize_path(quarantine_dir_name)
    _quarantine_dir.mkdir(parents=True, exist_ok=True)
    return _quarantine_dir


def _get_db_path() -> Path:
    """获取隔离记录数据库路径"""
    global _quarantine_db
    if _quarantine_db is None:
        _quarantine_db = _get_quarantine_dir() / "quarantine.json"
    return _quarantine_db


def _load_db() -> List[Dict[str, Any]]:
    """加载隔离记录数据库。

    v2.0: Repository-first loading. When storage.backend is sqlite or both,
    reads from SQLite via Repository. Falls back to JSON when backend is json
    or Repository is unavailable.
    """
    # v2.0: Try Repository first (SQLite primary)
    try:
        from anteumbra.infrastructure.config.registry import ConfigRegistry
        config = ConfigRegistry.get_raw_config()
        backend = config.get("storage", {}).get("backend", "json")
        if backend != "json":
            from anteumbra.infrastructure.persistence import get_repository
            repo = get_repository("quarantine")
            records = repo.list_all(limit=999999)
            # v2.0 fix: SqliteRepository.list_all() always queries 'registry' table.
            # Validate that records have quarantine-specific fields (quarantine_id or status).
            if records and any(r.get("quarantine_id") or r.get("status") for r in records[:1]):
                return records
    except Exception:
        logger.debug("Repository load failed, falling back to JSON", exc_info=True)

    db_path = _get_db_path()
    if db_path.exists():
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            logger.debug("JSON load failed, falling back to disk recovery", exc_info=True)

    # 数据库不存在或损坏，尝试从磁盘文件恢复
    qdir = _get_quarantine_dir()
    recovered = []
    for date_dir in sorted(qdir.glob("*")):
        if not date_dir.is_dir():
            continue
        for f in sorted(date_dir.iterdir(), key=lambda x: x.name, reverse=True):
            match = re.match(r'(Q-\d{14}-[A-F0-9]{8})_(.+)', f.name)
            if not match:
                continue
            qid = match.group(1)
            original_name = match.group(2)
            ts_str = qid[2:16]
            try:
                from datetime import datetime
                ts = datetime.strptime(ts_str, "%Y%m%d%H%M%S")
            except Exception:
                ts = datetime.fromtimestamp(f.stat().st_mtime)
            recovered.append({
                "quarantine_id": qid,
                "original_path": f"(recovered)/{original_name}",
                "quarantine_path": str(f),
                "quarantine_time": ts.isoformat(),
                "rule_name": "(auto-recovered from disk)",
                "features": ["(recovered)"],
                "file_size": f.stat().st_size,
                "status": "quarantined",
            })
    if recovered:
        recovered.sort(key=lambda r: r["quarantine_time"], reverse=True)
        _save_db(recovered)
        log_with_symbol("quarantine_recover", "INFO",
                        f"[QUARANTINE] 自动从磁盘恢复 {len(recovered)} 条隔离记录")
    return recovered


def _repo_shadow_save_quarantine(records: List[Dict[str, Any]]) -> None:
    """v2.0: Shadow-write quarantine records to Repository interface.

    Best-effort — failures are silently ignored so JSON persistence
    (the primary store) is never impacted.
    """
    try:
        from anteumbra.infrastructure.persistence import get_repository
        repo = get_repository("quarantine")
        for item in records:
            key = item.get("quarantine_id", "")
            if key:
                try:
                    repo.save(key, dict(item))
                except Exception:
                    logger.debug("Repository shadow save quarantine item failed", exc_info=True)
    except Exception:
        logger.debug("Repository shadow save quarantine unavailable", exc_info=True)


def _save_db(records: List[Dict[str, Any]]) -> None:
    """保存隔离记录数据库（v1.7.9: 原子写入 + 备份，防断电/并发损坏）"""
    db_path = _get_db_path()
    tmp_path = db_path.with_suffix('.tmp')
    bak_path = db_path.with_suffix('.bak')

    # 1. 写入临时文件
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())

    # 2. 保留旧文件作为备份
    if db_path.exists():
        try:
            db_path.replace(bak_path)
        except OSError:
            pass  # Windows 上可能被占用，跳过备份

    # 3. 原子替换
    try:
        tmp_path.replace(db_path)
    except OSError:
        # Windows fallback: 先删目标再rename
        if db_path.exists():
            db_path.unlink()
        tmp_path.replace(db_path)

    # v2.0: Shadow-write to Repository for storage.backend = sqlite / both
    _repo_shadow_save_quarantine(records)


# ============================================================================
# 核心接口
# ============================================================================

def quarantine_file(
    file_path: str,
    rule_name: str,
    features: List[str],
    original_path: str = None
) -> Optional[Dict[str, Any]]:
    """
    隔离文件

    Args:
        file_path: 文件绝对路径（当前位置）
        rule_name: 命中的规则名
        features: 命中的特征列表
        original_path: 原始监控路径（用于恢复时放回正确位置）

    Returns:
        隔离记录 dict：{
            quarantine_id, original_path, quarantine_path,
            quarantine_time, rule_name, features, file_size, status
        }
    """
    with _quarantine_lock:
        src = normalize_path(file_path)
        if not src.exists():
            log_with_symbol("quarantine_skip", "WARNING",
                            f"[QUARANTINE] Source file not found, skip: {file_path}")
            return None

        quarantine_dir = _get_quarantine_dir()

        # 生成隔离ID：时间戳 + 8位随机hex
        qid = f"Q-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"

        # 隔离文件存放路径：quarantine/YYYY-MM-DD/<qid>_filename.ext
        date_dir = quarantine_dir / datetime.now().strftime("%Y-%m-%d")
        date_dir.mkdir(parents=True, exist_ok=True)

        quarantine_file = date_dir / f"{qid}_{src.name}"

        # 在移动前捕获文件大小（移动后 src 不存在会抛 FileNotFoundError）
        file_size = src.stat().st_size

        # v2.0 fix: Quarantining日志，让用户知道操作正在进行
        import logging as _logging
        log_with_symbol("quarantine_add", "info",
                        f"[QUARANTINE] Quarantining: {src.name} → {qid}", _logging.getLogger("monitor.quarantine"))

        # 移动文件（不是复制，原位置删除）
        try:
            shutil.move(str(src), str(quarantine_file))
        except FileNotFoundError:
            log_with_symbol("quarantine_skip", "WARNING",
                            f"[QUARANTINE] Source file deleted before move: {src}")
            return None
        except PermissionError:
            log_with_symbol("quarantine_skip", "WARNING",
                            f"[QUARANTINE] Permission denied, cannot move: {src}")
            return None

        # 记录元数据
        record = {
            "quarantine_id": qid,
            "original_path": str(original_path or src),
            "quarantine_path": str(quarantine_file),
            "quarantine_time": datetime.now().isoformat(),
            "rule_name": rule_name,
            "features": features,
            "file_size": file_size,
            "status": "quarantined",  # quarantined | restored | deleted
        }

        # 写入数据库
        records = _load_db()
        records.insert(0, record)  # 新记录放前面
        _save_db(records)

        log_with_symbol("quarantine_add", "INFO",
                        f"[QUARANTINE] File quarantined: {src.name} -> {qid}")

        return record


def restore_file(quarantine_id: str) -> Dict[str, Any]:
    """
    恢复隔离文件到原始位置

    Args:
        quarantine_id: 隔离ID

    Returns:
        更新后的隔离记录
    """
    with _quarantine_lock:
        records = _load_db()
        record = None
        for r in records:
            if r["quarantine_id"] == quarantine_id:
                record = r
                break

        if not record:
            raise ValueError(f"隔离记录不存在: {quarantine_id}")

        if record["status"] != "quarantined":
            raise ValueError(f"File not in quarantined status, cannot restore: {record['status']}")

        quarantine_path = normalize_path(record["quarantine_path"])
        original_path = normalize_path(record["original_path"])

        # 确保原始目录存在
        original_path.parent.mkdir(parents=True, exist_ok=True)

        # 移动回原始位置
        shutil.move(str(quarantine_path), str(original_path))

        # v1.7.9: 加入恢复白名单，30秒内不被重新隔离
        _recently_restored[str(original_path.resolve())] = time.time() + _restored_ttl

        # 更新记录状态
        record["status"] = "restored"
        record["restore_time"] = datetime.now().isoformat()
        _save_db(records)

        log_with_symbol("quarantine_restore", "INFO",
                        f"[QUARANTINE] File restored: {quarantine_id} -> {original_path}")

        return record


def delete_quarantine(quarantine_id: str) -> None:
    """
    永久删除隔离文件（不可恢复）

    Args:
        quarantine_id: 隔离ID
    """
    with _quarantine_lock:
        records = _load_db()
        record = None
        for r in records:
            if r["quarantine_id"] == quarantine_id:
                record = r
                break

        if not record:
            raise ValueError(f"隔离记录不存在: {quarantine_id}")

        quarantine_path = normalize_path(record["quarantine_path"])

        # 如果文件还在隔离目录，物理删除
        if quarantine_path.exists():
            quarantine_path.unlink()

        # 更新记录状态
        record["status"] = "deleted"
        record["delete_time"] = datetime.now().isoformat()
        _save_db(records)

        log_with_symbol("quarantine_delete", "INFO",
                        f"[QUARANTINE] File permanently deleted: {quarantine_id}")


def is_recently_restored(file_path: str) -> bool:
    """v1.7.9: 检查文件是否在恢复白名单内（刚恢复的文件暂不重新隔离）"""
    try:
        key = str(Path(file_path).resolve())
        expire = _recently_restored.get(key, 0)
        if time.time() < expire:
            return True
        # 过期清理
        if key in _recently_restored:
            del _recently_restored[key]
    except Exception:
        logger.debug("Failed to check recently restored whitelist", exc_info=True)
    return False


def get_quarantine_list(
    status: str = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    查询隔离记录列表

    Args:
        status: 筛选状态（quarantined/restored/deleted），None 表示全部
        limit: 返回数量
        offset: 偏移量

    Returns:
        隔离记录列表
    """
    records = _load_db()
    if status:
        records = [r for r in records if r["status"] == status]
    return records[offset:offset + limit]


def get_quarantine_detail(quarantine_id: str) -> Optional[Dict[str, Any]]:
    """获取单个隔离记录详情"""
    records = _load_db()
    for r in records:
        if r["quarantine_id"] == quarantine_id:
            return r
    return None


def get_quarantine_stats() -> Dict[str, int]:
    """获取隔离统计数字

    v2.0 fix: Use .get() for defensive access. SqliteRepository.list_all()
    may return records from the wrong table (registry vs quarantine), so
    we validate the returned records have the expected structure.
    """
    records = _load_db()
    # v2.0 fix: detect wrong-table records and reload from JSON directly
    if records and "status" not in records[0]:
        db_path = _get_db_path()
        if db_path.exists():
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    records = json.load(f)
            except Exception:
                records = []
    stats = {
        "total": len(records),
        "quarantined": sum(1 for r in records if r.get("status") == "quarantined"),
        "restored": sum(1 for r in records if r.get("status") == "restored"),
        "deleted": sum(1 for r in records if r.get("status") == "deleted"),
    }
    return stats
