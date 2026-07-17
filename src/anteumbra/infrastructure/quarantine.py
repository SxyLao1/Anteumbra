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

def _record_score(record: Dict[str, Any]) -> int:
    """Prefer complete records over disk-recovered placeholders."""
    score = 0
    original_path = str(record.get("original_path", ""))
    rule_name = str(record.get("rule_name", ""))
    features = record.get("features") or []
    quarantine_path = record.get("quarantine_path")

    if original_path and not original_path.startswith("(recovered)/"):
        score += 4
    if rule_name and "auto-recovered" not in rule_name:
        score += 2
    if features and features != ["(recovered)"]:
        score += 1
    if quarantine_path and Path(quarantine_path).exists():
        score += 1
    return score


def _normalize_records(raw_records: Any) -> List[Dict[str, Any]]:
    """Normalize legacy list/dict stores and dedupe repeated quarantine IDs."""
    if isinstance(raw_records, dict):
        records = [r for r in raw_records.values() if isinstance(r, dict)]
    elif isinstance(raw_records, list):
        records = [r for r in raw_records if isinstance(r, dict)]
    else:
        return []

    by_qid: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for record in records:
        qid = str(record.get("quarantine_id", ""))
        if not qid:
            continue
        if qid not in by_qid:
            by_qid[qid] = record
            order.append(qid)
        elif _record_score(record) > _record_score(by_qid[qid]):
            by_qid[qid] = record
    return [by_qid[qid] for qid in order]



def _get_quarantine_dir() -> Path:
    """获取隔离目录路径，不存在则自动创建（线程安全）"""
    global _quarantine_dir
    if _quarantine_dir is None:
        with _quarantine_lock:
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
    """Load quarantine records.

    JSON is the primary store; Repository is a best-effort shadow copy.
    Prefer JSON to avoid stale placeholder records recovered from disk.
    """
    db_path = _get_db_path()
    if db_path.exists():
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                return _normalize_records(json.load(f))
        except Exception:
            logger.debug("JSON load failed, falling back to disk recovery", exc_info=True)

    try:
        from anteumbra.infrastructure.config.registry import ConfigRegistry
        config = ConfigRegistry.get_raw_config()
        backend = config.get("storage", {}).get("backend", "json")
        if backend != "json":
            from anteumbra.infrastructure.persistence import get_repository
            repo = get_repository("quarantine")
            records = _normalize_records(repo.list_all(limit=999999))
            if records and any(r.get("quarantine_id") or r.get("status") for r in records[:1]):
                return records
    except Exception:
        logger.debug("Repository load failed, falling back to disk recovery", exc_info=True)

    # Data store missing or corrupted; recover from quarantine files on disk.
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
        recovered = _normalize_records(recovered)
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
    if any(isinstance(r, dict) and r.get("quarantine_id") for r in records):
        records = _normalize_records(records)
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

        # Load metadata before moving the file.  If the JSON store is missing,
        # _load_db() recovers files already on disk; loading after the move
        # would mistake the new file for an orphan and create a placeholder.
        records = _load_db()
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

        # 写入数据库。元数据提交失败时必须把文件放回原处，避免出现
        # "文件已移动但隔离记录不可用" 的半成功状态。
        records.insert(0, record)  # 新记录放前面
        try:
            _save_db(records)
        except Exception as save_error:
            rollback_error = None
            try:
                src.parent.mkdir(parents=True, exist_ok=True)
                if quarantine_file.exists() and not src.exists():
                    shutil.move(str(quarantine_file), str(src))
            except Exception as exc:
                rollback_error = exc
                logger.critical(
                    "Quarantine metadata save and file rollback both failed: %s",
                    qid,
                    exc_info=True,
                )
            if rollback_error is not None:
                raise RuntimeError(
                    f"Quarantine metadata save failed and rollback failed for {qid}: "
                    f"{rollback_error}"
                ) from save_error
            raise

        log_with_symbol("quarantine_add", "INFO",
                        f"[QUARANTINE] File quarantined: {src.name} -> {qid}")

        return record


def rollback_quarantine(quarantine_id: str) -> Dict[str, Any]:
    """Undo a newly-created quarantine operation.

    This is used by the application service when Registry persistence fails
    after the quarantine store has committed.  The file and metadata are
    restored atomically from the caller's point of view.
    """
    with _quarantine_lock:
        records = _load_db()
        record = next(
            (item for item in records if item.get("quarantine_id") == quarantine_id),
            None,
        )
        if record is None:
            raise ValueError(f"Quarantine record not found: {quarantine_id}")
        if record.get("status") != "quarantined":
            raise ValueError(
                f"Quarantine record cannot be rolled back: {record.get('status')}"
            )

        quarantine_path = normalize_path(record["quarantine_path"])
        original_path = normalize_path(record["original_path"])
        if original_path.exists():
            raise FileExistsError(
                f"Cannot roll back quarantine; destination exists: {original_path}"
            )
        if not quarantine_path.exists():
            raise FileNotFoundError(
                f"Cannot roll back quarantine; stored file is missing: {quarantine_path}"
            )

        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(original_path))
        remaining = [item for item in records if item is not record]
        try:
            _save_db(remaining)
        except Exception as save_error:
            try:
                quarantine_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(original_path), str(quarantine_path))
            except Exception as rollback_error:
                logger.critical(
                    "Quarantine rollback metadata save and compensation both failed: %s",
                    quarantine_id,
                    exc_info=True,
                )
                raise RuntimeError(
                    f"Rollback persistence and compensation failed for {quarantine_id}: "
                    f"{rollback_error}"
                ) from save_error
            raise
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
        if original_path.exists():
            raise FileExistsError(
                f"Cannot restore quarantine; destination exists: {original_path}"
            )
        if not quarantine_path.exists():
            raise FileNotFoundError(
                f"Cannot restore quarantine; stored file is missing: {quarantine_path}"
            )

        # 确保原始目录存在
        original_path.parent.mkdir(parents=True, exist_ok=True)

        restore_key = str(original_path.resolve())
        previous_record = dict(record)
        _recently_restored[restore_key] = time.time() + _restored_ttl

        # 移动回原始位置
        try:
            shutil.move(str(quarantine_path), str(original_path))
        except Exception:
            _recently_restored.pop(restore_key, None)
            raise

        # 更新记录状态
        record["status"] = "restored"
        record["restore_time"] = datetime.now().isoformat()
        try:
            _save_db(records)
        except Exception as save_error:
            record.clear()
            record.update(previous_record)
            _recently_restored.pop(restore_key, None)
            try:
                quarantine_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(original_path), str(quarantine_path))
            except Exception as rollback_error:
                logger.critical(
                    "Restore metadata save and file rollback both failed: %s",
                    quarantine_id,
                    exc_info=True,
                )
                raise RuntimeError(
                    f"Restore persistence and rollback failed for {quarantine_id}: "
                    f"{rollback_error}"
                ) from save_error
            raise

        log_with_symbol("quarantine_restore", "INFO",
                        f"[QUARANTINE] File restored: {quarantine_id} -> {original_path}")

        return record


def rollback_restore(quarantine_id: str) -> Dict[str, Any]:
    """Compensate a restore when its linked Registry update fails."""
    with _quarantine_lock:
        records = _load_db()
        record = next(
            (item for item in records if item.get("quarantine_id") == quarantine_id),
            None,
        )
        if record is None:
            raise ValueError(f"Quarantine record not found: {quarantine_id}")
        if record.get("status") != "restored":
            raise ValueError(
                f"Restored record cannot be rolled back: {record.get('status')}"
            )

        quarantine_path = normalize_path(record["quarantine_path"])
        original_path = normalize_path(record["original_path"])
        if quarantine_path.exists():
            raise FileExistsError(
                f"Cannot roll back restore; quarantine destination exists: {quarantine_path}"
            )
        if not original_path.exists():
            raise FileNotFoundError(
                f"Cannot roll back restore; restored file is missing: {original_path}"
            )

        previous_record = dict(record)
        quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(original_path), str(quarantine_path))
        record["status"] = "quarantined"
        record.pop("restore_time", None)
        try:
            _save_db(records)
        except Exception as save_error:
            record.clear()
            record.update(previous_record)
            try:
                original_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(quarantine_path), str(original_path))
            except Exception as rollback_error:
                logger.critical(
                    "Restore rollback persistence and compensation both failed: %s",
                    quarantine_id,
                    exc_info=True,
                )
                raise RuntimeError(
                    f"Restore rollback persistence and compensation failed for "
                    f"{quarantine_id}: {rollback_error}"
                ) from save_error
            raise

        _recently_restored.pop(str(original_path.resolve()), None)
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
        previous_record = dict(record)
        delete_pending_path = None

        # Rename first so both metadata and the file can be compensated until
        # the final unlink succeeds.
        if quarantine_path.exists():
            delete_pending_path = quarantine_path.with_name(
                f"{quarantine_path.name}.delete-pending-{uuid.uuid4().hex[:8]}"
            )
            quarantine_path.replace(delete_pending_path)

        # 更新记录状态
        record["status"] = "deleted"
        record["delete_time"] = datetime.now().isoformat()
        try:
            _save_db(records)
            if delete_pending_path is not None:
                delete_pending_path.unlink()
        except Exception as delete_error:
            record.clear()
            record.update(previous_record)
            compensation_error = None
            try:
                if delete_pending_path is not None and delete_pending_path.exists():
                    delete_pending_path.replace(quarantine_path)
                _save_db(records)
            except Exception as exc:
                compensation_error = exc
                logger.critical(
                    "Quarantine deletion and compensation both failed: %s",
                    quarantine_id,
                    exc_info=True,
                )
            if compensation_error is not None:
                raise RuntimeError(
                    f"Deletion and compensation failed for {quarantine_id}: "
                    f"{compensation_error}"
                ) from delete_error
            raise

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
    with _quarantine_lock:
        records = _load_db()
        # v1.0.10: normalize field names — SQLite records may have created_at instead of quarantine_time
        for r in records:
            if isinstance(r, dict) and "quarantine_time" not in r and "created_at" in r:
                r["quarantine_time"] = r["created_at"]
        if status:
            records = [r for r in records if r["status"] == status]
        return records[offset:offset + limit]


def get_quarantine_detail(quarantine_id: str) -> Optional[Dict[str, Any]]:
    """获取单个隔离记录详情"""
    with _quarantine_lock:
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
    with _quarantine_lock:
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
        return {
            "total": len(records),
            "quarantined": sum(1 for r in records if r.get("status") == "quarantined"),
            "restored": sum(1 for r in records if r.get("status") == "restored"),
            "deleted": sum(1 for r in records if r.get("status") == "deleted"),
        }
