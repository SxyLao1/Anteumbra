"""Trident WAL管理器 - 高内聚低耦合封装
v1.8.4: 从 suspicious_registry.py 中完整迁移 WAL 功能
"""
import json
import logging
import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import normalize_path, path_to_key
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol

logger = logging.getLogger("monitor.wal_manager")

# WAL 状态
_WAL_PATH: Optional[Path] = None
_replaying = False
_replay_lock = threading.Lock()


def _init_wal_path():
    """初始化 WAL 路径"""
    global _WAL_PATH
    if _WAL_PATH is None:
        try:
            config = ConfigRegistry.get_raw_config()
            paths = config.get("paths", {})
            data_dir = normalize_path(paths.get("data_dir", "data"))
        except Exception:
            data_dir = normalize_path("data")
        data_dir.mkdir(parents=True, exist_ok=True)
        _WAL_PATH = data_dir / "registry_wal.log"


def get_wal_path() -> Optional[Path]:
    """获取当前 WAL 文件路径"""
    _init_wal_path()
    return _WAL_PATH


def write_entry(operation: str, file_path, features: List[str], ip: Optional[str] = None) -> bool:
    """写入 WAL 事务日志"""
    try:
        _init_wal_path()
        config = ConfigRegistry.get_raw_config()
        filesizes_cfg = config.get("filesizes", {})
        wal_rotate_mb = filesizes_cfg.get("wal_rotate_threshold_mb", 10)

        wal_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "file_path": path_to_key(file_path) if hasattr(file_path, 'name') else str(file_path),
            "features": features,
            "ip": ip,
            "pid": os.getpid(),
            "thread_id": threading.get_ident(),
            "wal_threshold_mb": wal_rotate_mb
        }

        _WAL_PATH.parent.mkdir(parents=True, exist_ok=True)

        with open(_WAL_PATH, "a", encoding='utf-8', buffering=1) as f:
            f.write(json.dumps(wal_entry, ensure_ascii=False) + "\n")
            f.flush()
            if sys.platform != "win32":
                os.fsync(f.fileno())

        _rotate_if_needed()
        return True

    except Exception as e:
        log_with_symbol("error_wal_write", "error", f"写入失败: {e}")
        return False


def read_entries() -> List[Dict]:
    """读取所有 WAL 条目"""
    _init_wal_path()
    entries = []
    if not _WAL_PATH or not _WAL_PATH.exists():
        return entries

    try:
        with open(_WAL_PATH, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return entries


def archive_current_wal() -> Optional[Path]:
    """将当前 WAL 归档并创建新的空 WAL"""
    _init_wal_path()
    if not _WAL_PATH or not _WAL_PATH.exists():
        return None

    try:
        wal_backup = _WAL_PATH.with_suffix(f".log.{int(time.time())}")
        _WAL_PATH.rename(wal_backup)
        _WAL_PATH.touch()
        with open(_WAL_PATH, 'w', encoding='utf-8') as f:
            f.write(f"# WAL restarted at {datetime.now().isoformat()}\n")
        _emit_wal_event("wal_archived", {"archive_path": str(wal_backup)})
        return wal_backup
    except Exception as e:
        log_with_symbol("error_wal_archive", "error", f"归档失败: {e}")
        return None


def _emit_wal_event(event_type: str, extra: Dict = None) -> None:
    """Emit WAL lifecycle event through PluginManager (best-effort)."""
    try:
        from anteumbra.application.plugin_manager import get_plugin_manager
        pm = get_plugin_manager()
        if pm.is_enabled:
            payload = {"event_type": event_type}
            if extra:
                payload.update(extra)
            pm.emit(event_type, "wal_manager", payload)
    except Exception:
        logger.debug("PluginManager emit WAL event failed", exc_info=True)


def _rotate_if_needed():
    """检查并执行 WAL 轮转"""
    _init_wal_path()
    if not _WAL_PATH or not _WAL_PATH.exists():
        return

    try:
        config = ConfigRegistry.get_raw_config()
        filesizes_cfg = config.get("filesizes", {})
        wal_rotate_mb = filesizes_cfg.get("wal_rotate_threshold_mb", 10)

        size = _WAL_PATH.stat().st_size
        if size > wal_rotate_mb * 1024 * 1024:
            log_with_symbol("notice", "info", f"触发轮转，文件大小: {size / 1024 / 1024:.2f}MB")

            daily_name = _WAL_PATH.parent / f"registry_wal.log.{datetime.now().strftime('%Y%m%d')}"
            if daily_name.exists():
                counter = 1
                while True:
                    alt_name = daily_name.parent / f"{daily_name.name}.{counter:03d}"
                    if not alt_name.exists():
                        daily_name = alt_name
                        break
                    counter += 1

            _WAL_PATH.rename(daily_name)
            log_with_symbol("notice", "info", f"轮转日志: {daily_name}")

            _WAL_PATH.touch()
            with open(_WAL_PATH, 'w', encoding='utf-8') as f:
                f.write(f"# WAL restarted at {datetime.now().isoformat()}\n")
                f.flush()
                if sys.platform != "win32":
                    os.fsync(f.fileno())

            _cleanup_archives()
    except Exception as e:
        log_with_symbol("error_wal_rotate", "error", f"失败: {e}")


def _cleanup_archives():
    """清理过期 WAL 归档"""
    _init_wal_path()
    wal_dir = _WAL_PATH.parent

    cutoff_time = time.time() - 7 * 86400
    deleted_by_time = 0

    for wal_file in wal_dir.glob("registry_wal.log.*"):
        try:
            if wal_file.stat().st_mtime < cutoff_time:
                wal_file.unlink()
                deleted_by_time += 1
                log_with_symbol("notice", "info", f"删除过期: {wal_file.name}")
        except Exception as e:
            log_with_symbol("warning", "warning", f"删除失败 {wal_file}: {e}")

    remaining = sorted(wal_dir.glob("registry_wal.log.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    deleted_by_count = 0
    if len(remaining) > 20:
        for old_file in remaining[20:]:
            try:
                old_file.unlink()
                deleted_by_count += 1
                log_with_symbol("notice", "info", f"保留超限: {old_file.name}")
            except Exception as e:
                log_with_symbol("warning", "warning", f"删除失败 {old_file}: {e}")


def replay(callbacks: Dict[str, callable]) -> int:
    """重放 WAL（通过回调函数执行操作）

    callbacks = {
        'ADD': func(file_path, features, ip),
        'INCREMENT': func(file_path, features, ip),
        'REMOVE': func(file_path, features, ip),
        'ALERTED': func(file_path, features, ip)
    }
    """
    global _replaying
    _init_wal_path()

    if not _WAL_PATH or not _WAL_PATH.exists():
        return 0

    with _replay_lock:
        _replaying = True
        try:
            logger = logging.getLogger("monitor.wal_manager")
            if not logger.handlers:
                logger.setLevel(logging.INFO)
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter('[%(asctime)s] [WAL] %(message)s'))
                logger.addHandler(handler)

            logger.info("发现事务日志，正在重放...")
            entries = read_entries()
            recovered = 0

            for entry in entries:
                try:
                    operation = entry["operation"]
                    file_path = normalize_path(entry["file_path"])
                    features = entry.get("features", [])
                    ip = entry.get("ip")

                    callback = callbacks.get(operation)
                    if callback:
                        callback(file_path, features, ip)
                        recovered += 1
                    else:
                        logger.warning(f"未知操作: {operation}")

                except Exception as e:
                    logger.error(f"重放行失败: {e}", exc_info=True)

            logger.info(f"重放完成，恢复 {recovered} 条记录")
            _emit_wal_event("wal_replayed", {"recovered_count": recovered})
            archive_current_wal()
            return recovered

        finally:
            _replaying = False


def is_replaying() -> bool:
    """返回当前是否正在执行 WAL 重放"""
    return _replaying


def get_wal_info() -> Dict:
    """获取当前 WAL 文件信息"""
    _init_wal_path()
    if not _WAL_PATH or not _WAL_PATH.exists():
        return {}
    stat = _WAL_PATH.stat()
    return {
        'name': _WAL_PATH.name,
        'path': str(_WAL_PATH),
        'size_mb': round(stat.st_size / 1024 / 1024, 2),
        'mtime': stat.st_mtime
    }


def list_archives() -> List[Dict]:
    """获取 WAL 归档文件列表"""
    _init_wal_path()
    if not _WAL_PATH:
        return []
    wal_dir = _WAL_PATH.parent
    if not wal_dir.exists():
        return []
    archives = []
    for wal_file in wal_dir.glob("registry_wal.log.*"):
        try:
            stat = wal_file.stat()
            archives.append({
                'name': wal_file.name,
                'size_mb': round(stat.st_size / 1024 / 1024, 2),
                'mtime': stat.st_mtime
            })
        except Exception:
            logger.debug("Failed to stat WAL archive file", exc_info=True)
    return sorted(archives, key=lambda x: x['mtime'], reverse=True)


def get_status_text() -> tuple:
    """获取 WAL 状态文本和级别"""
    info = get_wal_info()
    if info is None:
        return 'error', 'WAL文件不存在', 0.0
    size_mb = info.get('size_mb', 0.0)
    status = 'normal' if size_mb < 10 else 'warning'
    text = f'正常写入 ({size_mb:.1f}MB)' if status == 'normal' else '接近阈值'
    return status, text, size_mb


# API 兼容别名 (v1.7.8 CI/CD 测试兼容)
def read_wal_records(limit: int = 0) -> List[Dict]:
    """读取 WAL 记录（兼容 v1.7.8 API 测试）"""
    entries = read_entries()
    if limit > 0:
        return entries[:limit]
    return entries
