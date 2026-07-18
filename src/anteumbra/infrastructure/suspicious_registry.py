# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 9:40 PM
@Auth: SxyLao1
@File: suspicious_registry.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.6修复：remove()函数触发SSE更新
"""
import json
import logging
import threading
import queue
import time
import atexit
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from anteumbra.domain.runtime import EventPublisherPort
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import path_to_key, normalize_path
# v1.7.3：导入统一日志接口
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
from anteumbra.infrastructure import wal_manager

# ============================================================================
# FIX v1.7.3: 工具脚本模式检测（静默运行）
# ============================================================================
def _is_tool_script() -> bool:
    """检测是否为工具脚本运行模式（测试环境也视为工具模式）

    v1.0.6 fix: 原生检测 pytest (PYTEST_CURRENT_TEST)，不再依赖 ANTEUMBRA_TOOL_MODE。
    解决 import 时序问题 — 当 suspicious_registry 在 env var 设置前被导入时，
    仍然能正确识别测试环境并隔离数据路径。
    """
    if os.environ.get("ANTEUMBRA_TOOL_MODE", "false") == "true":
        return True
    # pytest sets PYTEST_CURRENT_TEST when running tests (even during collection)
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    # Fallback: detect pytest / test runner from command-line
    if "pytest" in sys.argv[0].lower() or "test" in sys.argv[0].lower():
        return True
    return False
# ============================================================================

_logger_instance = None

# ============================================================================
# v1.7.0重构：从配置读取所有路径和阈值
# ============================================================================
def _get_registry_paths():
    """获取Registry相关路径（增强版：确保返回有效Path对象）"""
    try:
        config = ConfigRegistry.get_raw_config()
        paths = config.get("paths", {})
        data_dir_str = paths.get("data_dir", "data")

        # 确保字符串不为None
        if data_dir_str is None:
            raise ValueError("data_dir配置为None")

        data_dir = normalize_path(data_dir_str)

        # 确保创建目录（防止后续操作失败）
        data_dir.mkdir(parents=True, exist_ok=True)

    except Exception as e:
        # 所有异常都使用硬编码默认值
        logger = logging.getLogger("monitor.suspicious_registry")
        logger.error(f"[REGISTRY] 配置加载失败: {e}，使用默认值 'data/'")
        data_dir = normalize_path("data")
        data_dir.mkdir(parents=True, exist_ok=True)

    # 确保返回的每个Path都有效（不为None）
    registry_path = data_dir / "suspicious_registry.json"
    backup_path = data_dir / "suspicious_registry.json.bak"

    # 终极检查：如果任一路径为None，抛出错误
    if any(p is None for p in [registry_path, backup_path]):
        raise RuntimeError(f"[REGISTRY] 路径初始化失败: registry={registry_path}")

    return {
        "registry": registry_path,
        "backup": backup_path
    }

# 延迟初始化路径（避免模块导入时ConfigRegistry未初始化）
_REGISTRY_PATH = None
_REGISTRY_BACKUP_PATH = None

# ============================================================================
# v1.7.0重构：补充缺失的异步保存全局变量
# ============================================================================
# 全局异步保存队列和线程（必须保留这些全局变量）
_async_save_queue: Optional[queue.Queue] = None
_async_save_thread: Optional[threading.Thread] = None
_async_save_enabled = False
_async_save_interval = 60
_async_running = False
_async_lock = threading.RLock()
_snapshot_lock = threading.Lock()
_last_registry_snapshot: Optional[List[Dict]] = None  # 数据快照

_save_lock = threading.Lock()  # 文件写入锁

_registry_update_timer = None  # 防抖定时器
_registry_update_lock = threading.Lock()
_REGISTRY_UPDATE_DEBOUNCE_SECONDS = 2.0  # 防抖延迟（可调整）

def _ensure_initialized():
    """v1.7.0新增：确保所有必要组件已初始化（公共函数入口调用）

    v1.0.6 fix: 测试环境下强制覆盖 _REGISTRY_PATH，无论是否已被 import 链设置。
    之前的 `if _REGISTRY_PATH is None` 守卫在 import 时序问题下失效 —
    wal_manager 等模块的 import 链可能在 env var 设置前触发 _init_paths()，
    导致生产路径被锁定。
    """
    global _REGISTRY_PATH, _REGISTRY_BACKUP_PATH, _async_save_enabled

    # v1.7.3重构：统一处理工具脚本模式（包含测试和工具脚本）
    if _is_tool_script():
        # 工具模式：完全禁用异步保存
        _async_save_enabled = False

        # 如果是测试环境，使用测试专用路径
        # v1.0.6: 移除 `if _REGISTRY_PATH is None` 守卫 —
        # 当 import 链提前触发了 _init_paths() 时，生产路径已被写入，
        # 必须无条件覆盖为测试隔离路径。
        if os.environ.get("PYTEST_CURRENT_TEST") or "test" in sys.argv[0].lower():
            test_dir = normalize_path("temp/registry_test_isolated/data")
            test_dir.mkdir(parents=True, exist_ok=True)
            _REGISTRY_PATH = test_dir / "test_registry.json"
            _REGISTRY_BACKUP_PATH = _REGISTRY_PATH.with_suffix('.json.bak')

    _init_paths()
    _enable_async_save()

def _init_paths():
    """初始化路径（第一次使用时）"""
    global _REGISTRY_PATH, _REGISTRY_BACKUP_PATH
    if _REGISTRY_PATH is None:
        paths = _get_registry_paths()
        _REGISTRY_PATH = paths["registry"]
        _REGISTRY_BACKUP_PATH = paths["backup"]


def _get_logger():
    """获取或创建带时间戳的logger（使用monitor命名空间）"""
    global _logger_instance
    if _logger_instance is None:
        # v1.7.3修复：使用monitor命名空间，确保日志写入monitor.log
        _logger_instance = logging.getLogger("monitor.suspicious_registry")
    return _logger_instance


def _enable_async_save():
    """从配置启用异步保存"""
    global _async_save_enabled, _async_save_interval, _async_save_queue, _async_save_thread, _async_running

    if _is_tool_script():
        _async_save_enabled = False
        return

    # 如果已经初始化，跳过
    if _async_save_queue is not None:
        return

    try:
        config = ConfigRegistry.get_raw_config()
        registry_cfg = config.get("registry", {})

        _async_save_enabled = registry_cfg.get("async_save_enabled", False)
        # v1.7.0重构：从配置读取间隔时间
        _async_save_interval = ConfigRegistry.safe_int(registry_cfg.get("async_save_interval_seconds", 60))

        if _async_save_enabled:
            log_with_symbol("notice", "info", f"启用异步保存，间隔: {_async_save_interval}秒")

            _async_save_queue = queue.Queue(maxsize=0)
            _async_running = True
            _async_save_thread = threading.Thread(
                target=_async_save_worker,
                name="RegistryAsyncSaver",
                daemon=True
            )
            _async_save_thread.start()

            atexit.register(_shutdown_async_saver)

    except Exception as e:
        log_with_symbol("warning", "warning", f"配置加载失败，使用同步模式: {e}")
        _async_save_enabled = False



def _add_record_direct(registry_data: List[Dict], file_path: Path, features: List[str]):
    """直接操作registry数据（不经过WAL，用于重放）"""
    abs_path = path_to_key(file_path)

    for item in registry_data:
        if item["file_path"] == abs_path:
            item.update({
                "file_exists": True,
                "deleted_at": None,
                "alerted": False,
                "communication_count": 0,
                "first_seen_ip": None,
                "detected_at": datetime.now().isoformat(),
                "features": features,
                # v1.7.2新增：误报标记字段
                "marked_false_positive": False,
                "false_positive_reason": "",
                "false_positive_at": None
            })
            return  # 找到即更新

    # 不存在则添加
    registry_data.append({
        "file_path": abs_path,
        "detected_at": datetime.now().isoformat(),
        "features": features,
        "alerted": False,
        "file_exists": True,
        "first_seen_ip": None,
        "communication_count": 0,
        "deleted_at": None,
        # v1.7.2新增：误报标记字段
        "marked_false_positive": False,
        "false_positive_reason": "",
        "false_positive_at": None
    })

def replay_wal_manually():
    """手动触发WAL重放（测试或灾难恢复时调用）- v1.8.4: 使用 wal_manager"""

    logger = logging.getLogger("monitor.suspicious_registry.wal")

    entries = wal_manager.read_entries()
    if not entries:
        logger.info("WAL file not found or empty")
        return 0
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('[%(asctime)s] [REGISTRY][WAL] %(message)s'))
        logger.addHandler(handler)

    logger.info("发现事务日志，正在重放...")

    recovered = 0
    registry = _load_registry()

    for entry in entries:
        try:
            operation = entry["operation"]
            file_path = normalize_path(entry["file_path"])
            features = entry.get("features", [])
            ip = entry.get("ip")

            if operation == "ADD":
                _add_record_direct(registry, file_path, features)
                recovered += 1
            elif operation == "INCREMENT" and ip:
                _increment_access_direct(registry, file_path, ip)
                recovered += 1
            elif operation == "REMOVE":
                _remove_record_direct(registry, file_path)
                recovered += 1
            elif operation == "ALERTED":
                _mark_alerted_direct(registry, file_path)
                recovered += 1
            else:
                logger.warning(f"未知操作: {operation}")
        except Exception as e:
            logger.error(f"重放行失败: {e}", exc_info=True)

    _save_registry_sync(registry)
    logger.info(f"重放完成，恢复 {recovered} 条记录")

    # 归档 WAL
    wal_manager.archive_current_wal()
    return recovered

def _increment_access_direct(registry_data: List[Dict], file_path: Path, ip: str):
    """直接递增访问计数（用于WAL重放）"""
    abs_path = path_to_key(file_path)
    for item in registry_data:
        if item["file_path"] == abs_path:
            item["communication_count"] = item.get("communication_count", 0) + 1
            if not item.get("first_seen_ip"):
                item["first_seen_ip"] = ip
            return

def _remove_record_direct(registry_data: List[Dict], file_path: Path):
    """直接标记删除（用于WAL重放）"""
    abs_path = path_to_key(file_path)
    for item in registry_data:
        if item["file_path"] == abs_path:
            item["file_exists"] = False
            item["deleted_at"] = datetime.now().isoformat()

def _mark_alerted_direct(registry_data: List[Dict], file_path: Path):
    """直接标记已告警（用于WAL重放）"""
    abs_path = path_to_key(file_path)
    for item in registry_data:
        if item["file_path"] == abs_path:
            item["alerted"] = True

def _shutdown_async_saver():
    """优雅关闭异步保存器"""
    global _async_running, _async_save_thread, _async_save_queue

    if _is_tool_script():
        return

    try:
        logger = _get_logger()
    except Exception:
        logger = logging.getLogger("monitor.suspicious_registry")

    log_with_symbol("notice", "info", "正在关闭异步保存器...", logger)

    with _async_lock:
        _async_running = False

        if _async_save_queue:
            try:
                _async_save_queue.put(None)
            except Exception:
                _get_logger().debug("Async save queue put failed during shutdown", exc_info=True)

        if _async_save_thread and _async_save_thread.is_alive():
            _async_save_thread.join(timeout=5.0)

        if _async_save_thread and _async_save_thread.is_alive():
            logger.warning("[REGISTRY][ASYNC] 线程未能在5秒内关闭")

    log_with_symbol("notice", "info", "异步保存器已关闭", logger)

def _async_save_worker():
    """后台保存工作线程"""
    global _async_running

    try:
        logger = _get_logger()
    except Exception:
        logger = logging.getLogger("monitor.suspicious_registry")

    log_with_symbol("notice", "info", "工作线程已启动", logger)

    while _async_running:
        try:
            try:
                registry_data = _async_save_queue.get(timeout=_async_save_interval)
            except queue.Empty:
                if _last_registry_snapshot:
                    _save_registry_sync(_last_registry_snapshot)
                continue

            if registry_data is None:
                break  # 退出信号

            _save_registry_sync(registry_data)
            log_with_symbol("notice", "debug", f"保存 {len(registry_data)} 条记录", logger)

        except Exception as e:
            log_with_symbol("error_async", "error", f"工作线程错误: {e}", logger)

    log_with_symbol("notice", "info", "工作线程已退出", logger)

def _queue_async_save(registry_data: List[Dict]):
    """将序列化后的registry数据加入队列"""
    global _async_save_queue

    if not _async_save_queue:
        return

    try:
        _async_save_queue.put(registry_data)
    except queue.Full:
        logger = _get_logger()
        logger.error("[REGISTRY][ASYNC] 队列已满，保存操作丢失！")

def _flush_sync():
    """同步刷新内存数据到磁盘（立即执行）"""
    try:
        data = _load_registry()
        _save_registry_sync(data)
        _get_logger().debug("[REGISTRY][ASYNC] 同步刷新完成")
    except Exception as e:
        _get_logger().error(f"[REGISTRY][ASYNC] 同步刷新失败: {e}", exc_info=True)


def _repo_load_registry() -> Optional[List[Dict]]:
    """v2.0: Try to load registry records from Repository (SQLite).

    Returns None if Repository is not available, doesn't have the backend
    configured for SQLite, or loading fails.
    """
    try:
        from anteumbra.infrastructure.persistence import get_shadow_repository
        from anteumbra.infrastructure.config.registry import ConfigRegistry
        config = ConfigRegistry.get_raw_config()
        backend = config.get("storage", {}).get("backend", "json")
        if backend == "json":
            return None  # JSON-only mode, don't read from Repository
        repo = get_shadow_repository("registry")
        if repo is None:
            return None
        records = repo.list_all(limit=999999)
        if records:
            # v2.0 fix: SQLite stores list/dict fields as JSON strings.
            # Deserialize them back so downstream code gets proper Python lists.
            for r in records:
                for field in ("features",):
                    val = r.get(field)
                    if isinstance(val, str):
                        try:
                            parsed = json.loads(val)
                            if isinstance(parsed, list):
                                r[field] = parsed
                        except (json.JSONDecodeError, TypeError):
                            _get_logger().debug("Failed to deserialize features field from Repository", exc_info=True)
            logger = logging.getLogger("monitor.suspicious_registry")
            logger.info(f"[REGISTRY] 从 Repository 加载 {len(records)} 条记录 (backend={backend})")
            return records
    except Exception:
        _get_logger().debug("Repository load failed, falling back to JSON", exc_info=True)
    return None


def _normalize_registry_format(data) -> List[Dict]:
    """v2.0 fix: Normalize registry to always be a list of dicts.

    The JSON file may store records as either:
    - A list: [{"file_path": "...", ...}, ...]
    - A dict: {"path/key": {"file_path": "...", ...}, ...}

    All internal code expects a list, so normalize dict format to list.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Convert dict-of-dicts to list, ensuring file_path is set from key if missing
        result = []
        for key, item in data.items():
            if isinstance(item, dict):
                if "file_path" not in item:
                    item["file_path"] = key
                result.append(item)
        return result
    return []


def _resolve_site_identity(
    file_path: Union[str, Path],
    site_id: Optional[str] = None,
    site_name: Optional[str] = None,
) -> SiteIdentity:
    """Resolve explicit or legacy record ownership without guessing a first site."""
    try:
        return ConfigRegistry.resolve_site_identity(
            str(file_path), site_id=site_id, site_name=site_name
        )
    except Exception:
        if site_id:
            return SiteIdentity.from_values(site_id, site_name or site_id)
        return SiteIdentity.legacy()


def _ensure_site_metadata(record: Dict) -> bool:
    """Populate missing site fields in a historical record in memory."""
    identity = _resolve_site_identity(
        record.get("file_path", ""),
        record.get("site_id"),
        record.get("site_name"),
    )
    changed = (
        record.get("site_id") != identity.site_id
        or record.get("site_name") != identity.site_name
    )
    if changed:
        record.update(identity.as_dict())
    return changed


def _matches_site(record: Dict, site_id: Optional[str]) -> bool:
    """Match a record against an optional site filter after legacy enrichment."""
    if site_id is None:
        return True
    _ensure_site_metadata(record)
    return record.get("site_id") == str(site_id).strip().lower()


def _publish_event(
    publisher: EventPublisherPort | None,
    event_type: str,
    payload: Dict,
) -> None:
    """Publish a Registry event only through an explicitly supplied runtime port."""
    if publisher is None:
        return
    try:
        publisher.publish(event_type, "suspicious_registry", payload)
    except Exception:
        _get_logger().debug("Registry event publish failed: %s", event_type, exc_info=True)


def migrate_site_metadata() -> int:
    """Persist site ownership for historical Registry records once configuration is ready."""
    _ensure_initialized()
    with _async_lock:
        registry = _load_registry()
        changed = sum(1 for record in registry if _ensure_site_metadata(record))
        if changed:
            _save_registry_sync(registry)
        return changed


def _load_registry() -> List[Dict]:
    """加载注册表（确保路径已初始化）。

    JSON is the authoritative store. Repository backends are best-effort
    shadow copies and are consulted only when both JSON files are unavailable.

    v2.0 fix: Always returns a list of dicts, normalizing dict-format JSON files.
    """
    _init_paths()

    # v1.7.9: 优先使用内存快照（避免异步保存未刷盘时读到旧数据）
    global _last_registry_snapshot
    with _snapshot_lock:
        if _last_registry_snapshot is not None:
            return _normalize_registry_format(_last_registry_snapshot)

    if _REGISTRY_PATH and _REGISTRY_PATH.exists():
        try:
            content = _REGISTRY_PATH.read_text(encoding='utf-8')
            if content.strip():
                data = json.loads(content)
                data = _normalize_registry_format(data)
                logger = logging.getLogger("monitor.suspicious_registry")
                logger.debug(f"[REGISTRY] 加载主文件成功: {len(data)} 条记录")
                return data
        except (json.JSONDecodeError, OSError) as e:
            _logger_warning(f"[REGISTRY] 主文件损坏或无法读取: {e}")

    if _REGISTRY_BACKUP_PATH and _REGISTRY_BACKUP_PATH.exists():
        try:
            content = _REGISTRY_BACKUP_PATH.read_text(encoding='utf-8')
            if content.strip():
                data = json.loads(content)
                data = _normalize_registry_format(data)
                try:
                    # Always write as list format going forward
                    _REGISTRY_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
                    _logger_info("[REGISTRY] 已从备份恢复主文件")
                except Exception:
                    _logger_warning("[REGISTRY] 无法恢复主文件，继续使用备份")
                return data
        except (json.JSONDecodeError, OSError):
            _logger_warning("[REGISTRY] 备份文件也损坏")

    repo_data = _repo_load_registry()
    if repo_data is not None:
        return _normalize_registry_format(repo_data)
    return []


def _repository_record_id(item: Dict) -> str:
    """Build a site-qualified shadow-store key for one Registry record."""
    file_path = str(item.get("file_path") or "")
    if not file_path:
        return ""
    site_id = str(item.get("site_id") or "legacy").strip().lower() or "legacy"
    return f"{site_id}:{file_path}"


def _repo_shadow_save(data: List[Dict]):
    """v2.0: Shadow-write registry records to Repository interface.

    This is a best-effort operation — failures are silently ignored
    to ensure JSON persistence (the primary store) is never impacted.
    When storage.backend = 'sqlite' or 'both', this ensures data
    flows to SQLite without changing the module's public API.
    """
    try:
        from anteumbra.infrastructure.persistence import get_shadow_repository
        repo = get_shadow_repository("registry")
        if repo is None:
            return None
        for item in data:
            _ensure_site_metadata(item)
            key = _repository_record_id(item)
            if key:
                try:
                    repo.save(key, dict(item))
                except Exception:
                    _get_logger().debug("Repository shadow save item failed", exc_info=True)
    except Exception:
        _get_logger().debug("Repository shadow save unavailable", exc_info=True)


def _save_registry_sync(data: List[Dict]) -> bool:
    """同步保存注册表（Windows终极版：关闭所有句柄后替换）"""
    logger = _get_logger()
    global _save_lock
    registry_path = _REGISTRY_PATH

    with _save_lock:
        try:
            _init_paths()
            # 获取路径（确保已初始化）
            registry_path = _REGISTRY_PATH
            backup_path = _REGISTRY_BACKUP_PATH

            if not registry_path:
                raise RuntimeError("REGISTRY_PATH未初始化")

            # 确保目录存在
            registry_path.parent.mkdir(parents=True, exist_ok=True)

            # 序列化数据
            json_content = json.dumps(data, indent=2, ensure_ascii=False)

            # Windows特殊处理：先关闭所有可能打开的句柄
            if sys.platform == "win32":
                # 重置全局快照（释放内存引用）
                global _last_registry_snapshot
                _last_registry_snapshot = None

                # 强制垃圾回收（关闭文件句柄）
                import gc
                gc.collect()
                time.sleep(0.1)  # 给操作系统释放时间

            # 原子写入策略 - 保持原有逻辑但优化Windows处理
            temp_path = registry_path.with_suffix('.tmp')

            # 写入临时文件（确保关闭）
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(json_content)
                f.flush()
                if sys.platform != "win32":
                    os.fsync(f.fileno())

            # 关闭文件句柄后，在Windows上增加额外等待确保句柄完全释放
            if sys.platform == "win32":
                time.sleep(0.05)  # 额外等待50ms确保句柄释放

            # 执行原子替换
            if sys.platform == "win32":
                # Windows：尝试重命名，如果失败则直接写入
                try:
                    # 如果目标文件存在，先删除
                    if registry_path.exists():
                        registry_path.unlink()
                    temp_path.rename(registry_path)
                except (PermissionError, OSError):
                    # 文件被占用，回退到直接写入
                    registry_path.write_text(json_content, encoding='utf-8')
                    if temp_path.exists():
                        temp_path.unlink()
            else:
                # Linux：原子替换
                temp_path.replace(registry_path)

            # 更新备份
            backup_path.write_text(json_content, encoding='utf-8')

            _get_logger().debug(f"[REGISTRY][SAVE] 保存 {len(data)} 条记录")

        except PermissionError:
            logger.warning(f"Registry file permission denied: {registry_path}, using in-memory mode")
            return False
        except Exception as e:
            logger = logging.getLogger("monitor.suspicious_registry")
            logger.error(f"[REGISTRY][SAVE] 失败: {e}", exc_info=True)

            # 最后手段：写入紧急备份
            try:
                fallback_path = registry_path.parent / "registry_emergency_backup.json"
                fallback_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
                logger.critical(f"[REGISTRY][FALLBACK] 已写入紧急备份: {fallback_path}")
            except Exception:
                _get_logger().debug("Emergency backup write failed", exc_info=True)
            return False

    # v2.0: Shadow-write to Repository for storage.backend = sqlite / both
    _repo_shadow_save(data)
    return True

def _save_registry(data: List[Dict]):
    """保存注册表（根据配置自动选择同步或异步）"""
    global _last_registry_snapshot

    with _snapshot_lock:
        _last_registry_snapshot = data

    if _async_save_enabled:
        _queue_async_save(data)
    else:
        _save_registry_sync(data)




def add(
    file_path: Path,
    features: List[str],
    first_seen_ip: str = None,
    detection_source: str = "passive",
    site_id: str = None,
    site_name: str = None,
    event_publisher: EventPublisherPort | None = None,
):
    """添加可疑文件（线程安全版）。v1.8.4: 支持传入 first_seen_ip，避免本地检测时IP显示None。
       v1.9.0: 支持 detection_source 区分被动/主动检测。"""
    _ensure_initialized()
    site = _resolve_site_identity(file_path, site_id, site_name)

    try:
        with _async_lock:
            global _last_registry_snapshot

            # FIX: 强制使用path_to_key确保路径格式一致
            abs_path = path_to_key(file_path)

            # 加载当前数据
            if _last_registry_snapshot is not None:
                registry = _last_registry_snapshot.copy()
            else:
                registry = _load_registry()

            # 查找或更新记录
            updated = False
            for item in registry:
                if item["file_path"] == abs_path and _matches_site(
                    item, site.site_id
                ):
                    # 更新现有记录：保留已有的 first_seen_ip（除非新的有效IP）
                    existing_ip = item.get("first_seen_ip")
                    new_ip = first_seen_ip if first_seen_ip else existing_ip
                    # v1.9.0: 保留已有 detection_source，active 覆盖 passive
                    existing_src = item.get("detection_source", "passive")
                    new_src = detection_source if detection_source == "active" else existing_src
                    item.update({
                        "file_exists": True,
                        "deleted_at": None,
                        "alerted": False,
                        "communication_count": 0,
                        "first_seen_ip": new_ip,
                        "detected_at": datetime.now().isoformat(),
                        "features": features,
                        "detection_source": new_src,
                        **site.as_dict(),
                    })
                    updated = True
                    break

            if not updated:
                # 添加新记录
                registry.append({
                    "file_path": abs_path,  # FIX: 使用path_to_key生成的键
                    "detected_at": datetime.now().isoformat(),
                    "features": features,
                    "alerted": False,
                    "file_exists": True,
                    "first_seen_ip": first_seen_ip,
                    "communication_count": 0,
                    "deleted_at": None,
                    "detection_source": detection_source,
                    **site.as_dict(),
                })

            _last_registry_snapshot = registry
            _save_registry(registry)

            try:
                trigger_registry_update_debounced()
                _get_logger().debug("[REGISTRY] SSE防抖推送已触发")
            except Exception as e:
                _get_logger().warning(f"[REGISTRY] SSE推送失败: {e}")

            _publish_event(event_publisher, "record_added", {
                "file_path": abs_path,
                "detected_at": datetime.now().isoformat(),
                "features": features,
                "first_seen_ip": first_seen_ip,
                "detection_source": detection_source,
                **site.as_dict(),
            })

            log_with_symbol("registry_add", "info", f"{file_path.name} | 特征: {', '.join(features[:3])}")

    except Exception as e:
        log_with_symbol("error_registry_add", "error", f"异常: {e}")

def get_all(
    include_deleted: bool = False,
    include_false_positive: bool = False,
    site_id: Optional[str] = None,
) -> List[Dict]:
    """
    v1.7.7: 默认不显示已删除文件，保持清单整洁
    include_deleted: 审计视图专用参数
    """
    _ensure_initialized()

    registry = _load_registry()
    for record in registry:
        _ensure_site_metadata(record)

    # 第一层过滤：删除状态（默认False）
    if include_deleted:
        base_filtered = registry  # 审计视图：显示所有
    else:
        base_filtered = [item for item in registry if item.get("file_exists", True)]

    # 第二层过滤：误报标记
    if include_false_positive:
        filtered = base_filtered
    else:
        filtered = [item for item in base_filtered if not item.get("marked_false_positive", False)]

    if site_id is not None:
        normalized_id = str(site_id).strip().lower()
        filtered = [item for item in filtered if item.get("site_id") == normalized_id]

    filtered.sort(key=lambda x: x.get("detected_at", ""), reverse=True)
    return filtered

def mark_alerted(
    file_path: Path,
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
):
    """标记已告警"""
    _ensure_initialized()  # 确保初始化

    try:
        registry = _load_registry()
        abs_path = path_to_key(file_path)

        for item in registry:
            if item["file_path"] == abs_path and _matches_site(item, site_id):
                item["alerted"] = True
                _save_registry(registry)
                log_with_symbol("notice", "debug", f"标记已告警: {file_path.name}")

                _publish_event(event_publisher, "registry_changed", {
                    "operation": "mark_alerted",
                    "file_path": abs_path,
                    "site_id": item.get("site_id"),
                    "site_name": item.get("site_name"),
                })
                break
    except Exception as e:
        log_with_symbol("error_mark_alerted", "error", f"异常: {e}")

def mark_quarantined(
    file_path: str,
    quarantine_id: str,
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
) -> bool:
    """v1.7.9: 标记文件已被隔离 — 更新 Registry 条目并设 file_exists=False"""
    _ensure_initialized()
    try:
        with _async_lock:
            registry = _load_registry()
            abs_path = path_to_key(file_path)
            for item in registry:
                if item["file_path"] == abs_path and _matches_site(item, site_id):
                    item["file_exists"] = False
                    item["quarantine_id"] = quarantine_id
                    item["quarantined_at"] = datetime.now().isoformat()
                    if not _save_registry_sync(registry):
                        return False
                    log_with_symbol("quarantine_add", "info",
                                    f"Registry 已标记隔离: {Path(file_path).name} -> {quarantine_id}")

                    _publish_event(event_publisher, "registry_changed", {
                        "operation": "mark_quarantined",
                        "file_path": abs_path,
                        "quarantine_id": quarantine_id,
                        "site_id": item.get("site_id"),
                        "site_name": item.get("site_name"),
                    })
                    return True
            _get_logger().warning("Registry record not found for quarantine: %s", abs_path)
            return False
    except Exception as e:
        log_with_symbol("error_registry_save", "error", f"标记隔离失败: {e}")
        return False


def mark_restored(
    file_path: str,
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
) -> bool:
    """Clear quarantine state after a file is restored from quarantine."""
    _ensure_initialized()
    try:
        with _async_lock:
            registry = _load_registry()
            abs_path = path_to_key(file_path)
            for item in registry:
                if item["file_path"] == abs_path and _matches_site(item, site_id):
                    item["file_exists"] = True
                    item["quarantine_id"] = None
                    item["restored_at"] = datetime.now().isoformat()
                    if not _save_registry_sync(registry):
                        return False
                    log_with_symbol("quarantine_restore", "info",
                                    f"Registry restored: {Path(file_path).name}")

                    _publish_event(event_publisher, "registry_changed", {
                        "operation": "mark_restored",
                        "file_path": abs_path,
                        "site_id": item.get("site_id"),
                        "site_name": item.get("site_name"),
                    })
                    return True
            return False
    except Exception as e:
        log_with_symbol("error_registry_save", "error", f"标记恢复失败: {e}")
        return False


def mark_false_positive(
    file_path: Union[Path, str],
    reason: str = "",
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
) -> bool:
    """v2.0: 标记记录为误报 — 在 Registry 中设置 marked_false_positive=True

    与 remove() 区分：此操作由用户手动触发（前端按钮），不是文件删除事件。
    标记后记录默认隐藏，但可通过 include_false_positive=True 查看。
    """
    _ensure_initialized()
    logger = logging.getLogger("monitor.suspicious_registry")

    if isinstance(file_path, Path):
        abs_path = path_to_key(file_path)
    else:
        abs_path = file_path

    try:
        registry = _load_registry()
        found = False
        for item in registry:
            if item.get("file_path") == abs_path and _matches_site(item, site_id):
                item["marked_false_positive"] = True
                item["false_positive_at"] = datetime.now().isoformat()
                item["false_positive_reason"] = reason
                found = True
                break

        if not found:
            logger.warning(f"[REGISTRY][FALSE_POSITIVE] 记录不存在: {abs_path[:50]}...")
            return False

        _save_registry(registry)

        _publish_event(event_publisher, "registry_changed", {
            "operation": "mark_false_positive",
            "file_path": abs_path,
            "reason": reason,
            "site_id": item.get("site_id"),
            "site_name": item.get("site_name"),
        })

        logger.info(f"[REGISTRY][FALSE_POSITIVE] 已标记误报: {abs_path}")
        return True

    except Exception as e:
        logger.error(f"[REGISTRY][FALSE_POSITIVE] 标记失败: {e}", exc_info=True)
        return False


def increment_access(
    file_path: Path,
    ip: str,
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
):
    """增加访问计数 - v1.7.7-Patch11: 使用防抖SSE推送"""
    _ensure_initialized()
    site = _resolve_site_identity(file_path, site_id)

    try:
        registry = _load_registry()
        abs_path = path_to_key(file_path)

        # 查找记录
        for item in registry:
            if item["file_path"] == abs_path and _matches_site(item, site_id):
                old = item.get("communication_count", 0)
                new_count = old + 1
                item["communication_count"] = new_count
                if item.get("first_seen_ip") is None:
                    item["first_seen_ip"] = ip

                # v1.7.7-Patch11: 记录日志（每次都有），但SSE推送防抖
                log_with_symbol(
                    "notice",
                    "info",
                    f"{file_path.name} 通信次数: {old} → {new_count} | IP: {ip}",
                    _get_logger()
                )
                break
        else:
            # 记录不存在：直接创建
            registry.append({
                "file_path": abs_path,
                "detected_at": datetime.now().isoformat(),
                "features": ["AUTO_CREATED_BY_ACCESS"],
                "alerted": False,
                "file_exists": True,
                "first_seen_ip": ip,
                "communication_count": 1,
                "deleted_at": None,
                **site.as_dict(),
            })
            log_with_symbol("warning", "warning", f"记录不存在，自动创建: {file_path.name}", _get_logger())

        # 保存更改
        _save_registry(registry)

        # v1.7.7-Patch11: 使用防抖推送（关键修复）
        # - 高频访问时，只会每2秒推送一次
        # - 最后一次更新后2秒，前端最终状态一定正确
        trigger_registry_update_debounced()

        _publish_event(event_publisher, "registry_changed", {
            "operation": "increment_access",
            "file_path": abs_path,
            "ip": ip,
            **site.as_dict(),
        })

    except Exception as e:
        log_with_symbol("error_increment", "error", f"异常: {e}", _get_logger())

def remove(
    file_path: Union[Path, str],
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
) -> bool:
    """
    v1.7.6-Patch1: 软删除（标记file_exists=False），不是物理删除
    与误报标记区分：此操作由文件删除事件触发
    """
    _ensure_initialized()
    logger = logging.getLogger("monitor.suspicious_registry")

    # 区分输入类型
    if isinstance(file_path, str):
        abs_path = file_path  # 来自前端的已标准化键
    elif isinstance(file_path, Path):
        abs_path = path_to_key(file_path)  # 来自监控事件的Path
    else:
        log_with_symbol("error", "error", f"无效路径类型: {type(file_path)}", logger)
        return False

    try:
        with _async_lock:
            registry = _load_registry()
            found = False

            for item in registry:
                if item["file_path"] == abs_path and _matches_site(item, site_id):
                    # v1.7.9: 如果已被隔离（有quarantine_id），只标记file_exists=False，保留隔离信息
                    if item.get("quarantine_id"):
                        item["file_exists"] = False
                        logger.info(f"[REGISTRY][DELETE_AFTER_QUARANTINE] 已隔离文件被删除: {item['quarantine_id']}")
                    else:
                        item["file_exists"] = False
                        item["deleted_at"] = datetime.now().isoformat()
                        logger.info(f"[REGISTRY][MARK_DELETED] 标记删除: {abs_path}")
                    found = True
                    break

            if not found:
                log_with_symbol("notice", "info", f"记录不存在: {abs_path[:50]}...", logger)
                return False

            if not _save_registry_sync(registry):
                return False

        log_with_symbol("registry_remove", "info", f"标记删除成功: {abs_path}", logger)

        # 触发SSE更新
        try:
            trigger_registry_update_debounced()
            logger.debug("[REGISTRY] SSE防抖推送已触发")
        except Exception as e:
            logger.warning(f"[REGISTRY] SSE推送失败: {e}")

        _publish_event(event_publisher, "registry_changed", {
            "operation": "remove",
            "file_path": abs_path,
            "site_id": item.get("site_id"),
            "site_name": item.get("site_name"),
        })

        return True

    except Exception as e:
        log_with_symbol("error_registry_remove", "error", f"删除异常: {e}", logger)
        return False

def _trigger_registry_update_event():
    """触发Registry更新事件（通过日志触发SSE）"""
    logger = logging.getLogger("monitor.webshell.registry")
    log_with_symbol("notice", "info", "Registry已更新，触发前端刷新", logger)
    # 同时写入一个标记文件，让SSE检测到变化
    try:
        marker = normalize_path("data/registry_update.marker")
        marker.write_text(str(time.time()))
    except Exception:
        _get_logger().debug("Registry update marker write failed", exc_info=True)

def get(path: Path, site_id: Optional[str] = None) -> Optional[Dict]:
    """获取单条记录"""
    _ensure_initialized()  # 确保初始化

    try:
        # v1.1.0 fix: 使用 path_to_key() 确保与 add() 的键一致
        # 之前 str(path.resolve()) 在 Windows 上保留原始大小写，
        # 而 add() 使用 path_to_key() 进行小写规范化，导致查找失败。
        abs_path = path_to_key(path)
        # v1.1.0 fix: include false positives so marked records are still findable
        for item in get_all(
            include_deleted=True,
            include_false_positive=True,
            site_id=site_id,
        ):
            if item.get("file_path") == abs_path:
                return item
    except Exception as e:
        log_with_symbol("error", "error", f"异常: {e}")
    return None


def is_suspicious(path: Path, site_id: Optional[str] = None) -> bool:
    """检查是否在清单中"""
    return get(path, site_id=site_id) is not None

def compact_registry(runtime_config: Optional[Dict] = None):
    """压缩注册表"""
    _ensure_initialized()
    try:
        _init_paths()

        config = runtime_config if runtime_config is not None else ConfigRegistry.get_raw_config()
        filesizes_cfg = config.get("filesizes", {})
        compact_days = filesizes_cfg.get("registry_compact_days", 30)

        data = _load_registry()
        original_count = len(data)

        cutoff = datetime.now() - timedelta(days=compact_days)
        compacted = [
            r for r in data
            if r["file_exists"] or datetime.fromisoformat(r["detected_at"]) > cutoff
        ]

        cleaned_count = original_count - len(compacted)

        # 增强日志反馈
        if cleaned_count > 0:
            _save_registry(compacted)
            log_with_symbol("notice", "info", f"清理 {cleaned_count} 条过期记录")
        else:
            # 新增：明确告知用户无记录可清理
            log_with_symbol("notice", "info",
                            f"扫描 {original_count} 条记录，无过期记录需要清理（阈值: {compact_days}天）")

        return {
            "total": original_count,
            "cleaned": cleaned_count,
            "remaining": len(compacted)
        }
    except Exception as e:
        log_with_symbol("error", "error", f"Registry压缩失败: {e}")
        return {"error": str(e)}

# ── v1.1.0: Public status getters (replaces direct access to private module globals) ──

def soft_delete_record(
    file_path: Union[Path, str],
    site_id: Optional[str] = None,
    event_publisher: EventPublisherPort | None = None,
) -> bool:
    """v1.1.0: 软删除记录 — 标记 file_exists=False 并记录删除时间。

    Blueprint 层应使用此函数，而非直接操作 _load_registry()/_save_registry()。
    """
    _ensure_initialized()
    if isinstance(file_path, Path):
        abs_path = path_to_key(file_path)
    else:
        abs_path = file_path

    try:
        registry = _load_registry()
        for item in registry:
            if item.get("file_path") == abs_path and _matches_site(item, site_id):
                item["file_exists"] = False
                item["deleted_at"] = datetime.now().isoformat()
                _save_registry(registry)

                _publish_event(event_publisher, "registry_changed", {
                    "operation": "soft_delete",
                    "file_path": abs_path,
                    "site_id": item.get("site_id"),
                    "site_name": item.get("site_name"),
                })

                return True
        return False
    except Exception:
        _logger_error(f"soft_delete_record failed: {file_path}")
        return False


def is_async_save_enabled() -> bool:
    """v1.1.0: 公共 getter — 异步保存是否启用"""
    return _async_save_enabled


def get_async_save_queue_size() -> int:
    """v1.1.0: 公共 getter — 异步保存队列大小"""
    if _async_save_queue is None:
        return 0
    try:
        return _async_save_queue.qsize()
    except Exception:
        _get_logger().debug("Failed to get async save queue size", exc_info=True)
        return 0


def get_registry_path() -> Optional[Path]:
    """v1.1.0: 公共 getter — Registry 文件路径"""
    return _REGISTRY_PATH


def _auto_compact_worker():
    """自动压缩工作线程"""
    time.sleep(3600)
    while _async_running:
        compact_registry()
        time.sleep(86400)

def trigger_registry_update_debounced():
    """
    v1.7.7-Patch11: 防抖版Registry更新触发器
    - 最后一次更新后2秒才会真正推送
    - 避免高频访问时SSE过载
    """
    global _registry_update_timer, _registry_update_lock

    with _registry_update_lock:
        # 如果已有待触发的定时器，取消它（重置倒计时）
        if _registry_update_timer is not None:
            _registry_update_timer.cancel()

        # 创建新的定时器
        _registry_update_timer = threading.Timer(
            _REGISTRY_UPDATE_DEBOUNCE_SECONDS,
            _do_trigger_registry_update
        )
        _registry_update_timer.daemon = True
        _registry_update_timer.start()


def _do_trigger_registry_update():
    """实际执行Registry更新推送"""
    global _registry_update_timer, _registry_update_lock

    try:
        # 调用sse_manager中的原始函数
        from anteumbra.infrastructure.utils.sse_manager import trigger_registry_update
        trigger_registry_update()
        _get_logger().debug("[REGISTRY][SSE] 防抖推送已执行")
    except Exception as e:
        _get_logger().warning(f"[REGISTRY][SSE] 推送失败: {e}")
    finally:
        with _registry_update_lock:
            _registry_update_timer = None


def _clear_memory_cache():
    """v1.7.6-Patch18: 清空内存缓存，强制下次从磁盘加载"""
    global _last_registry_snapshot
    logger = logging.getLogger("monitor.suspicious_registry")

    with _async_lock:
        if _last_registry_snapshot is not None:
            old_count = len(_last_registry_snapshot)
            _last_registry_snapshot = None
            logger.info(f"[REGISTRY] 内存缓存已清空（原记录数: {old_count}）")
        else:
            logger.debug("[REGISTRY] 内存缓存已为空")


def clear_memory_cache():
    """v1.1.0: 公共 API — 清空内存缓存，强制下次从磁盘加载"""
    _clear_memory_cache()

# 优雅关闭注册
atexit.register(_shutdown_async_saver)


# 辅助函数：避免在函数内重复写logger
def _logger_debug(msg: str):
    logging.getLogger("monitor.suspicious_registry").debug(msg)

def _logger_info(msg: str):
    logging.getLogger("monitor.suspicious_registry").info(msg)

def _logger_warning(msg: str):
    logging.getLogger("monitor.suspicious_registry").warning(msg)

def _logger_error(msg: str):
    logging.getLogger("monitor.suspicious_registry").error(msg)
