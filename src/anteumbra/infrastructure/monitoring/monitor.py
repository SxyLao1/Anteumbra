# -*- coding: utf-8 -*-
"""
@Time: 1/3/2026 11:42 PM
@Auth: SxyLao1
@File: monitor.py
@IDE: PyCharm
@Motto: HACK THE REAL

v1.8.1-Release: 平台自适应幽灵目录修复（改进版）
- 实现论文6.3.1/6.3.2节描述的延迟验证+TTL缓存机制
- Windows: 50ms延迟验证 (30ms基础+20ms安全余量)
- Linux: 0ms即时验证 (Inotify原生可靠)
- T-01-B验证: ≥0.01ms即可消除误判，50ms为工程保守设计
- v1.8.1改进: 采用TTL控制的无限制容量缓存（替代LRU硬编码100）
"""
import json
import logging
import os
import sys
import threading
import time
import queue
import fnmatch
from pathlib import Path
from typing import Callable, Dict, Set
from watchdog.events import FileSystemEventHandler
from anteumbra.domain.runtime import RuntimeServices
from anteumbra.infrastructure.models import ScanOptions, Website
from anteumbra.infrastructure.utils.path_utils import normalize_path, path_to_key
from anteumbra.infrastructure.utils.platform_utils import get_optimal_observer
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol


class FileMonitorHandler(FileSystemEventHandler):
    """
    v1.8.1-Release: 跨平台文件监控处理器

    核心改进 (对应论文6.3.1/6.3.2节):
    1. 平台自适应延迟验证: Windows 50ms / Linux 0ms
    2. TTL缓存机制: 无容量上限，TTL 60s过期清理
    3. 幽灵目录修复: 集中式 _verify_directory 方法
    4. T-01-B验证: 二元阈值特性，≥0.01ms即可消除误判

    论文对应关系:
    - _verify_directory  ←  附录A-2的 _lazy_verify_dir_event (伪代码→真实方法)
    - _dir_cache (Set)  ←  目录缓存集合（TTL控制，无固定容量限制）
    - _verify_delay_ms  ←  平台自适应延迟 (Windows 50ms / Linux 0ms)

    v1.8.1改进说明:
    原v1.8.0采用LRU机制（硬编码容量100），在极端场景（60s内>100目录操作）
    可能导致早期目录缓存被提前淘汰，削弱幽灵目录防护。
    现改为TTL控制的无限制Set，确保60s内所有访问过的目录均被记忆，
    最大化幽灵目录修复的覆盖范围。
    """

    def __init__(
        self,
        scan_callback: Callable,
        scan_options: ScanOptions,
        base_path: Path,
        logger: logging.Logger,
        website: 'Website' = None,
        *,
        services: RuntimeServices,
    ):
        self.scan_callback = scan_callback
        self.scan_options = scan_options
        self.base_path = base_path
        self.logger = logger
        self.services = services
        self.runtime = services.context
        self.site = (
            self.runtime.site_for_website(website)
            if website is not None
            else self.runtime.site_for_path(base_path)
        )
        self.website = website  # v1.0.10: 修复 LogAnalyzer 需要 website 属性
        self.exclude_dirs = {d.lower() for d in scan_options.exclude_dirs}
        self._dedupe_window = 5.0

        # 平台自适应配置初始化
        self._init_platform_config()

        # Bounded queue: overload falls back to synchronous processing instead
        # of silently dropping a file-system event.
        scanner_cfg = self.runtime.config.get("scanner", {})
        try:
            queue_size = max(1, int(scanner_cfg.get("event_queue_size", 500)))
        except (TypeError, ValueError):
            queue_size = 500
        try:
            self._scan_queue_put_timeout = max(
                0.01,
                float(scanner_cfg.get("event_queue_put_timeout_seconds", 0.25)),
            )
        except (TypeError, ValueError):
            self._scan_queue_put_timeout = 0.25
        self._scan_queue = queue.Queue(maxsize=queue_size)
        self._scan_worker_thread = None
        self._scan_worker_shutdown = threading.Event()
        self._start_scan_worker()

        # v1.8.1: TTL缓存（Set实现，无容量上限）
        self._dir_cache: Set[str] = set()  # 目录键集合
        self._cache_ttl: Dict[str, float] = {}  # TTL时间戳映射
        self._cache_timeout = 60.0  # TTL 60秒

        # 路径别名映射 (用于move事件追踪)
        self._path_aliases: Dict[str, str] = {}

        # _recent_files 初始化
        self._recent_files: Dict[str, float] = {}

        # 魔术头检测缓存
        self._magic_cache: Dict[str, tuple[bool, float]] = {}
        self._magic_cache_ttl = 0.5

        # 异步告警系统（无锁队列）
        self._alert_queue = queue.Queue(maxsize=0)
        self._alert_thread = None

        # v1.0.9: batch notification moved to quarantine_handler plugin.
        # notifier and quarantine paths now go through the event bus (emit).

        log_with_symbol("success", "debug",
                        f"处理器初始化完成 | 平台: {self._platform} | "
                        f"验证延迟: {self._verify_delay_ms}ms | "
                        f"缓存策略: TTL-{self._cache_timeout}s无限制", self.logger)

    def _init_platform_config(self):
        """
        v1.8.1: 初始化平台自适应配置
        对应论文6.3.2节T-01-B实验发现的二元阈值特性
        """
        config = self.runtime.config
        monitor_cfg = config.get("monitor", {})

        # 检测平台
        self._platform = "windows" if sys.platform == "win32" else "linux"

        # 平台自适应延迟 (论文6.3.1/6.3.2)
        # T-01-B验证: ≥0.01ms即可消除误判，但采用50ms工程保守设计
        # Windows: 50ms = 30ms基础成本 + 20ms安全余量 (附录A-2注释)
        # Linux: 0ms (Inotify原生可靠，无需延迟)
        if self._platform == "windows":
            self._verify_delay_ms = monitor_cfg.get("windows_verify_delay_ms", 50)
        else:
            self._verify_delay_ms = 0  # Linux无需延迟

        # v1.8.1: 移除硬编码LRU容量限制，改为TTL控制
        # 缓存超时时间可配置，默认60s
        self._cache_timeout = monitor_cfg.get("dir_cache_timeout_seconds", 60.0)

        # 扩展名配置
        paths_cfg = config.get("paths", {})
        if self.scan_options.monitor_extensions:
            self.monitor_extensions = {ext.lower() for ext in self.scan_options.monitor_extensions}
        else:
            default_extensions = paths_cfg.get("monitor_extensions", [".php", ".asp", ".jsp"])
            self.monitor_extensions = {ext.lower() for ext in default_extensions}

    # ===== v1.8.1: 核心方法 _verify_directory (对应附录A-2伪代码) =====
    def _verify_directory(self, path: Path) -> bool:
        """
        v1.8.1-Release: 目录验证核心方法

        对应论文附录A-2的 _lazy_verify_dir_event 伪代码实现。
        实现延迟验证+TTL缓存机制，解决Windows平台ReadDirectoryChangesW
        API的目录类型标志位不稳定问题 (幽灵目录现象)。

        论文实验基础:
        - T-01: Vanilla组误判率100% → Optimized组0% (n=500)
        - T-01-B: 二元阈值特性，≥0.01ms即可消除误判
        - T-01-E: 50ms = 30ms基础成本 + 20ms安全余量

        v1.8.1改进:
        采用TTL控制的Set替代LRU队列，确保60s内所有访问过的目录
        均被记忆，避免高并发目录操作场景下的提前淘汰问题。

        Args:
            path: 待验证的路径对象

        Returns:
            bool: True表示确认是目录，False表示不是目录或验证失败

        工程保守设计说明:
        尽管T-01-B证明≥0.01ms即可消除误判，但实际部署采用50ms (Windows)
        以覆盖Python运行时开销、GIL调度、磁盘I/O竞争等不确定因素。
        Linux平台采用0ms (Inotify原生可靠)。
        """
        try:
            # 生成标准化键 (小写/正斜杠/绝对路径)
            key = self._normalize_path(path)

            # 1. 检查TTL缓存
            if key in self._dir_cache:
                # 更新访问时间（刷新TTL）
                self._cache_ttl[key] = time.time()
                return True

            # 2. 检查路径别名
            original = self._path_aliases.get(key)
            if original and original in self._dir_cache:
                # 刷新原键的TTL
                self._cache_ttl[original] = time.time()
                return True

            # 3. 平台自适应延迟验证
            # 对应论文6.3.2节: Windows 50ms / Linux 0ms
            if self._verify_delay_ms > 0 and self._platform == "windows":
                # T-01-B验证: 只要非零延迟即可消除误判，50ms为工程保守值
                time.sleep(self._verify_delay_ms / 1000.0)

            # 4. 二次验证 (强制内核同步)
            # T-01-B机制解析: stat()系统调用强制从文件系统元数据缓存同步状态，
            # 不受ReadDirectoryChangesW异步通知的竞态条件影响
            if path.exists():
                is_dir = path.is_dir()
                if is_dir:
                    self._record_directory(path)
                return is_dir

            return False

        except Exception as e:
            # 任何异常都返回False (避免误判文件为目录)
            log_with_symbol("error_dir_cache", "debug",
                            f"目录验证异常: {e}", self.logger)
            return False

    def _is_known_directory(self, path: Path) -> bool:
        """
        v1.8.1: 兼容旧接口，委托给 _verify_directory
        保持向后兼容性，同时统一验证逻辑
        """
        return self._verify_directory(path)

    def _record_directory(self, path: Path):
        """
        v1.8.1: TTL缓存记录目录
        采用Set+Dict实现，无容量上限，仅TTL控制
        """
        try:
            if path.exists() and path.is_dir():
                key = self._normalize_path(path)

                # 添加到缓存集合
                self._dir_cache.add(key)
                # 记录/刷新TTL时间戳
                self._cache_ttl[key] = time.time()

                # 触发清理（仅移除过期项，不限制容量）
                self._cleanup_cache()

        except Exception:
            self.logger.debug("Failed to record directory in cache", exc_info=True)

    def _cleanup_cache(self):
        """
        v1.8.1: 清理过期缓存项（仅基于TTL，无容量限制）
        相比v1.8.0的LRU机制，确保活跃期内所有目录均被记忆
        """
        now = time.time()
        expired = [
            k for k, ts in self._cache_ttl.items()
            if now - ts > self._cache_timeout
        ]
        for k in expired:
            self._dir_cache.discard(k)
            self._cache_ttl.pop(k, None)

        # 清理失效的别名映射
        self._path_aliases = {
            new: old for new, old in self._path_aliases.items()
            if old in self._dir_cache
        }

    def _normalize_path(self, path: Path) -> str:
        """统一路径解析逻辑"""
        try:
            return path_to_key(path)
        except Exception:
            return str(path).lower()

    def _update_cache_on_move(self, src_path: Path, dest_path: Path):
        """更新移动事件的缓存 (内部使用，保持TTL)"""
        try:
            src_key = self._normalize_path(src_path)
            dest_key = self._normalize_path(dest_path)

            if src_key in self._dir_cache:
                # 移除旧键，添加新键，保留原TTL时间戳
                timestamp = self._cache_ttl.pop(src_key, time.time())
                self._dir_cache.discard(src_key)

                self._dir_cache.add(dest_key)
                self._cache_ttl[dest_key] = timestamp

                # 记录别名关系
                self._path_aliases[dest_key] = src_key

        except Exception:
            self.logger.debug("Failed to update cache on move", exc_info=True)

    # ===== 以下方法保持原有逻辑 =====

    def _should_monitor(self, event_path: Path) -> bool:
        """v1.7.5-Patch5: 监控决策 (保持原有逻辑)"""
        try:
            if event_path.suffix.lower() not in self.monitor_extensions:
                return False
            rel_path = event_path.relative_to(self.base_path)
            if any(part.lower() in self.exclude_dirs for part in rel_path.parts):
                log_with_symbol("skip_exclude", "info", f"排除目录: {event_path}", self.logger)
                return False
        except ValueError:
            return False

        try:
            if event_path.stat().st_size > self.scan_options.max_size_bytes:
                log_with_symbol("skip_size", "info", f"大小超限: {event_path.name}", self.logger)
                return False
        except Exception:
            self.logger.debug("Failed to check file size for monitoring decision", exc_info=True)

        exclude_files = self.scan_options.exclude_files or ["*.log", "*.cache"]

        for pattern in exclude_files:
            if fnmatch.fnmatch(event_path.name, pattern):
                log_with_symbol("skip_exclude", "info", f"白名单排除: {event_path.name}", self.logger)
                return False

        return True

    def _is_duplicate(self, event_path: Path) -> bool:
        """检查重复事件 (保持原有逻辑)"""
        now = time.time()
        path_key = path_to_key(event_path)

        last_time = self._recent_files.get(path_key)
        if last_time and (now - last_time) < self._dedupe_window:
            log_with_symbol("skip_duplicate", "info",
                            f"跳过重复事件: {event_path.name} (距上次: {now - last_time:.2f}s)",
                            self.logger)
            return True

        self._recent_files[path_key] = now
        self._recent_files = {
            k: v for k, v in self._recent_files.items()
            if now - v < self._dedupe_window * 2
        }
        return False

    def _get_system_status(self) -> dict:
        """v1.8.4: 读取系统运行状态（供通知消息使用）"""
        status = {
            "auto_quarantine_enabled": True,
            "auto_block_enabled": False,
            "block_device_count": 0,
        }
        try:
            cfg = self.runtime.config
            status["auto_quarantine_enabled"] = cfg.get("quarantine", {}).get("auto_quarantine_enabled", True)
            blocker_cfg = cfg.get("ip_blocker", {})
            status["auto_block_enabled"] = blocker_cfg.get("auto_block_enabled", False)
            status["block_device_count"] = len(blocker_cfg.get("devices", []))
        except Exception:
            self.logger.debug("Failed to read system status from config", exc_info=True)
        return status

    # ── v1.0.9: EDA bridge helpers (Surgery 4 completion) ─────

    def _emit_alert(self, alert_type: str, file_path: str, engine: str,
                    features: list, first_seen_ip: str, level: str, **extra) -> None:
        """Emit alert_requested via event bus → notifier_handler plugin."""
        try:
            self.services.events.publish("alert_requested", "monitor", {
                "alert_type": alert_type,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "file_path": file_path,
                "engine": engine,
                "features": features,
                "first_seen_ip": first_seen_ip,
                "level": level,
                **self.site.as_dict(),
                **extra,
            })
        except Exception:
            self.logger.debug("PluginManager emit alert_requested failed", exc_info=True)

    def _emit_file_quarantined(self, file_path: str, rule_name: str,
                               features: list, original_path: str,
                               first_seen_ip: str = "127.0.0.1") -> None:
        """Emit file_quarantined via event bus → quarantine_handler plugin."""
        try:
            self.services.events.publish("file_quarantined", "monitor", {
                "file_path": file_path,
                "rule_name": rule_name,
                "features": features,
                "original_path": original_path,
                "first_seen_ip": first_seen_ip,
                "quarantine_enabled": self.runtime.config.get(
                    "quarantine", {}
                ).get("auto_quarantine_enabled", True),
                **self.site.as_dict(),
            })
        except Exception:
            self.logger.debug("PluginManager emit file_quarantined failed", exc_info=True)

    def _flush_batch_notify(self):
        """v1.0.9: emit batch notification via event bus → notifier_handler."""
        try:
            self.services.events.publish("alert_requested", "monitor", {
                "alert_type": "quarantine_batch",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "level": "INFO",
                **self.site.as_dict(),
            })
        except Exception as e:
            self.logger.warning(f"[BATCH_NOTIFY] emit 失败: {e}")

    def _detect_script_magic_number(self, file_path: Path) -> bool:
        """魔术头检测 (保持原有逻辑)"""
        cache_key = str(file_path.resolve())
        now = time.time()

        if cache_key in self._magic_cache:
            is_script, timestamp = self._magic_cache[cache_key]
            if now - timestamp < self._magic_cache_ttl:
                return is_script

        result = self._do_detect_magic_number(file_path)
        self._magic_cache[cache_key] = (result, now)

        if len(self._magic_cache) > 1000:
            self._magic_cache = {
                k: v for k, v in self._magic_cache.items()
                if now - v[1] < self._magic_cache_ttl
            }

        return result

    def _do_detect_magic_number(self, file_path: Path) -> bool:
        """魔术头检测实现 (保持原有逻辑)"""
        try:
            config = self.runtime.config
            filesizes_cfg = config.get("filesizes", {})
            max_size_mb = filesizes_cfg.get("magic_detection_size_mb", 10)

            if file_path.stat().st_size > max_size_mb * 1024 * 1024:
                return False

            content = file_path.read_bytes()

            php_patterns = [
                b'<?php', b'<?=', b'<? ',
                b'eval($_POST', b'eval($_GET',
                b'system($_POST', b'exec($_POST',
            ]

            for pattern in php_patterns:
                if pattern in content[:1024]:
                    log_with_symbol("detect_php", "warning", f"PHP signature detected: {file_path.name}", self.logger)
                    return True

            if b'<%@' in content[:256] or b'runtime' in content.lower()[:256]:
                log_with_symbol("detect_jsp", "warning", f"JSP signature detected: {file_path.name}", self.logger)
                return True

            if b'<%' in content[:256] and b'%>' in content[:256]:
                log_with_symbol("detect_asp", "warning", f"ASP signature detected: {file_path.name}", self.logger)
                return True

        except Exception as e:
            log_with_symbol("detect_error", "warning", f"Detection failed {file_path}: {e}", self.logger)

        return False

    def _is_force_scan_file(self, file_path: Path) -> bool:
        """强制扫描检测 (保持原有逻辑)"""
        if file_path.is_dir():
            return False

        config = self.runtime.config
        paths_cfg = config.get("paths", {})
        default_extensions = paths_cfg.get("monitor_extensions",
                                           ['.php', '.php3', '.php4', '.php5', '.php7', '.php8',
                                            '.phtml', '.phar', '.phpt', '.phtm',
                                            '.asp', '.aspx', '.asa', '.ashx', '.asmx', '.asax',
                                            '.jsp', '.jspx', '.jspa', '.jspf', '.jsw', '.jsv',
                                            '.txt', '.inc', '.bak', '.old'])

        if file_path.suffix.lower() in default_extensions:
            return True

        try:
            filesizes_cfg = config.get("filesizes", {})
            max_size_mb = filesizes_cfg.get("max_scan_file_size_mb", 5)

            if file_path.stat().st_size > max_size_mb * 1024 * 1024:
                return False

            header = file_path.read_bytes()[:256]

            if header.startswith(b'<?php') or b'<?=' in header or b'<? ' in header:
                log_with_symbol("detect_php", "warning", f"PHP script detected: {file_path.name}", self.logger)
                return True

            if header.startswith(b'<%@') or b'%!' in header or b'%\n' in header:
                log_with_symbol("detect_jsp", "warning", f"JSP script detected: {file_path.name}", self.logger)
                return True

            if header.startswith(b'<%') and b'%>' in header[:100]:
                log_with_symbol("detect_asp", "warning", f"ASP script detected: {file_path.name}", self.logger)
                return True

        except Exception as e:
            log_with_symbol("detect_error", "warning", f"Detection failed {file_path}: {e}", self.logger)

        return False


    # ===== v1.7.9: 异步扫描工作线程 =====
    def _start_scan_worker(self):
        """启动后台扫描工作线程（仅一次）"""
        if self._scan_worker_thread is not None and self._scan_worker_thread.is_alive():
            return
        self._scan_worker_shutdown.clear()
        self._scan_worker_thread = threading.Thread(
            target=self._scan_worker_loop, daemon=True, name="ScanWorker"
        )
        self._scan_worker_thread.start()
        self.logger.info("[SCAN][WORKER] 异步扫描工作线程已启动")

    def _scan_worker_loop(self):
        """扫描队列消费循环"""
        while not self._scan_worker_shutdown.is_set():
            try:
                event_path, event_type = self._scan_queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                if event_path is None:
                    break
                self._do_scan(event_path, event_type)
            except Exception as e:
                self.logger.error(f"[SCAN][WORKER] 消费异常: {e}", exc_info=True)
            finally:
                self._scan_queue.task_done()

    def _do_scan(self, event_path, event_type):
        """实际执行扫描（从 _handle_event 抽离）"""
        # A restored file generates a fresh filesystem event. Skip before the
        # scanner so an intentional restore produces neither a new finding nor
        # scan-log noise during its short guard window.
        try:
            if self.services.quarantine.is_recently_restored(str(event_path)):
                self.logger.info(
                    "[RESTORE][SKIP] Recently restored file: %s",
                    event_path.name,
                )
                return
        except Exception:
            self.logger.debug(
                "Failed to check restored-file guard before scanning",
                exc_info=True,
            )

        try:
            if isinstance(self.scan_callback, str):
                module_path, func_name = self.scan_callback.rsplit('.', 1)
                import importlib
                module = importlib.import_module(module_path)
                scan_func = getattr(module, func_name)
            else:
                scan_func = self.scan_callback

            scan_result = scan_func(event_path, self.scan_options, self.logger)
            self.services.metrics.increment_site("scan_total", self.site.site_id)

            # v2.0: Emit FileScannedEvent to PluginManager (dual-write: existing flow + event-driven)
            try:
                self.services.events.publish("file_scanned", "monitor", {
                    "file_path": str(event_path),
                    "event_type": event_type,
                    "is_suspicious": scan_result.is_suspicious if scan_result else False,
                    "engine": scan_result.engine if scan_result else "unknown",
                    "features": scan_result.features if scan_result else [],
                    "score": scan_result.score if scan_result and hasattr(scan_result, 'score') else 0,
                    **self.site.as_dict(),
                })
            except Exception:
                self.logger.debug("PluginManager emit file_scanned failed", exc_info=True)

            if scan_result and scan_result.is_suspicious:
                log_with_symbol("scan_hit", "critical",
                                f"{event_path.name} | 引擎: {scan_result.engine}", self.logger)

                # v1.0.9: 统一在此处完成 注册→事件化隔离，保证事务完整性
                # Surgery 4 completion: quarantine + notification go through event bus.
                try:
                    # v1.8.4 / v2.0: 本地文件检测 — 多源IP溯源
                    # 优先级: WAF事件日志 > LogAnalyzer(access log) > 默认127.0.0.1
                    first_seen_ip = "127.0.0.1"
                    event_name = event_path.name.lower()

                    # Source 1: WAF events (waf_events.jsonl)
                    # v2.0 fix: Match by TIME WINDOW, not by filename.
                    try:
                        waf_log = Path("data/waf_events.jsonl")
                        if waf_log.exists():
                            from datetime import datetime as _dt
                            now_dt = _dt.now()
                            with open(str(waf_log), 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                            for line in reversed(lines[-200:]):
                                if not line.strip():
                                    continue
                                evt = json.loads(line.strip())
                                src_ip = evt.get("src_ip", "")
                                if not src_ip or src_ip in ("127.0.0.1", "::1"):
                                    continue
                                evt_ts_str = evt.get("timestamp", "")
                                if evt_ts_str:
                                    try:
                                        evt_dt = _dt.fromisoformat(evt_ts_str.replace("Z", "+00:00"))
                                        if abs((now_dt - evt_dt).total_seconds()) <= 15:
                                            method = evt.get("method", "") or evt.get("http_method", "")
                                            if method.upper() in ("POST", "PUT", ""):
                                                first_seen_ip = src_ip
                                                self.logger.info(f"[MONITOR] Resolved attacker IP from WAF: {first_seen_ip} -> {event_name} (time-window match, Δ={abs((now_dt - evt_dt).total_seconds()):.1f}s)")
                                                break
                                    except (ValueError, TypeError, AttributeError):
                                        pass
                    except Exception:
                        self.logger.debug("Failed to parse WAF event log for IP resolution", exc_info=True)

                    # Source 2: LogAnalyzer — Apache/Nginx access log (正则解析)
                    # Access-log attribution is opt-in.  Otherwise a default
                    # placeholder path creates a warning for every detection.
                    log_config = getattr(self.website, "log_config", {}) or {}
                    if (
                        first_seen_ip == "127.0.0.1"
                        and log_config.get("log_monitor_enabled", False)
                    ):
                        try:
                            from anteumbra.infrastructure.monitoring.log_analyzer import LogAnalyzer
                            analyzer = LogAnalyzer(self.website, self.logger)
                            result = analyzer.analyze_shell_access(event_path)
                            if result and result.get("suspicious_ips"):
                                best_ip = max(result["suspicious_ips"], key=result["suspicious_ips"].get)
                                if best_ip and best_ip not in ("127.0.0.1", "::1"):
                                    first_seen_ip = best_ip
                                    self.logger.info(
                                        f"[MONITOR] Resolved attacker IP from access log: {first_seen_ip} -> {event_name} "
                                        f"(hits: {result['suspicious_ips'][best_ip]}, log: {result.get('log_path', '?')})"
                                    )
                        except Exception:
                            self.logger.debug("LogAnalyzer failed to resolve attacker IP", exc_info=True)

                    # v1.0.9: Critical detection alert via event bus → notifier_handler
                    self._emit_alert("local_detection", str(event_path),
                                     scan_result.engine, scan_result.features,
                                     first_seen_ip, "CRITICAL")

                    # Step 1: 注册到Registry — add() emits record_added internally
                    self.services.registry.add(
                        event_path,
                        scan_result.features,
                        first_seen_ip=first_seen_ip,
                        detection_source="passive",
                        site=self.site,
                    )

                    # Step 2: 检查隔离总开关（日志用；quarantine_handler 也会检查）
                    quarantine_enabled = True
                    try:
                        quarantine_enabled = self.runtime.config.get(
                            "quarantine", {}
                        ).get("auto_quarantine_enabled", True)
                    except Exception:
                        self.logger.debug("Failed to read quarantine config", exc_info=True)

                    if not quarantine_enabled:
                        self.logger.info(f"[QUARANTINE] 总开关关闭，跳过隔离: {event_path.name}")
                        self._emit_alert("quarantine_skipped", str(event_path),
                                         scan_result.engine, scan_result.features,
                                         first_seen_ip, "WARNING",
                                         reason="auto_quarantine_disabled")
                    elif self.services.quarantine.is_recently_restored(str(event_path)):
                        self.logger.info(f"[QUARANTINE] 跳过刚恢复文件: {event_path.name}")
                    else:
                        # Step 3: 事件化隔离 — quarantine_handler 处理全链路
                        # (quarantine_file → mark_quarantined → batch/skip/failure alert)
                        rule_name = scan_result.features[0] if scan_result.features else "unknown"
                        self._emit_file_quarantined(
                            file_path=str(event_path),
                            rule_name=rule_name,
                            features=scan_result.features,
                            original_path=str(event_path),
                            first_seen_ip=first_seen_ip,
                        )
                except Exception as qe:
                    self.logger.warning(f"[QUARANTINE] 隔离失败: {event_path.name} | {qe}")

        except Exception as e:
            log_with_symbol("error_scan", "error", f"{event_path}: {e}", self.logger)

    def _stop_scan_worker(self):
        """停止扫描工作线程"""
        self._scan_worker_shutdown.set()
        if self._scan_worker_thread and self._scan_worker_thread.is_alive():
            try:
                self._scan_queue.put_nowait((None, None))
            except queue.Full:
                # The worker observes the shutdown flag after the current item.
                pass
            self._scan_worker_thread.join(timeout=3)

    def shutdown(self):
        """Release worker resources when the owning WebsiteMonitor stops."""
        self._stop_scan_worker()

    def enqueue_scan(self, event_path: Path, event_type: str) -> None:
        """Queue a scan or apply backpressure without losing the event."""
        if self._scan_worker_shutdown.is_set():
            return
        try:
            self._scan_queue.put(
                (event_path, event_type),
                timeout=self._scan_queue_put_timeout,
            )
        except queue.Full:
            try:
                self.services.metrics.increment(
                    "scan_queue_overflow", site_id=self.site.site_id
                )
            except Exception:
                self.logger.debug("Failed to record scan queue overflow", exc_info=True)
            log_with_symbol(
                "scan_queue_full",
                "warning",
                f"扫描队列已满，同步处理: {event_path.name}",
                self.logger,
            )
            self._do_scan(event_path, event_type)

    def _handle_event(self, event, event_type: str, override_path: Path = None):
        """v1.7.9: 统一事件处理 → 异步入队，不阻塞watchdog主线程"""
        if getattr(event, "is_directory", False):
            return

        event_path = override_path or normalize_path(event.src_path)
        event_path = event_path.resolve()

        if not self._should_monitor(event_path):
            return

        if self._is_duplicate(event_path):
            log_with_symbol("skip_duplicate", "info",
                            f"重复事件已过滤: {event_path.name} ({event_type})", self.logger)
            return

        try:
            self.enqueue_scan(event_path, event_type)
        except Exception as e:
            log_with_symbol("error_scan", "error", f"{event_path}: {e}", self.logger)

    # ===== v1.8.1: 事件处理方法 (使用新的 _verify_directory) =====

    def on_created(self, event):
        """文件/目录创建事件"""
        try:
            path = normalize_path(event.src_path).resolve()

            if not path.exists():
                log_with_symbol("create_skip", "debug", f"路径不存在: {event.src_path}", self.logger)
                return

            # ===== 目录处理: 使用 _verify_directory 验证 =====
            if path.is_dir():
                log_with_symbol("create_dir", "info", f"{path.name}", self.logger)
                self._record_directory(path)
                return

            # ===== 文件处理 =====
            log_with_symbol("create_file", "info", f"{path.name}", self.logger)

            # Linux优化: 等待文件内容写入
            if sys.platform != "win32":
                wait_count = 0
                while path.stat().st_size == 0 and wait_count < 10:
                    time.sleep(0.01)
                    wait_count += 1
                if wait_count > 0:
                    log_with_symbol("create_wait", "debug",
                                    f"{path.name} 等待内容写入 {wait_count * 10}ms", self.logger)

            # 记录父目录到缓存
            self._record_directory(path.parent)

            # 统一事件处理
            self._handle_event(event, "CREATE")

        except PermissionError:
            log_with_symbol("critical_permission", "critical",
                            f"权限被拒绝: {event.src_path}", self.logger)
        except Exception as e:
            log_with_symbol("create_error", "critical", f"致命错误: {e}", self.logger)

    def on_modified(self, event):
        """文件修改事件 (v1.8.1)"""
        try:
            path = normalize_path(event.src_path).resolve()

            # 使用 _verify_directory 检查是否为目录
            if self._verify_directory(path):
                log_with_symbol("skip_duplicate", "debug", f"跳过目录修改: {path.name}", self.logger)
                return

            log_with_symbol("modify", "info", f"{path.name}", self.logger)
            self._handle_event(event, "MODIFY")

        except PermissionError:
            log_with_symbol("warning_permission", "warning",
                            f"修改权限被拒绝: {event.src_path}", self.logger)
        except FileNotFoundError:
            log_with_symbol("delete_file", "info",
                            f"文件在修改期间被删除: {event.src_path}", self.logger)
        except Exception as e:
            log_with_symbol("error_scan", "error",
                            f"修改事件处理失败: {e}", self.logger)

    def on_moved(self, event):
        """
        v1.8.1: 移动事件处理 (幽灵目录兼容)
        使用 _verify_directory 替代直接缓存检查
        """
        try:
            src_path = normalize_path(event.src_path).resolve()
            dest_path = normalize_path(event.dest_path).resolve()

            # ===== 使用 _verify_directory 检测源是否为目录 =====
            src_key = self._normalize_path(src_path)
            is_directory = self._verify_directory(src_path)

            if is_directory:
                log_with_symbol("move_dir", "info",
                                f"{src_path.name} -> {dest_path.name}", self.logger)

                # 更新缓存: 重命名所有子目录键
                dest_key = self._normalize_path(dest_path)
                new_cache = set()
                new_ttl = {}

                for cached_key in self._dir_cache:
                    if cached_key.startswith(src_key):
                        new_key = dest_key + cached_key[len(src_key):]
                        new_cache.add(new_key)
                        # 保留原TTL时间戳
                        new_ttl[new_key] = self._cache_ttl.get(cached_key, time.time())
                    else:
                        new_cache.add(cached_key)
                        new_ttl[cached_key] = self._cache_ttl.get(cached_key, time.time())

                self._dir_cache = new_cache
                self._cache_ttl = new_ttl

                # 更新别名映射
                new_aliases = {}
                for cached_dest, cached_src in self._path_aliases.items():
                    new_cached_dest = cached_dest
                    if cached_dest.startswith(src_key):
                        new_cached_dest = dest_key + cached_dest[len(src_key):]

                    new_cached_src = cached_src
                    if cached_src.startswith(src_key):
                        new_cached_src = dest_key + cached_src[len(src_key):]

                    new_aliases[new_cached_dest] = new_cached_src

                # 添加当前移动关系的别名
                new_aliases[dest_key] = src_key
                self._path_aliases = new_aliases

                self.logger.debug(f"[MOVE][DIR] 缓存已更新: {len(self._dir_cache)}个目录键")

            else:
                log_with_symbol("move_file", "info",
                                f"{src_path.name} -> {dest_path.name}", self.logger)
                self._update_cache_on_move(src_path, dest_path)

            # File moves now enter the same queue and scan transaction as
            # create/modify events. This preserves attribution, alerting,
            # metrics, Registry writes, and quarantine behavior in one flow.
            if not is_directory:
                self._handle_event(event, "MOVE", override_path=dest_path)

        except PermissionError:
            log_with_symbol("warning_permission", "warning",
                            f"移动权限被拒绝: {event.src_path}", self.logger)
        except Exception as e:
            log_with_symbol("error_scan", "error", f"移动事件处理失败: {e}", self.logger)

    def on_deleted(self, event):
        """
        v1.8.1: 删除事件处理 (基于 _verify_directory 的真实修复)
        """
        event_path = normalize_path(event.src_path)
        path_key = self._normalize_path(event_path)

        # 正确判断: 检查缓存中是否存在该路径键
        is_directory = path_key in self._dir_cache

        if is_directory:
            log_with_symbol("delete_dir", "info", f"{event_path.name}", self.logger)

            # 激进清理: 删除该目录及其所有子孙路径
            self._dir_cache = {
                k for k in self._dir_cache
                if not k.startswith(path_key)
            }
            self._cache_ttl = {
                k: v for k, v in self._cache_ttl.items()
                if not k.startswith(path_key)
            }
            self._path_aliases = {
                new: old for new, old in self._path_aliases.items()
                if not (old.startswith(path_key) or new.startswith(path_key))
            }
        else:
            # v2.0 fix: Check if this file was quarantined before logging DELETE
            is_quarantined = False
            try:
                record = self.services.registry.get(
                    event_path, site_id=self.site.site_id
                )
                is_quarantined = bool(record and record.get("quarantine_id"))
            except Exception:
                self.logger.warning(
                    "Failed to check quarantine status for deleted file",
                    exc_info=True,
                )

            if is_quarantined:
                log_with_symbol("quarantine_add", "info",
                                f"[QUARANTINE][FILE] 隔离完成(文件已移走): {event_path.name}", self.logger)
            else:
                log_with_symbol("delete_file", "info", f"[DELETE][FILE] {event_path.name}", self.logger)

        # Registry清理
        if self.services.registry.remove(event_path, site=self.site):
            log_with_symbol("registry_remove", "info",
                            f"Registry清理: {event_path.name}", self.logger)

    def on_closed(self, event):
        """文件关闭事件"""
        path = normalize_path(event.src_path)
        if self._verify_directory(path):
            return
        if self._should_monitor(path):
            log_with_symbol("close", "info", path.name, self.logger)
            self._handle_event(event, "CLOSE")


class WebsiteMonitor:
    """网站监控管理器 (保持原有逻辑)"""

    def __init__(
        self,
        website: Website,
        scan_callback: Callable,
        logger: logging.Logger,
        services: RuntimeServices,
    ):
        self.website = website
        self.scan_callback = scan_callback
        self.logger = logger
        self.services = services
        self._is_running = False
        self._baseline_stop = threading.Event()
        self._baseline_thread = None

        self.logger.debug(f"[DEBUG][CONFIG] Website配置: {website.name}")

        # 初始化处理器 (v1.8.1版本)
        self.handler = FileMonitorHandler(
            scan_callback=scan_callback,
            scan_options=website.scan_options,
            base_path=website.path,
            logger=logger,
            services=self.services,
            website=website  # v1.0.10: 修复 LogAnalyzer(self.website, ...)
        )

        # 初始化Observer
        self.observer = get_optimal_observer()

        # Linux权限检查
        if sys.platform != "win32":
            if not os.access(str(website.path), os.R_OK):
                log_with_symbol("critical_permission", "critical",
                                f"监控路径无读取权限: {website.path}", logger)
                raise PermissionError(f"权限不足: {website.path}")

        # 调度监控
        self.observer.schedule(self.handler, str(website.path), recursive=True)

        log_with_symbol("success", "info",
                        f"{self.observer.__class__.__name__} | 路径: {website.path}", logger)

    def start(self):
        """启动监控"""
        if self._is_running:
            log_with_symbol("warning", "warning", "Duplicate start ignored", self.logger)
            return

        self.observer.start()
        self._is_running = True
        time.sleep(0.5)

        if hasattr(self.observer, 'is_alive') and not self.observer.is_alive():
            log_with_symbol("error", "error", "Observer start failed", self.logger)
            self._is_running = False
            self.handler.shutdown()
            return

        log_with_symbol("success", "info", "Monitor started successfully", self.logger)
        self._start_baseline_scan()

    def _start_baseline_scan(self):
        config = self.services.context.config
        if not config.get("scanner", {}).get("scan_existing_on_start", True):
            return
        if self._baseline_thread and self._baseline_thread.is_alive():
            return

        self._baseline_stop.clear()
        self._baseline_thread = threading.Thread(
            target=self._run_baseline_scan,
            daemon=True,
            name=f"BaselineScan-{self.website.name}",
        )
        self._baseline_thread.start()

    def _run_baseline_scan(self):
        queued = 0
        try:
            for root, dirs, files in os.walk(self.website.path):
                if self._baseline_stop.is_set():
                    break
                dirs[:] = [
                    name for name in dirs
                    if name.lower() not in self.handler.exclude_dirs
                ]
                for filename in files:
                    if self._baseline_stop.is_set():
                        break
                    file_path = Path(root) / filename
                    if self.handler._should_monitor(file_path):
                        self.handler.enqueue_scan(file_path, "BASELINE")
                        queued += 1
            try:
                self.services.metrics.increment(
                    "baseline_runs", site_id=self.website.site_id
                )
                self.services.metrics.increment(
                    "baseline_files_queued", queued, site_id=self.website.site_id
                )
            except Exception:
                self.logger.debug("Failed to record baseline metrics", exc_info=True)
            self.logger.info(
                "[SCAN][BASELINE] %s queued %d existing files",
                self.website.name,
                queued,
            )
        except Exception:
            self.logger.exception("[SCAN][BASELINE] Failed for %s", self.website.name)

    def stop(self):
        """停止监控"""
        if not self._is_running:
            return

        # v1.0.9: batch notification is now handled by quarantine_handler plugin.
        # Its deactivate() flushes any pending batch on PluginManager shutdown.

        self.observer.stop()
        self.observer.join(timeout=10.0)

        self._baseline_stop.set()
        if self._baseline_thread and self._baseline_thread.is_alive():
            self._baseline_thread.join(timeout=3.0)

        if hasattr(self.observer, 'is_alive') and self.observer.is_alive():
            log_with_symbol("warning", "warning",
                            "Observer未能在10秒内停止，可能资源泄漏", self.logger)

        self._is_running = False
        log_with_symbol("info", "info", "Monitor stopped", self.logger)

        if hasattr(self, 'handler'):
            self.handler.shutdown()
            del self.handler

    @property
    def is_running(self) -> bool:
        return self._is_running
