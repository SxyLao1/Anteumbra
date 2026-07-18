# -*- coding: utf-8 -*-
"""
@Time: 1/6/2026 12:31 AM
@Auth: SxyLao1
@File: metrics.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.0重构：移除Flask应用，仅保留指标收集逻辑
"""
import json
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional
from anteumbra.infrastructure.utils.path_utils import normalize_path


class MetricsCollector:
    """Prometheus风格指标收集器"""

    def __init__(self, data_path: Path = normalize_path("data/metrics.json")):
        self.data_path = data_path
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._stats = {
            "scan_total": 0,
            "scan_suspicious": 0,
            "alert_total": 0,
            "alert_cooldown_suppressed": 0,
            "notification_attempted": 0,
            "notification_success": 0,
            "notification_failed": 0,
            "notification_skipped": 0,
            "last_notification_status": "never",
            "last_notification_error": "",
            "last_notification_at": "",
            "registry_size": 0,
            "log_lines_processed": 0,
            "scan_queue_overflow": 0,
            "baseline_runs": 0,
            "baseline_files_queued": 0,
            "plugin_queue_overflow": 0,
            "plugin_handler_timeout": 0,
            "plugin_handler_skipped": 0,
            "uptime_seconds": 0
        }
        self._start_time = time.time()
        # 微信推送失败计数
        self._stats["wechat_failures"] = 0

    def record_wechat_failure(self):
        with self._lock:
            self._stats["wechat_failures"] += 1

    def record_memory_usage(self):
        import psutil
        p = psutil.Process()
        with self._lock:
            self._stats["memory_mb"] = p.memory_info().rss / 1024 / 1024

    def increment(self, metric: str, value: int = 1):
        with self._lock:
            self._stats[metric] = self._stats.get(metric, 0) + value

    def record_notification(self, status: str, error: str = "") -> None:
        """Record the outcome of one alert notification request."""
        from datetime import datetime, timezone

        status = status.lower()
        metric = {
            "attempted": "notification_attempted",
            "success": "notification_success",
            "failed": "notification_failed",
            "partial": "notification_failed",
            "skipped": "notification_skipped",
            "queued": "notification_attempted",
        }.get(status)
        with self._lock:
            if metric:
                self._stats[metric] = self._stats.get(metric, 0) + 1
            self._stats["last_notification_status"] = status
            self._stats["last_notification_error"] = str(error)[:500]
            self._stats["last_notification_at"] = datetime.now(timezone.utc).isoformat()

    def get(self) -> Dict[str, Any]:
        """v1.7.7-Patch10: 增强鲁棒性，确保所有字段存在"""
        with self._lock:
            self._stats["uptime_seconds"] = time.time() - self._start_time

        # 核心修复：异常时返回默认值而非崩溃
        try:
            from anteumbra.infrastructure.suspicious_registry import get_all

            # 只统计file_exists=True且marked_false_positive=False
            active_threats = get_all(include_deleted=False, include_false_positive=False)
            all_records = get_all(include_deleted=True, include_false_positive=True)
            with self._lock:
                self._stats["scan_suspicious"] = len(active_threats)
                self._stats["registry_size"] = len(all_records)

        except Exception as e:
            logging.getLogger("monitor.metrics").warning(f"[METRICS] Registry查询失败: {e}")
            with self._lock:
                self._stats["scan_suspicious"] = 0  # 确保字段存在

        # v1.7.6-Patch25: 确保所有必要字段存在
        with self._lock:
            self._stats.setdefault("scan_total", 0)
            self._stats.setdefault("scan_suspicious", 0)
            self._stats.setdefault("registry_size", 0)
            self._stats.setdefault("memory_mb", 0)
            self._stats.setdefault("uptime_seconds", 0)
            self._stats.setdefault("registry_qsize", 0)
            self._stats.setdefault("alert_qsize", 0)
            self._stats.setdefault("scan_queue_overflow", 0)
            self._stats.setdefault("baseline_runs", 0)
            self._stats.setdefault("baseline_files_queued", 0)
            self._stats.setdefault("plugin_queue_overflow", 0)
            self._stats.setdefault("plugin_handler_timeout", 0)
            self._stats.setdefault("plugin_handler_skipped", 0)
            return dict(self._stats)

    def persist(self):
        """每分钟持久化"""
        self.data_path.write_text(json.dumps(self.get(), indent=2), encoding='utf-8')

    def load_persisted(self):
        """启动时加载历史scan_total"""
        if self.data_path.exists():
            try:
                saved = json.loads(self.data_path.read_text(encoding='utf-8'))
                with self._lock:
                    self._stats["scan_total"] = saved.get("scan_total", 0)
                logging.getLogger("monitor.metrics").info(
                    f"[METRICS] 已加载历史数据: scan_total={self._stats['scan_total']}"
                )
            except Exception as e:
                logging.getLogger("monitor.metrics").warning(f"[METRICS] 加载失败: {e}")

# 全局实例
_metrics_instance: Optional[MetricsCollector] = None
_metrics_thread: Optional[threading.Thread] = None
_metrics_stop_event = threading.Event()
_metrics_lifecycle_lock = threading.Lock()


def get_metrics() -> MetricsCollector:
    """获取指标收集器单例"""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = MetricsCollector()
    return _metrics_instance

def preload_metrics():
    """启动时预热metrics，避免首次访问延迟"""
    global _metrics_thread
    try:
        with _metrics_lifecycle_lock:
            if _metrics_thread is not None and _metrics_thread.is_alive():
                return

            metrics = get_metrics()
            metrics.record_memory_usage()
            metrics.load_persisted()
            metrics.get()

            logger = logging.getLogger("monitor.metrics")
            logger.info(
                "[METRICS][LOAD] Historical data loaded: scan_total=%s",
                metrics._stats["scan_total"],
            )

            _metrics_stop_event.clear()

            def _persistence_worker():
                while not _metrics_stop_event.wait(60.0):
                    try:
                        metrics.persist()
                        logger.debug("[METRICS][PERSIST] Metrics saved")
                    except Exception as e:
                        logger.error("[METRICS][PERSIST] Failed: %s", e, exc_info=True)

            _metrics_thread = threading.Thread(
                target=_persistence_worker,
                daemon=True,
                name="MetricsPersistence",
            )
            _metrics_thread.start()
            logger.info("[METRICS][PERSIST] Persistence worker started")

    except Exception as e:
        logging.getLogger("monitor.metrics").warning(f"[METRICS] Preload failed: {e}")


def stop_metrics(timeout: float = 2.0, persist: bool = True) -> bool:
    """Stop the metrics persistence worker, optionally saving one final sample."""
    global _metrics_thread

    with _metrics_lifecycle_lock:
        thread = _metrics_thread
        _metrics_stop_event.set()

    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    stopped = thread is None or not thread.is_alive()

    if persist and _metrics_instance is not None:
        try:
            _metrics_instance.persist()
        except Exception:
            logging.getLogger("monitor.metrics").exception(
                "[METRICS][PERSIST] Final persistence failed"
            )

    with _metrics_lifecycle_lock:
        if _metrics_thread is thread and stopped:
            _metrics_thread = None
    return stopped


def is_metrics_running() -> bool:
    """Return whether the persistence worker is alive."""
    with _metrics_lifecycle_lock:
        return bool(_metrics_thread and _metrics_thread.is_alive())
