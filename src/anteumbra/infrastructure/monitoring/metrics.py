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
from copy import deepcopy
from pathlib import Path
from typing import Dict, Any, Optional
from anteumbra.infrastructure.utils.path_utils import normalize_path


_SITE_COUNTER_DEFAULTS = {
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
    "wechat_failures": 0,
}


class MetricsCollector:
    """Prometheus风格指标收集器"""

    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or normalize_path("data/metrics.json")
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
        self._site_stats: Dict[str, Dict[str, Any]] = {}
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        # 微信推送失败计数
        self._stats["wechat_failures"] = 0

    def record_wechat_failure(self, *, site_id: str | None = None) -> None:
        with self._lock:
            self._stats["wechat_failures"] += 1
            if site_id:
                bucket = self._site_bucket(site_id)
                bucket["wechat_failures"] += 1

    def record_memory_usage(self):
        import psutil
        p = psutil.Process()
        with self._lock:
            self._stats["memory_mb"] = p.memory_info().rss / 1024 / 1024

    def _site_bucket(self, site_id: str) -> Dict[str, Any]:
        normalized_id = str(site_id).strip().lower()
        if not normalized_id:
            raise ValueError("site_id must not be empty")
        return self._site_stats.setdefault(normalized_id, dict(_SITE_COUNTER_DEFAULTS))

    def increment(
        self,
        metric: str,
        value: int = 1,
        *,
        site_id: str | None = None,
    ) -> None:
        with self._lock:
            self._stats[metric] = self._stats.get(metric, 0) + value
            if site_id:
                bucket = self._site_bucket(site_id)
                bucket[metric] = bucket.get(metric, 0) + value

    def increment_site(self, metric: str, site_id: str, value: int = 1) -> None:
        """Increment a site counter without double-counting a legacy global metric."""
        with self._lock:
            bucket = self._site_bucket(site_id)
            bucket[metric] = bucket.get(metric, 0) + value

    def record_notification(
        self,
        status: str,
        error: str = "",
        *,
        site_id: str | None = None,
    ) -> None:
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
            if site_id:
                bucket = self._site_bucket(site_id)
                if metric:
                    bucket[metric] = bucket.get(metric, 0) + 1
                bucket["last_notification_status"] = status
                bucket["last_notification_error"] = str(error)[:500]
                bucket["last_notification_at"] = self._stats["last_notification_at"]

    def _refresh_site_registry_stats(self) -> None:
        """Synchronize site-level registry counts without changing global totals."""
        try:
            from anteumbra.infrastructure.suspicious_registry import get_all

            active_records = get_all(
                include_deleted=False,
                include_false_positive=False,
            )
            all_records = get_all(
                include_deleted=True,
                include_false_positive=True,
            )
        except Exception:
            logging.getLogger("monitor.metrics").debug(
                "Failed to refresh site registry metrics", exc_info=True
            )
            return

        active_by_site: Dict[str, int] = {}
        total_by_site: Dict[str, int] = {}
        for record in active_records:
            site_id = str(record.get("site_id") or "legacy").lower()
            active_by_site[site_id] = active_by_site.get(site_id, 0) + 1
        for record in all_records:
            site_id = str(record.get("site_id") or "legacy").lower()
            total_by_site[site_id] = total_by_site.get(site_id, 0) + 1

        with self._lock:
            for site_id in set(active_by_site) | set(total_by_site) | set(self._site_stats):
                bucket = self._site_bucket(site_id)
                bucket["scan_suspicious"] = active_by_site.get(site_id, 0)
                bucket["registry_size"] = total_by_site.get(site_id, 0)

    def get(self, site_id: str | None = None) -> Dict[str, Any]:
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
        self._refresh_site_registry_stats()
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
            snapshot = dict(self._stats)
            snapshot["sites"] = deepcopy(self._site_stats)
            if site_id:
                return dict(snapshot["sites"].get(str(site_id).lower(), {}))
            return snapshot

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
                    saved_sites = saved.get("sites", {})
                    if isinstance(saved_sites, dict):
                        for site_id, values in saved_sites.items():
                            if not str(site_id).strip() or not isinstance(values, dict):
                                continue
                            bucket = self._site_bucket(str(site_id))
                            for key, value in values.items():
                                if isinstance(value, (int, float, str)):
                                    bucket[key] = value
                logging.getLogger("monitor.metrics").info(
                    f"[METRICS] 已加载历史数据: scan_total={self._stats['scan_total']}"
                )
            except Exception as e:
                logging.getLogger("monitor.metrics").warning(f"[METRICS] 加载失败: {e}")

    def start(self) -> None:
        """Load persisted state and start this collector's persistence worker."""
        with self._lifecycle_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            try:
                self.record_memory_usage()
            except Exception:
                logging.getLogger("monitor.metrics").debug(
                    "Initial memory sample failed",
                    exc_info=True,
                )
            self.load_persisted()
            self.get()
            self._stop_event.clear()
            self._worker = threading.Thread(
                target=self._persistence_worker,
                daemon=True,
                name="MetricsPersistence",
            )
            self._worker.start()

    def _persistence_worker(self) -> None:
        logger = logging.getLogger("monitor.metrics")
        while not self._stop_event.wait(60.0):
            try:
                self.persist()
            except Exception:
                logger.exception("[METRICS][PERSIST] Failed")

    def stop(self, timeout: float = 2.0, persist: bool = True) -> bool:
        """Stop this collector's worker and optionally persist a final sample."""
        with self._lifecycle_lock:
            worker = self._worker
            self._stop_event.set()
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=timeout)
        stopped = worker is None or not worker.is_alive()
        if persist:
            self.persist()
        with self._lifecycle_lock:
            if self._worker is worker and stopped:
                self._worker = None
        return stopped

    @property
    def is_running(self) -> bool:
        """Return whether this collector's persistence worker is alive."""
        with self._lifecycle_lock:
            return bool(self._worker and self._worker.is_alive())

# Temporary compatibility instance. Runtime code uses RuntimeContainer.metrics.
_metrics_instance: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """获取指标收集器单例"""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = MetricsCollector()
    return _metrics_instance

def preload_metrics() -> None:
    """Compatibility wrapper for callers not yet holding the collector."""
    get_metrics().start()


def stop_metrics(timeout: float = 2.0, persist: bool = True) -> bool:
    """Compatibility wrapper for callers not yet holding the collector."""
    if _metrics_instance is None:
        return True
    return _metrics_instance.stop(timeout=timeout, persist=persist)


def is_metrics_running() -> bool:
    """Compatibility wrapper for callers not yet holding the collector."""
    return bool(_metrics_instance and _metrics_instance.is_running)
