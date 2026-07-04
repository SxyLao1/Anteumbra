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
        self._stats = {
            "scan_total": 0,
            "scan_suspicious": 0,
            "alert_total": 0,
            "alert_cooldown_suppressed": 0,
            "registry_size": 0,
            "log_lines_processed": 0,
            "uptime_seconds": 0
        }
        self._start_time = time.time()
        # 微信推送失败计数
        self._stats["wechat_failures"] = 0

    def record_wechat_failure(self):
        self._stats["wechat_failures"] += 1

    def record_memory_usage(self):
        import psutil
        p = psutil.Process()
        self._stats["memory_mb"] = p.memory_info().rss / 1024 / 1024

    def increment(self, metric: str, value: int = 1):
        self._stats[metric] = self._stats.get(metric, 0) + value

    def get(self) -> Dict[str, Any]:
        """v1.7.7-Patch10: 增强鲁棒性，确保所有字段存在"""
        self._stats["uptime_seconds"] = time.time() - self._start_time

        # 核心修复：异常时返回默认值而非崩溃
        try:
            from anteumbra.infrastructure.suspicious_registry import get_all

            # 只统计file_exists=True且marked_false_positive=False
            active_threats = get_all(include_deleted=False, include_false_positive=False)
            self._stats["scan_suspicious"] = len(active_threats)

        except Exception as e:
            logging.getLogger("monitor.metrics").warning(f"[METRICS] Registry查询失败: {e}")
            self._stats["scan_suspicious"] = 0  # 确保字段存在

        # v1.7.6-Patch25: 确保所有必要字段存在
        self._stats.setdefault("scan_total", 0)
        self._stats.setdefault("scan_suspicious", 0)
        self._stats.setdefault("memory_mb", 0)
        self._stats.setdefault("uptime_seconds", 0)
        self._stats.setdefault("registry_qsize", 0)
        self._stats.setdefault("alert_qsize", 0)

        return self._stats

    def persist(self):
        """每分钟持久化"""
        self.data_path.write_text(json.dumps(self.get(), indent=2), encoding='utf-8')

    def load_persisted(self):
        """启动时加载历史scan_total"""
        if self.data_path.exists():
            try:
                saved = json.loads(self.data_path.read_text(encoding='utf-8'))
                self._stats["scan_total"] = saved.get("scan_total", 0)
                logging.getLogger("monitor.metrics").info(
                    f"[METRICS] 已加载历史数据: scan_total={self._stats['scan_total']}"
                )
            except Exception as e:
                logging.getLogger("monitor.metrics").warning(f"[METRICS] 加载失败: {e}")

# 全局实例
_metrics_instance: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """获取指标收集器单例"""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = MetricsCollector()
    return _metrics_instance

def preload_metrics():
    """启动时预热metrics，避免首次访问延迟"""
    try:
        metrics = get_metrics()
        metrics.record_memory_usage()
        metrics.get()  # 触发完整计算

        # v1.7.6-Patch19: 加载历史数据并启动持久化
        logger = logging.getLogger("monitor.metrics")
        metrics.load_persisted()  # 加载磁盘数据到内存
        logger.info(f"[METRICS][LOAD] 历史数据加载完成: scan_total={metrics._stats['scan_total']}")

        # 启动后台持久化线程（60秒间隔）
        def _persistence_worker():
            while True:
                time.sleep(60)
                try:
                    metrics.persist()
                    logger.debug(f"[METRICS][PERSIST] scan_total 已保存")
                except Exception as e:
                    logger.error(f"[METRICS][PERSIST] 失败: {e}")

        thread = threading.Thread(target=_persistence_worker, daemon=True, name="MetricsPersistence")
        thread.start()
        logger.info("[METRICS][PERSIST] 持久化线程已启动")

    except Exception as e:
        logging.getLogger("monitor.metrics").warning(f"[METRICS] Preload failed: {e}")