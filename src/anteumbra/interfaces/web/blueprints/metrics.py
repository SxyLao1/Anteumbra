# -*- coding: utf-8 -*-
"""
@Time: 1/11/2026 10:02 PM
@Auth: SxyLao1
@File: metrics.py
@IDE: PyCharm
@Motto: HACK THE REAL
Metrics Blueprint：提供健康检查和指标API
"""
from anteumbra.infrastructure.config.version import get_version
import json
import logging
import sys
import time
from flask import Blueprint, jsonify
from pathlib import Path
from typing import Dict, Any, Optional
from anteumbra.infrastructure.utils.path_utils import normalize_path
from anteumbra.infrastructure.config.registry import ConfigRegistry

logger = logging.getLogger(__name__)

# 创建Blueprint
metrics_bp = Blueprint('metrics', __name__, url_prefix='/api/v1')


@metrics_bp.route("/health")
def health_check():
    """健康检查（容错版，避免500错误）"""
    try:
        from anteumbra.application.metrics_service import get_metrics
        metrics = get_metrics()

        # 安全获取指标，避免psutil异常
        try:
            metrics.record_memory_usage()
        except Exception as e:
            # Windows权限问题或psutil未安装
            metrics._stats["memory_mb"] = 0
            logger.warning(f"[METRICS] Memory monitoring failed: {e}")

        data = metrics.get()

        # 安全访问registry队列大小
        registry_qsize = data.get("registry_qsize", 0)

        return jsonify({
            "status": "healthy" if registry_qsize < 1000 else "warning",
            "version": get_version(),
            "platform": sys.platform,
            **data
        })
    except Exception as e:
        # v1.0.9: remove traceback leak — only log internally, never expose to caller
        import traceback
        logger.error(f"[HEALTH] Health check crashed: {e}\n{traceback.format_exc()}")

        return jsonify({
            "status": "error",
            "error": "Internal health check error",
            "version": get_version()
        }), 500


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
        self._stats["uptime_seconds"] = time.time() - self._start_time
        self._stats["registry_size"] = 0
        return self._stats

    def persist(self):
        """每分钟持久化"""
        self.data_path.write_text(json.dumps(self.get(), indent=2), encoding='utf-8')


# 全局实例
_metrics_instance: Optional['MetricsCollector'] = None


def get_metrics() -> MetricsCollector:
    """获取指标收集器单例"""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = MetricsCollector()
    return _metrics_instance