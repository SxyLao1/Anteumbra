# -*- coding: utf-8 -*-
"""
@Time: 1/11/2026 10:02 PM
@Auth: SxyLao1
@File: metrics.py
@IDE: PyCharm
@Motto: HACK THE REAL
Metrics Blueprint：提供健康检查和指标API
"""

import logging
import sys

from flask import Blueprint, jsonify

from anteumbra.application.config_service import get_version
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

# 创建Blueprint
metrics_bp = Blueprint("metrics", __name__, url_prefix="/api/v1")


@metrics_bp.route("/health")
def health_check():
    """Public metrics plus shared runtime health and capability status."""
    try:
        from anteumbra.application.runtime_health_service import assess_system_health

        runtime = get_runtime()
        metrics = runtime.metrics
        metrics.record_memory_usage()
        data = metrics.get()

        # 安全访问registry队列大小
        registry_qsize = data.get("registry_qsize", 0)

        health = assess_system_health(
            config_loader=runtime.config.get,
            wal_probe=runtime.wal.get_info,
            registry_probe=lambda: runtime.registry.get_all(include_deleted=False),
        )
        status = health["status"]
        if registry_qsize >= 1000 and status == "healthy":
            status = "warning"

        return jsonify(
            {
                "status": status,
                "version": get_version(),
                "platform": sys.platform,
                "checks": health["checks"],
                "capabilities": health["capabilities"],
                **data,
            }
        ), health["http_status"]
    except Exception as e:
        # v1.0.9: remove traceback leak — only log internally, never expose to caller
        import traceback

        logger.error(f"[HEALTH] Health check crashed: {e}\n{traceback.format_exc()}")

        return jsonify(
            {"status": "error", "error": "Internal health check error", "version": get_version()}
        ), 503
