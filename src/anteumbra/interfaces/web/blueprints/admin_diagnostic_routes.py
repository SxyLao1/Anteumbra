"""Administrator metrics and health diagnostic routes."""

import logging
import time

from flask import current_app, jsonify, render_template
from flask_babel import gettext as _

from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.blueprints.admin_bp import admin_bp
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)


@admin_bp.route("/metrics/<metric_name>")
@require_auth
def get_metric(metric_name):
    """获取单个指标（v1.7.2修复：返回HTML片段）"""
    try:
        metrics = get_runtime().metrics
        metrics.record_memory_usage()
        data = metrics.get()

        if metric_name == "scan_total":
            value = data.get("scan_total", 0)
            label = _("Scan Total")
            color = "#00ff00"
        elif metric_name == "scan_suspicious":
            value = data.get("scan_suspicious", 0)
            label = _("High Risk")
            color = "#ffaa00"
        elif metric_name == "memory_mb":
            value = data.get("memory_mb", 0)
            label = _("Memory")
            color = "#00ff00"
        elif metric_name == "uptime_hours":
            value = data.get("uptime_seconds", 0) / 3600
            label = _("Uptime")
            color = "#00ff00"
        else:
            value = 0
            label = _("Unknown")
            color = "#ff0000"

        if metric_name == "memory_mb":
            val_str = f"{value:.1f} MB"
        elif metric_name == "uptime_hours":
            val_str = f"{value:.1f} h"
        else:
            val_str = str(value)

        return f"""
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color: {color};">{val_str}</div>
        """
    except Exception as e:
        err_label = _("Error")
        return f"""
        <div class="metric-label">{err_label}</div>
        <div class="metric-value" style="color: #ff0000;">{str(e)}</div>
        """


@admin_bp.route("/metrics")
@require_auth
def metrics_page():
    """性能指标页面（完整视图）"""
    # v1.9.6: Always pass explicit context dict to prevent Jinja2 UndefinedError.
    # Jinja2 raises UndefinedError when accessing attributes on an undefined
    # variable BEFORE the |default filter can run. Using .get() in the template
    # is safe because dict.get() handles missing keys gracefully.
    data = {}
    try:
        m = get_runtime().metrics
        data = m.get()
    except Exception:
        logger.debug("Failed to fetch metrics data for metrics_page", exc_info=True)
    ctx = {
        "metrics": data,
        "warning_threshold": 1,
        "critical_threshold": 3,
    }
    return render_template("admin/metrics_panel.html", **ctx)


@admin_bp.route("/metrics/data")
@require_auth
def metrics_data():
    """性能指标数据（v1.7.6-Patch12: 移除SSE属性，纯HTMX轮询）"""
    try:
        metrics = get_runtime().metrics
        metrics.record_memory_usage()
        data = metrics.get()

        # 安全获取阈值配置
        try:
            config = get_runtime().config.get()
            thresholds = config.get("thresholds", {})
            visual_alert = thresholds.get("visual_alert", {})
            critical_threshold = visual_alert.get("critical_threshold", 3)
        except Exception as e:
            current_app.logger.warning(f"[METRICS] 阈值配置读取失败: {e}")
            critical_threshold = 3

        # 关键修复：高危文件颜色计算
        suspicious_count = data.get("scan_suspicious", 0)
        if suspicious_count == 0:
            color_class = "safe"
            color_code = "#00ff00"
        elif suspicious_count < critical_threshold:
            color_class = "warning"
            color_code = "#ffaa00"
        else:
            color_class = "critical"
            color_code = "#ff4444"

        # Render HTML with i18n labels (pre-call _() to avoid f-string backslash issue)
        l_scan = _("Scan Total")
        l_risk = _("High Risk")
        l_alerts = _("Alerts")
        l_notification = _("Notification")
        l_mem = _("Memory")
        l_uptime = _("Uptime")
        notification_status = str(data.get("last_notification_status", "never"))
        notification_color = (
            "#00ff41"
            if notification_status == "success"
            else "#ffaa00"
            if notification_status in {"never", "skipped", "queued"}
            else "#ff4444"
        )
        return f"""
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">{l_scan}</div>
                <div class="metric-value">{data.get("scan_total", 0)}</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">{l_risk}</div>
                <div class="metric-value {color_class}" style="color: {color_code};">
                    {suspicious_count}
                </div>
            </div>

            <div class="metric-card">
                <div class="metric-label">{l_alerts}</div>
                <div class="metric-value">{data.get("alert_total", 0)}</div>
                <div class="metric-subtitle">registry {data.get("registry_size", 0)}</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">{l_notification}</div>
                <div class="metric-value" style="color: {notification_color}; font-size: 18px;">
                    {notification_status.upper()}
                </div>
                <div class="metric-subtitle">ok {data.get("notification_success", 0)} / failed {data.get("notification_failed", 0)} / skipped {data.get("notification_skipped", 0)}</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">{l_mem}</div>
                <div class="metric-value">{data.get("memory_mb", 0):.1f} MB</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">{l_uptime}</div>
                <div class="metric-value">{data.get("uptime_seconds", 0) / 3600:.1f} h</div>
            </div>
        </div>

        {f'<div style="margin-top: 15px; padding: 10px; background: #1a1a1a; border-left: 4px solid #ffaa00;"><small style="color: #ffaa00;">Registry queue backlog: {data.get("registry_qsize", 0)} items pending save</small></div>' if data.get("registry_qsize", 0) > 0 else ""}

        {f'<div style="margin-top: 10px; padding: 10px; background: #1a1a1a; border-left: 4px solid #ff4444;"><small style="color: #ff4444;">🚨 告警队列阻塞: {data.get("alert_qsize", 0)} 条待发送</small></div>' if data.get("alert_qsize", 0) > 10 else ""}
        """
    except Exception as e:
        current_app.logger.error(f"[ADMIN][METRICS] 致命错误: {e}", exc_info=True)
        return f'<div style="color: #ff4444;">指标加载失败: {str(e)}</div>', 500


# ============================================================================
# Health Check Endpoint (for Docker / monitoring)
# ============================================================================


@admin_bp.route("/api/v1/health", methods=["GET"])
def public_health():
    """Public health check for Docker HEALTHCHECK and load balancers.

    Intentionally open - no auth required. Returns minimal status only,
    no version numbers or sensitive data (attack surface reduction).
    """
    from anteumbra.application.runtime_health_service import assess_system_health

    runtime = get_runtime()
    health = assess_system_health(
        config_loader=runtime.config.get,
        wal_probe=runtime.wal.get_info,
        registry_probe=lambda: runtime.registry.get_all(include_deleted=False),
    )
    return jsonify({"status": health["status"]}), health["http_status"]


@admin_bp.route("/health", methods=["GET"])
@require_auth
def admin_health():
    """Authenticated health check with full diagnostics.

    Requires login. Returns version, component status, and detailed checks.
    """
    from anteumbra.application.config_service import get_version
    from anteumbra.application.runtime_health_service import assess_system_health

    runtime = get_runtime()
    health = assess_system_health(
        config_loader=runtime.config.get,
        wal_probe=runtime.wal.get_info,
        registry_probe=lambda: runtime.registry.get_all(include_deleted=False),
    )
    status = {
        "status": health["status"],
        "version": get_version(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": health["checks"],
        "capabilities": health["capabilities"],
    }
    if health["errors"]:
        status["errors"] = health["errors"]
    return jsonify(status), health["http_status"]
