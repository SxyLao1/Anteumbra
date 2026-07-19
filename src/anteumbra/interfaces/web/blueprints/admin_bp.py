# -*- coding: utf-8 -*-
"""
@Time: 1/11/2026 10:03 PM
@Auth: SxyLao1
@File: admin_bp.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.6-Patch30: 操作型接口返回HTML片段而非JSON
"""
import base64
from flask_babel import gettext as _
import json
import logging
import threading
import time

from flask import (
    Blueprint, render_template, request, jsonify, current_app, session, redirect, url_for
)
from flask_wtf.csrf import generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash
import secrets

from anteumbra.application.path_service import normalize_path
from anteumbra.application.platform_service import check_port_reachable
from anteumbra.application.password_service import check_password_strength, update_password_hash_in_config
from anteumbra.domain.logging import log_with_symbol
from anteumbra.interfaces.web.auth import (
    get_admin_credentials,
    is_ip_allowed,
    require_auth,
)
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

# 创建Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# v1.9.0: 扫描结果缓存（供报告生成使用，1小时TTL）

@admin_bp.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

def generate_secure_sse_token(username: str) -> str:
    random_part = secrets.token_urlsafe(16)
    token_str = f"{username}:{random_part}"
    return base64.b64encode(token_str.encode()).decode()


def _website_info(websites):
    """Build an aggregate website status model without privileging a first site."""
    if not websites:
        return None

    sites = []
    for website in websites:
        reachable = check_port_reachable("127.0.0.1", website.port)
        sites.append(
            {
                "site_id": website.site_id,
                "name": website.name,
                "port": website.port,
                "path": str(website.path),
                "reachable": reachable,
            }
        )

    if len(sites) == 1:
        return {
            **sites[0],
            "port_status": "listening" if sites[0]["reachable"] else "unreachable",
            "site_count": 1,
            "sites": sites,
        }

    all_reachable = all(site["reachable"] for site in sites)
    return {
        "name": f"{len(sites)} monitored sites",
        "port": "multiple",
        "path": "multiple roots",
        "reachable": all_reachable,
        "port_status": "all reachable" if all_reachable else "degraded",
        "site_count": len(sites),
        "sites": sites,
    }


def _monitor_log_history(websites, limit: int = 500) -> str:
    """Read recent monitor logs from every enabled site for aggregate views."""
    lines = []
    for website in websites:
        log_file = normalize_path(f"logs/{website.name}/monitor.log")
        if not log_file.exists():
            continue
        try:
            lines.extend(log_file.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            logger.debug("Failed to read site monitor log %s", log_file, exc_info=True)
    html_parts = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line or "[SSE]" in line:
            continue
        safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_parts.append(f'<div class="log-line">{safe_line}</div>')
    return "".join(html_parts)


@admin_bp.route('/')
@require_auth
def dashboard_index():
    try:
        username = session.get('username')
        if not username:
            username, _, _ = get_admin_credentials()
            session['username'] = username
        auth_header = session.get('sse_token')
        if not auth_header:
            auth_header = generate_secure_sse_token(username)
            session['sse_token'] = auth_header
        client_ip = request.remote_addr
        websites = get_runtime().config.get_enabled_websites()
        website_info = _website_info(websites)
        return render_template(
            'admin/dashboard.html',
            auth_header=auth_header,
            username=username,
            client_ip=client_ip,
            website_info=website_info
        )
    except Exception as e:
        current_app.logger.error(f"[ADMIN] dashboard_index失败: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@admin_bp.route('/overview')
@require_auth
def overview():
    """v1.8.0: Overview — 安全态势首页，合并Dashboard+Monitor"""
    try:
        auth_header = session.get('sse_token')
        username = session.get('username', 'admin')
        if not auth_header:
            auth_header = generate_secure_sse_token(username)
            session['sse_token'] = auth_header

        log_history_html = _monitor_log_history(get_runtime().config.get_enabled_websites())

        from anteumbra.application.runtime_health_service import assess_runtime_capabilities

        runtime_capabilities = assess_runtime_capabilities(
            get_runtime().config.get()
        )
        return render_template('admin/overview.html',
            auth_header=auth_header, username=username,
            client_ip=request.remote_addr, log_history=log_history_html,
            runtime_capabilities=runtime_capabilities)
    except Exception as e:
        current_app.logger.error(f"[ADMIN] overview失败: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@admin_bp.route('/threats')
@require_auth
def threats():
    """v1.8.0: Threats — 检测记录+隔离管理合并视图"""
    try:
        return render_template('admin/threats.html')
    except Exception as e:
        current_app.logger.error(f"[ADMIN] threats失败: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500



@admin_bp.route('/dashboard_content')
@require_auth
def dashboard_content():
    """v1.7.9: 安全报告 Dashboard"""
    try:
        from anteumbra.application.dashboard_service import build_dashboard_summary

        runtime = get_runtime()
        if runtime.metrics is None:
            raise RuntimeError("MetricsCollector is not configured")
        summary = build_dashboard_summary(
            request.args.get("site_id") or None,
            metrics=runtime.metrics,
            websites=runtime.config.get_enabled_websites(),
            registry=runtime.registry,
            quarantine_stats_reader=runtime.quarantine.get_stats,
        )
        stats = summary["aggregate"]
        recent = summary["recent_events"]

        return render_template(
            'admin/dashboard_content.html',
            stats=stats,
            recent_events=recent,
            site_summaries=summary["sites"],
            compact=request.args.get('compact') == '1'
        )
    except Exception as e:
        current_app.logger.error(f"[ADMIN] dashboard_content失败: {e}", exc_info=True)
        return f'<div style="color: #ff4444;">内容加载失败: {str(e)}</div>', 500


@admin_bp.route('/monitor_content')
@require_auth
def monitor_content():
    """v1.7.9: 监测模块（原 Dashboard 内容）"""
    try:
        auth_header = session.get('sse_token')
        if not auth_header:
            username = session.get('username', 'admin')
            auth_header = generate_secure_sse_token(username)
            session['sse_token'] = auth_header
        websites = get_runtime().config.get_enabled_websites()

        log_history_html = ""
        try:
            buffer_file = normalize_path("data/sse_log_buffer.json")
            if buffer_file.exists():
                with open(buffer_file, 'r', encoding='utf-8') as f:
                    buffer_data = json.load(f)
                if isinstance(buffer_data, list):
                    lines = buffer_data[-1000:]
                    html_parts = []
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        log_class = 'info'
                        upper = line.upper()
                        if '[CRITICAL]' in upper or 'CRITICAL' in upper:
                            log_class = 'critical'
                        elif '[ERROR]' in upper or 'ERROR' in upper:
                            log_class = 'error'
                        elif '[WARNING]' in upper or 'WARN' in upper:
                            log_class = 'warn'
                        elif '[DEBUG]' in upper or 'DEBUG' in upper:
                            log_class = 'debug'
                        if line.startswith('[SSE]') and ('连接' in line or '监控' in line):
                            continue
                        safe_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        html_parts.append(f'<div class="log-line {log_class}">{safe_line}</div>')
                    log_history_html = ''.join(html_parts)
        except Exception as e:
            current_app.logger.warning(f"[MONITOR_CONTENT] 历史日志加载失败: {e}")

        website_info = _website_info(websites)
        return render_template(
            'admin/monitor_content.html',
            auth_header=auth_header,
            username=session.get('username'),
            client_ip=request.remote_addr,
            website_info=website_info,
            log_history=log_history_html,
            compact=request.args.get('compact') == '1'
        )
    except Exception as e:
        current_app.logger.error(f"[ADMIN] monitor_content失败: {e}", exc_info=True)
        return f'<div style="color: #ff4444;">内容加载失败: {str(e)}</div>', 500




# v1.7.9: 登录速率限制（V-006修复）- 每IP每分钟最多5次尝试
_login_attempts: dict = {}
_login_lock = threading.Lock()

def _check_login_rate(client_ip: str) -> tuple[bool, str]:
    """检查登录速率限制。返回 (是否允许, 错误消息)"""
    now = time.time()
    window = 60  # 60秒窗口
    max_attempts = 5  # 最多5次

    with _login_lock:
        # 清理过期记录
        expired = [ip for ip, (_, ts) in _login_attempts.items() if now - ts > window]
        for ip in expired:
            del _login_attempts[ip]

        count, first_ts = _login_attempts.get(client_ip, (0, now))
        if now - first_ts > window:
            # 窗口过期，重置
            _login_attempts[client_ip] = (1, now)
            return True, ""
        elif count >= max_attempts:
            remaining = int(window - (now - first_ts))
            return False, f"登录尝试过于频繁，请 {remaining} 秒后重试"
        else:
            _login_attempts[client_ip] = (count + 1, first_ts)
            return True, ""

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('authenticated'):
            return redirect(url_for('admin.dashboard_index'))
        return render_template('admin/login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    expected_username, password_hash, allowed_ips = get_admin_credentials()
    client_ip = request.remote_addr

    # v1.7.9: 过滤空用户名的无效POST（浏览器/扩展自动请求等噪音）
    if not username:
        return render_template('admin/login.html', error="请输入用户名"), 400

    # V-006: 速率限制检查
    allowed, rate_msg = _check_login_rate(client_ip)
    if not allowed:
        log_with_symbol(
            "critical_permission",
            "critical",
            f"登录频率限制触发: {client_ip}",
            current_app.logger,
        )
        return render_template('admin/login.html', error=rate_msg), 429

    if not is_ip_allowed(client_ip, allowed_ips):
        log_with_symbol(
            "critical_permission",
            "critical",
            f"登录IP被拒绝: {client_ip}",
            current_app.logger,
        )
        return render_template('admin/login.html', error=f"IP {client_ip} 被拒绝访问"), 403
    if username == expected_username and check_password_hash(password_hash, password):
        # 登录成功：清除该IP的速率计数
        with _login_lock:
            _login_attempts.pop(client_ip, None)
        session['authenticated'] = True
        session['username'] = username
        session.permanent = current_app.config.get('SESSION_PERMANENT', False)
        session['sse_token'] = generate_secure_sse_token(username)
        log_with_symbol(
            "success", "info", f"用户 {username} 登录成功", current_app.logger
        )
        return redirect(url_for('admin.dashboard_index'))
    log_with_symbol(
        "critical_permission", "critical", f"登录失败: {username}", current_app.logger
    )
    return render_template('admin/login.html', error="用户名或密码错误"), 401


@admin_bp.route('/logout')
@require_auth
def logout():
    username = session.get('username', 'unknown')
    session.pop('authenticated', None)
    session.pop('username', None)
    session.pop('sse_token', None)
    session.clear()
    response = redirect(url_for('admin.login'))
    response.set_cookie('session', '', expires=0)
    log_with_symbol("success", "info", f"用户 {username} 已登出", current_app.logger)
    return response
@admin_bp.route('/dashboard')
@require_auth
def dashboard():
    """返回完整仪表盘（与主页面一致）"""
    auth_header = session.get('sse_token')
    if not auth_header:
        username = session.get('username', 'admin')
        auth_str = f"{username}:session_fallback"
        auth_bytes = auth_str.encode('utf-8')
        auth_header = base64.b64encode(auth_bytes).decode('utf-8')
        session['sse_token'] = auth_header
    websites = get_runtime().config.get_enabled_websites()
    website_info = _website_info(websites)
    return render_template(
        'admin/dashboard.html',
        auth_header=auth_header,
        username=session.get('username'),
        client_ip=request.remote_addr,
        website_info=website_info
    )


@admin_bp.route('/metrics/<metric_name>')
@require_auth
def get_metric(metric_name):
    """获取单个指标（v1.7.2修复：返回HTML片段）"""
    try:
        metrics = get_runtime().metrics
        if metrics is None:
            raise RuntimeError("MetricsCollector is not configured")

        # 安全获取指标，避免psutil异常
        try:
            metrics.record_memory_usage()
        except Exception as e:
            # Windows权限问题或psutil未安装
            metrics._stats["memory_mb"] = 0
            current_app.logger.warning(f"[METRICS] Memory monitoring failed: {e}")

        data = metrics.get()

        if metric_name == 'scan_total':
            value = data.get("scan_total", 0)
            label = _("Scan Total")
            color = "#00ff00"
        elif metric_name == 'scan_suspicious':
            value = data.get("scan_suspicious", 0)
            label = _("High Risk")
            color = "#ffaa00"
        elif metric_name == 'memory_mb':
            value = data.get("memory_mb", 0)
            label = _("Memory")
            color = "#00ff00"
        elif metric_name == 'uptime_hours':
            value = (time.time() - metrics._start_time) / 3600
            label = _("Uptime")
            color = "#00ff00"
        else:
            value = 0
            label = _("Unknown")
            color = "#ff0000"

        if metric_name == 'memory_mb':
            val_str = f"{value:.1f} MB"
        elif metric_name == 'uptime_hours':
            val_str = f"{value:.1f} h"
        else:
            val_str = str(value)

        return f'''
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color: {color};">{val_str}</div>
        '''
    except Exception as e:
        err_label = _("Error")
        return f'''
        <div class="metric-label">{err_label}</div>
        <div class="metric-value" style="color: #ff0000;">{str(e)}</div>
        '''


@admin_bp.route('/metrics')
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
        if m is None:
            raise RuntimeError("MetricsCollector is not configured")
        data = m.get()
    except Exception:
        logger.debug("Failed to fetch metrics data for metrics_page", exc_info=True)
    ctx = {
        "metrics": data,
        "warning_threshold": 1,
        "critical_threshold": 3,
    }
    return render_template('admin/metrics_panel.html', **ctx)

@admin_bp.route('/metrics/data')
@require_auth
def metrics_data():
    """性能指标数据（v1.7.6-Patch12: 移除SSE属性，纯HTMX轮询）"""
    try:
        metrics = get_runtime().metrics
        if metrics is None:
            raise RuntimeError("MetricsCollector is not configured")

        # 安全获取内存数据
        try:
            metrics.record_memory_usage()
        except Exception as e:
            current_app.logger.warning(f"[METRICS] 内存监控失败: {e}")
            metrics._stats["memory_mb"] = 0

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
            color_class = 'safe'
            color_code = '#00ff00'
        elif suspicious_count < critical_threshold:
            color_class = 'warning'
            color_code = '#ffaa00'
        else:
            color_class = 'critical'
            color_code = '#ff4444'

        # Render HTML with i18n labels (pre-call _() to avoid f-string backslash issue)
        l_scan = _("Scan Total")
        l_risk = _("High Risk")
        l_alerts = _("Alerts")
        l_notification = _("Notification")
        l_mem = _("Memory")
        l_uptime = _("Uptime")
        notification_status = str(data.get("last_notification_status", "never"))
        notification_color = (
            "#00ff41" if notification_status == "success"
            else "#ffaa00" if notification_status in {"never", "skipped", "queued"}
            else "#ff4444"
        )
        return f'''
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
                <div class="metric-value">{data.get("uptime_seconds", 0)/3600:.1f} h</div>
            </div>
        </div>

        {f'<div style="margin-top: 15px; padding: 10px; background: #1a1a1a; border-left: 4px solid #ffaa00;"><small style="color: #ffaa00;">Registry queue backlog: {data.get("registry_qsize", 0)} items pending save</small></div>' if data.get("registry_qsize", 0) > 0 else ''}

        {f'<div style="margin-top: 10px; padding: 10px; background: #1a1a1a; border-left: 4px solid #ff4444;"><small style="color: #ff4444;">🚨 告警队列阻塞: {data.get("alert_qsize", 0)} 条待发送</small></div>' if data.get("alert_qsize", 0) > 10 else ''}
        '''
    except Exception as e:
        current_app.logger.error(f"[ADMIN][METRICS] 致命错误: {e}", exc_info=True)
        return f'<div style="color: #ff4444;">指标加载失败: {str(e)}</div>', 500
@admin_bp.route('/test')
@require_auth
def test():
    return "SSE Test <script>alert('JS working');</script>"


@admin_bp.route('/debug/routes')
@require_auth
def debug_routes():
    """调试：查看所有已注册路由"""
    routes = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith('/admin'):
            routes.append(f"{rule.rule} → {rule.endpoint}")
    return jsonify(routes)


@admin_bp.app_template_filter('to_hash')
def to_hash(value):
    import hashlib
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()[:8]



@admin_bp.route('/account', methods=['GET'])
@require_auth
def account_page():
    """账户设置页面"""
    return render_template('admin/account.html', username=session.get('username'))


@admin_bp.route('/account/password', methods=['POST'])
@require_auth
def change_password():
    """修改密码API"""
    try:
        # v1.0.10: 优先 JSON（API 客户端），fallback form（Web UI HTML form）
        data = request.get_json(silent=True) or {}
        if not data:
            data = request.form.to_dict()
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        # 验证必填
        if not current_password or not new_password:
            return jsonify({"success": False, "error": "请填写所有字段"}), 400

        # 验证当前密码
        _, stored_hash, _ = get_admin_credentials()
        if not check_password_hash(stored_hash, current_password):
            return jsonify({"success": False, "error": "当前密码错误"}), 401

        # 验证新密码强度
        is_strong, msg = check_password_strength(new_password)
        if not is_strong:
            return jsonify({"success": False, "error": msg}), 400

        # 生成新哈希并更新
        new_hash = generate_password_hash(new_password)
        success, msg = update_password_hash_in_config(new_hash)

        if success:
            # 强制用户重新登录
            session.pop('authenticated', None)
            log_with_symbol("success", "info", f"用户 {session.get('username')} 修改密码成功", current_app.logger)

        return jsonify({"success": success, "message": msg})

    except Exception as e:
        current_app.logger.error(f"[ACCOUNT] 密码修改失败: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# Health Check Endpoint (for Docker / monitoring)
# ============================================================================

@admin_bp.route('/api/v1/health', methods=['GET'])
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


@admin_bp.route('/health', methods=['GET'])
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
        'status': health['status'],
        'version': get_version(),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'checks': health['checks'],
        'capabilities': health['capabilities'],
    }
    if health['errors']:
        status['errors'] = health['errors']
    return jsonify(status), health['http_status']


# ═══════════════════════════════════════════════════════════════
# v1.8.4: 安全文件内容查看器
# ═══════════════════════════════════════════════════════════════

# v1.0.5: _verify_file_in_registry / _verify_file_in_quarantine removed — use _shared.py versions
