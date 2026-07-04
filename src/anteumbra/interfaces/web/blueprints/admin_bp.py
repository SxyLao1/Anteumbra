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
import os
import queue
import re
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import unquote
from anteumbra.application.sse_service import persist_log_line

from flask import (
    Blueprint, render_template, request, jsonify, abort,
    make_response, Response, current_app, stream_with_context,
    session, redirect, url_for
)
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import secrets

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.application.registry_service import get_all, remove
from anteumbra.application.logging_service import log_with_symbol
from anteumbra.infrastructure.utils.path_utils import normalize_path, path_to_key
from anteumbra.application.platform_service import check_port_reachable
from anteumbra.application.sse_service import register_sse_client, unregister_sse_client, \
    trigger_registry_update
from anteumbra.application.password_service import check_password_strength, update_password_hash_in_config
from anteumbra.interfaces.web.auth import require_auth, get_admin_credentials

logger = logging.getLogger(__name__)

# 创建Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# v1.9.0: 扫描结果缓存（供报告生成使用，1小时TTL）

from flask_wtf.csrf import generate_csrf

@admin_bp.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

def generate_secure_sse_token(username: str) -> str:
    random_part = secrets.token_urlsafe(16)
    token_str = f"{username}:{random_part}"
    return base64.b64encode(token_str.encode()).decode()


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
        websites = ConfigRegistry.get_enabled_websites()
        website = websites[0] if websites else None
        website_reachable = False
        website_info = None
        if website:
            website_reachable = check_port_reachable("127.0.0.1", website.port)
            website._reachable = website_reachable
            website_info = {
                'name': website.name,
                'port': website.port,
                'path': str(website.path),
                'reachable': website_reachable,
                'port_status': '已监听' if website_reachable else '未监听'
            }
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

        # v1.8.0: 历史日志始终从 monitor.log 读取（buffer 仅用于 SSE 实时推送）
        import json
        log_history_html = ""
        try:
            log_file = normalize_path("logs/Website-PhpStudy/monitor.log")
            if log_file.exists():
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
                    lines = all_lines[-500:]
                    html_parts = []
                    for line in lines:
                        line = line.strip()
                        if not line or '[SSE]' in line:
                            continue
                        safe_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        html_parts.append(f'<div class="log-line">{safe_line}</div>')
                    log_history_html = ''.join(html_parts)
        except Exception:
            logger.debug("Failed to read monitor.log for overview log history", exc_info=True)

        return render_template('admin/overview.html',
            auth_header=auth_header, username=username,
            client_ip=request.remote_addr, log_history=log_history_html)
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
        from anteumbra.application.registry_service import get_all
        from anteumbra.application.quarantine_service import get_quarantine_stats

        all_records = get_all(include_deleted=True)
        quarantine_stats = get_quarantine_stats()

        total = len(all_records)
        quarantined = quarantine_stats.get("quarantined", 0)
        false_positives = sum(1 for r in all_records if r.get("marked_false_positive", False))
        # v1.8.2: quarantine stats 含历史数据可能 > registry total，cap at 100%
        protection_rate = round((min(quarantined, total) / total * 100), 1) if total > 0 else 0.0

        # 最近5条检测事件
        recent = []
        for r in all_records[:5]:
            try:
                file_name = Path(r.get("file_path", "")).name
            except Exception:
                file_name = "unknown"
            recent.append({
                "time": r.get("detected_at", "N/A")[:16],
                "file": file_name,
                "rule": r.get("features", ["Unknown"])[0] if r.get("features") else "Unknown",
                "quarantined": False,
                "false_positive": r.get("marked_false_positive", False)
            })

        stats = {
            "total_detections": total,
            "quarantined": quarantined,
            "false_positives": false_positives,
            "protection_rate": protection_rate
        }

        return render_template(
            'admin/dashboard_content.html',
            stats=stats,
            recent_events=recent,
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
        websites = ConfigRegistry.get_enabled_websites()
        website = websites[0] if websites else None
        website_reachable = False
        if website:
            website_reachable = check_port_reachable("127.0.0.1", website.port)
        website_info = {
            'name': website.name if website else 'Unknown',
            'port': website.port if website else 80,
            'path': str(website.path) if website else '/unknown',
            'reachable': website_reachable,
            'port_status': '已监听' if website_reachable else '未监听'
        } if website else None

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


def require_auth_except_sse(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.path == '/admin/stream_logs':
            return f(*args, **kwargs)
        return require_auth(f)(*args, **kwargs)

    return decorated


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
        log_with_symbol("critical_permission", "critical", f"登录频率限制触发: {client_ip}")
        return render_template('admin/login.html', error=rate_msg), 429

    if client_ip not in allowed_ips:
        log_with_symbol("critical_permission", "critical", f"登录IP被拒绝: {client_ip}")
        return render_template('admin/login.html', error=f"IP {client_ip} 被拒绝访问"), 403
    if username == expected_username and check_password_hash(password_hash, password):
        # 登录成功：清除该IP的速率计数
        with _login_lock:
            _login_attempts.pop(client_ip, None)
        session['authenticated'] = True
        session['username'] = username
        session.permanent = current_app.config.get('SESSION_PERMANENT', False)
        session['sse_token'] = generate_secure_sse_token(username)
        log_with_symbol("success", "info", f"用户 {username} 登录成功")
        return redirect(url_for('admin.dashboard_index'))
    log_with_symbol("critical_permission", "critical", f"登录失败: {username}")
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
    log_with_symbol("success", "info", f"用户 {username} 已登出")
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
    websites = ConfigRegistry.get_enabled_websites()
    website = websites[0] if websites else None
    website_reachable = False
    if website:
        website_reachable = check_port_reachable("127.0.0.1", website.port)
    website_info = {
        'name': website.name if website else 'Unknown',
        'port': website.port if website else 80,
        'path': str(website.path) if website else '/unknown',
        'reachable': website_reachable,
        'port_status': '已监听' if website_reachable else '未监听'
    } if website else None
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
        from anteumbra.application.metrics_service import get_metrics
        metrics = get_metrics()

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
        from anteumbra.application.metrics_service import get_metrics
        m = get_metrics()
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
        from anteumbra.application.metrics_service import get_metrics
        metrics = get_metrics()

        # 安全获取内存数据
        try:
            metrics.record_memory_usage()
        except Exception as e:
            current_app.logger.warning(f"[METRICS] 内存监控失败: {e}")
            metrics._stats["memory_mb"] = 0

        data = metrics.get()

        # 安全获取阈值配置
        try:
            config = ConfigRegistry.get_raw_config()
            thresholds = config.get("thresholds", {})
            visual_alert = thresholds.get("visual_alert", {})
            warning_threshold = visual_alert.get("warning_threshold", 1)
            critical_threshold = visual_alert.get("critical_threshold", 3)
        except Exception as e:
            current_app.logger.warning(f"[METRICS] 阈值配置读取失败: {e}")
            warning_threshold = 1
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
        l_mem = _("Memory")
        l_uptime = _("Uptime")
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
    return hashlib.md5(value.encode()).hexdigest()[:8]



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
        data = request.get_json()
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
    status = {"status": "healthy"}

    # Quick component checks
    try:
        from anteumbra.application.config_service import load_toml_config
        load_toml_config()
    except Exception:
        status["status"] = "degraded"

    try:
        from anteumbra.application.wal_service import get_wal_info
        get_wal_info()
    except Exception:
        status["status"] = "degraded"

    http_code = 200 if status["status"] == "healthy" else 503
    return jsonify(status), http_code


@admin_bp.route('/health', methods=['GET'])
@require_auth
def admin_health():
    """Authenticated health check with full diagnostics.

    Requires login. Returns version, component status, and detailed checks.
    """
    """Health check endpoint for Docker HEALTHCHECK and monitoring systems."""
    from anteumbra.application.config_service import get_version, load_config
    status = {
        'status': 'healthy',
        'version': get_version(),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'checks': {}
    }

    # Check config
    try:
        cfg = load_config()
        status['checks']['config'] = 'ok'
    except Exception as e:
        status['checks']['config'] = f'error: {str(e)}'
        status['status'] = 'degraded'

    # Check WAL module (function-based, no class)
    try:
        from anteumbra.application.wal_service import get_wal_info
        get_wal_info()
        status['checks']['wal'] = 'ok'
    except Exception as e:
        status['checks']['wal'] = f'error: {str(e)}'
        status['status'] = 'degraded'

    # Check registry module (function-based, no class)
    try:
        from anteumbra.application.registry_service import get_all
        get_all(include_deleted=False)
        status['checks']['registry'] = 'ok'
    except Exception as e:
        status['checks']['registry'] = f'error: {str(e)}'
        status['status'] = 'degraded'

    # Check YARA engine
    try:
        from anteumbra.application.yara_service import get_yara_engine
        import logging
        get_yara_engine(logging.getLogger('health'))
        status['checks']['yara'] = 'ok'
    except Exception as e:
        status['checks']['yara'] = f'error: {str(e)}'
        status['status'] = 'degraded'

    http_code = 200 if status['status'] == 'healthy' else 503
    return jsonify(status), http_code


# ═══════════════════════════════════════════════════════════════
# v1.8.4: 安全文件内容查看器
# ═══════════════════════════════════════════════════════════════

# v1.0.5: _verify_file_in_registry / _verify_file_in_quarantine removed — use _shared.py versions
