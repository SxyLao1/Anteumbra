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
import logging
import secrets

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import generate_csrf
from werkzeug.security import check_password_hash

from anteumbra.application.platform_service import check_port_reachable
from anteumbra.domain.logging import log_with_symbol
from anteumbra.interfaces.web.auth import (
    get_admin_credentials,
    is_ip_allowed,
    require_auth,
)
from anteumbra.interfaces.web.log_history import (
    collect_log_history,
    render_log_history,
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

        runtime = get_runtime()
        log_history_html = render_log_history(
            collect_log_history(runtime, limit=500, log=current_app.logger)
        )

        from anteumbra.application.runtime_health_service import assess_runtime_capabilities

        runtime_capabilities = assess_runtime_capabilities(runtime.config.get())
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
        runtime = get_runtime()
        websites = runtime.config.get_enabled_websites()
        log_history_html = render_log_history(
            collect_log_history(runtime, websites=websites, log=current_app.logger)
        )

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

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('authenticated'):
            return redirect(url_for('admin.dashboard_index'))
        return render_template('admin/login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    client_ip = request.remote_addr or "unknown"

    # v1.7.9: 过滤空用户名的无效POST（浏览器/扩展自动请求等噪音）
    if not username:
        return render_template('admin/login.html', error="请输入用户名"), 400
    if not password:
        return render_template('admin/login.html', error="请输入密码"), 400

    expected_username, password_hash, allowed_ips = get_admin_credentials()
    login_rate_limiter = get_runtime().login_rate_limiter
    rate_decision = login_rate_limiter.check_and_record(client_ip)
    if not rate_decision.allowed:
        log_with_symbol(
            "critical_permission",
            "critical",
            f"登录频率限制触发: {client_ip}",
            current_app.logger,
        )
        error = f"登录尝试过于频繁，请 {rate_decision.retry_after_seconds} 秒后重试"
        return (
            render_template('admin/login.html', error=error),
            429,
            {"Retry-After": str(rate_decision.retry_after_seconds)},
        )

    if not is_ip_allowed(client_ip, allowed_ips):
        log_with_symbol(
            "critical_permission",
            "critical",
            f"登录IP被拒绝: {client_ip}",
            current_app.logger,
        )
        return render_template('admin/login.html', error=f"IP {client_ip} 被拒绝访问"), 403
    if username == expected_username and check_password_hash(password_hash, password):
        login_rate_limiter.reset(client_ip)
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
        passwords = get_runtime().passwords
        is_strong, msg = passwords.check_strength(new_password)
        if not is_strong:
            return jsonify({"success": False, "error": msg}), 400

        # 生成新哈希并更新
        success, msg = passwords.set_password(new_password)
        if not success:
            return jsonify({"success": False, "error": msg}), 500

        username = session.get("username", "admin")
        log_with_symbol(
            "success",
            "info",
            f"用户 {username} 修改密码成功",
            current_app.logger,
        )
        session.pop("authenticated", None)
        return jsonify({"success": True, "message": msg})

    except Exception as e:
        current_app.logger.error(f"[ACCOUNT] 密码修改失败: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# v1.8.4: 安全文件内容查看器
# ═══════════════════════════════════════════════════════════════

# v1.0.5: _verify_file_in_registry / _verify_file_in_quarantine removed — use _shared.py versions

# Import route registrations after the shared Blueprint is initialized.
from anteumbra.interfaces.web.blueprints import (  # noqa: E402
    admin_diagnostic_routes as _admin_diagnostic_routes,  # noqa: F401
)
