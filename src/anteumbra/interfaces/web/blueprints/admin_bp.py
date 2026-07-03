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
from anteumbra.infrastructure.utils.sse_manager import persist_log_line

from flask import (
    Blueprint, render_template, request, jsonify, abort,
    make_response, Response, current_app, stream_with_context,
    session, redirect, url_for
)
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import secrets
import shutil

import anteumbra.infrastructure as core  # compat
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.suspicious_registry import get_all, remove, _async_save_enabled, _async_save_queue
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
from anteumbra.infrastructure.utils.path_utils import normalize_path, path_to_key
from anteumbra.infrastructure.utils.platform_utils import check_port_reachable
from anteumbra.interfaces.web.blueprints.yara_bp import yara_bp
from anteumbra.infrastructure.utils.sse_manager import register_sse_client, unregister_sse_client, _sse_clients, \
    _registry_update_queue, trigger_registry_update
from anteumbra.infrastructure.utils.password_utils import check_password_strength, update_password_hash_in_config
from anteumbra.interfaces.web.auth import require_auth, get_admin_credentials

# 创建Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# v1.9.0: 扫描结果缓存（供报告生成使用，1小时TTL）

import json as _stdlib_json
from flask_wtf.csrf import generate_csrf

@admin_bp.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

def start_registry_sse_worker():
    """Registry更新推送工作线程（在app.py启动时调用）"""

    def _worker():
        logger = logging.getLogger("monitor.admin_sse")
        logger.info("[SSE][WORKER] Registry推送工作线程已启动")

        while True:
            try:
                signal = _registry_update_queue.get(timeout=1)
                if signal == "registry_update":
                    logger.debug(f"[SSE][WORKER] 广播Registry更新给 {len(_sse_clients)} 个客户端")
                    dead_clients = []
                    for client_queue in _sse_clients[:]:
                        try:
                            client_queue.put_nowait("registry_update")
                        except queue.Full:
                            dead_clients.append(client_queue)
                        except Exception:
                            dead_clients.append(client_queue)
                    for dead in dead_clients:
                        if dead in _sse_clients:
                            _sse_clients.remove(dead)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[SSE][WORKER] 工作线程异常: {e}", exc_info=True)

    worker = threading.Thread(target=_worker, daemon=True, name="RegistrySSEWorker")
    worker.start()
    return worker


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
            pass

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


@admin_bp.route('/settings')
@require_auth
def settings_page():
    """v1.8.0: Settings — 系统+账户+通知配置合并视图"""
    try:
        return render_template('admin/settings.html')
    except Exception as e:
        current_app.logger.error(f"[ADMIN] settings失败: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@admin_bp.route('/settings/notifications')
@require_auth
def settings_notifications():
    """v1.8.0: Web Config Panel — 通知配置表单"""
    try:
        from anteumbra.infrastructure.config.loader import load_config
        cfg = load_config()
        notifier = cfg.get('notifier', {})
        email = notifier.get('email', {})
        wechat = notifier.get('wechat', {})
        webhook = notifier.get('webhook', {})
        return render_template('admin/panels/notify_config.html',
            email=email, wechat=wechat, webhook=webhook)
    except Exception as e:
        current_app.logger.error(f"[ADMIN] settings/notifications失败: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">加载失败: {e}</div>', 500


@admin_bp.route('/settings/config/editor')
@require_auth
def settings_config_editor():
    """v1.8.0: 动态 config.toml 编辑器 —— 服务端解析结构，模板渲染"""
    try:
        import re as _re
        config_path = ConfigRegistry._config_path
        sections = {}
        current_section = None
        pending_desc = None

        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('# @desc:'):
                pending_desc = stripped.split('@desc:', 1)[1].strip()
                continue
            if stripped.startswith('#') or not stripped:
                continue
            if stripped.startswith('[') and stripped.endswith(']'):
                current_section = stripped[1:-1]
                sections[current_section] = []
                continue
            if '=' in stripped and current_section:
                key, _, value = stripped.partition('=')
                key = key.strip()
                raw = value.strip().rstrip('#').strip()
                # Check if env var placeholder
                is_env = '${' in raw and '}' in raw
                if raw.startswith('"') and raw.endswith('"'):
                    ftype, fval = 'string', raw[1:-1]
                elif raw.lower() in ('true', 'false'):
                    ftype, fval = 'bool', raw.lower() == 'true'
                elif raw.startswith('['):
                    ftype, fval = 'array', raw
                elif raw.replace('.', '').replace('-', '').isdigit() or (raw.startswith('-') and raw[1:].replace('.', '').isdigit()):
                    ftype = 'float' if '.' in raw else 'int'
                    fval = float(raw) if '.' in raw else int(raw)
                else:
                    ftype, fval = 'string', raw
                sections[current_section].append({
                    'key': key, 'value': fval, 'type': ftype, 'raw': raw,
                    'desc': pending_desc or '', 'is_env': is_env,
                    'display': ('(env: ' + raw[2:-1].split(':-')[0] + ')' if is_env else fval)
                })
                pending_desc = None

        # Calculate nesting levels for tree display
        levels = {}
        for sec_name in sections:
            depth = sec_name.count('.')
            levels[sec_name] = depth

        # Load .env content and parse variables
        env_vars = {}
        env_path = os.path.join(os.path.dirname(config_path), '.env')
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        env_vars[k.strip()] = v.strip()

        return render_template('admin/panels/config_editor.html',
            sections=sections, sections_levels=levels,
            config_path=str(config_path), env_vars=env_vars, os=os)
    except Exception as e:
        current_app.logger.error(f"[ADMIN] config editor failed: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">Config load error: {e}</div>', 500


@admin_bp.route('/settings/config/save', methods=['POST'])
@require_auth
def settings_config_save():
    """v1.9.5: Fix — use tomli_w for proper TOML serialization"""
    try:
        import tomli_w
        data = request.get_json()
        changes = data.get('changes', {})
        if not changes: return jsonify({'success':False,'error':'No changes'}), 400
        config_path = ConfigRegistry._config_path
        raw = ConfigRegistry.get_raw_config()
        for full_key, new_val in changes.items():
            parts = full_key.split('.')
            target = raw
            for part in parts[:-1]:
                if part not in target: target[part] = {}
                target = target[part]
            key = parts[-1]
            s = str(new_val).strip() if not isinstance(new_val, (bool,int,float,list)) else new_val
            if isinstance(s, bool): target[key] = s
            elif isinstance(s, (int,float)): target[key] = s
            elif isinstance(s, str):
                if s.lower() in ('true','false'): target[key] = s.lower() == 'true'
                elif s.startswith('[') and s.endswith(']'):
                    import json
                    try: target[key] = json.loads(s)
                    except: target[key] = s
                else:
                    try:
                        if '.' in s: target[key] = float(s)
                        else: target[key] = int(s)
                    except ValueError: target[key] = s
            else: target[key] = new_val
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(tomli_w.dumps(raw))
        try: ConfigRegistry.initialize(force=True)
        except: pass
        return jsonify({'success':True,'message':'Config saved'})
    except Exception as e:
        current_app.logger.error(f'[ADMIN] config save failed: {e}', exc_info=True)
        return jsonify({'success':False,'error':str(e)}), 500
@admin_bp.route('/settings/config/data')
@require_auth
def settings_config_data():
    """v1.8.0: 返回 config.toml 结构化数据 + 注释描述，前端动态渲染"""
    try:
        config_path = ConfigRegistry._config_path
        sections = {}
        current_section = None
        pending_desc = None

        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line in lines:
            stripped = line.strip()

            # Parse @desc comment
            if stripped.startswith('# @desc:'):
                pending_desc = stripped.split('@desc:', 1)[1].strip()
                continue
            # Skip other comments and empty lines
            if stripped.startswith('#') or not stripped:
                continue

            # Section header
            if stripped.startswith('[') and stripped.endswith(']'):
                current_section = stripped[1:-1]
                sections[current_section] = {'title': current_section, 'fields': {}}
                continue

            # Key-value
            if '=' in stripped and current_section:
                key, _, value = stripped.partition('=')
                key = key.strip()
                value = value.strip().rstrip('#').strip()

                # Determine type
                if value.startswith('"') and value.endswith('"'):
                    ftype, fval = 'string', value[1:-1]
                elif value.lower() in ('true', 'false'):
                    ftype, fval = 'bool', value.lower() == 'true'
                elif value.startswith('['):
                    ftype, fval = 'array', value
                elif value.replace('.', '').replace('-', '').isdigit() or (value.startswith('-') and value[1:].replace('.', '').isdigit()):
                    ftype = 'float' if '.' in value else 'int'
                    fval = float(value) if '.' in value else int(value)
                else:
                    ftype, fval = 'string', value

                sections[current_section]['fields'][key] = {
                    'value': fval if ftype != 'array' else value,
                    'type': ftype,
                    'desc': pending_desc or ''
                }
                pending_desc = None

        return jsonify({'sections': sections, 'path': str(config_path)})
    except Exception as e:
        current_app.logger.error(f"[ADMIN] config data failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/settings/env/save', methods=['POST'])
@require_auth
def settings_env_save():
    """v1.8.0: 保存 .env 文件（结构化变量）"""
    try:
        data = request.get_json()
        vars_data = data.get('vars', {})
        config_path = ConfigRegistry._config_path
        env_path = os.path.join(os.path.dirname(config_path), '.env')

        # Read existing .env, update changed vars, write back
        existing = {}
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        existing[k.strip()] = line  # keep original line

        # Merge changes
        for k, v in vars_data.items():
            if v:  # only write non-empty values
                existing[k] = f'{k}={v}'

        with open(env_path, 'w', encoding='utf-8') as f:
            f.write('# Trident .env — managed via Settings UI\n')
            for k in sorted(existing.keys()):
                f.write(existing[k] + '\n')
            if not f.tell() == 0:
                pass  # Ensure file is written

        # Update os.environ and reload config so new values take effect immediately
        for k, v in vars_data.items():
            if v:
                os.environ[k] = v
        try:
            ConfigRegistry.initialize(force=True)
        except Exception:
            pass

        return jsonify({'success': True, 'message': '.env saved + config reloaded'})
    except Exception as e:
        current_app.logger.error(f"[ADMIN] env save failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@admin_bp.route('/settings/env/hash', methods=['POST'])
@require_auth
def settings_env_hash():
    """v1.8.0: 生成 scrypt 密码哈希"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        if not password or len(password) < 6:
            return jsonify({'error': 'Password too short (min 6 chars)'}), 400
        from werkzeug.security import generate_password_hash
        h = generate_password_hash(password, method='scrypt:32768:8:1')
        return jsonify({'hash': h})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/settings/notifications/save', methods=['POST'])
@require_auth
def settings_notifications_save():
    """v1.8.0: 保存通知开关状态到 config.toml"""
    try:
        section = request.form.get('section', '')
        key = request.form.get('key', '')
        value = request.form.get('value', 'on')  # checkbox sends 'on' when checked

        if section not in ('email', 'wechat', 'webhook') or key not in ('enabled',):
            return jsonify({"error": "Invalid parameters"}), 400

        # Read config.toml, update, write back
        config_path = ConfigRegistry._config_path
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        in_target_section = False
        section_header = f'[notifier.{section}]'
        for i, line in enumerate(lines):
            if line.strip() == section_header:
                in_target_section = True
                continue
            if in_target_section:
                if line.strip().startswith('['):
                    break  # next section, stop
                if line.strip().startswith(f'{key} =') or line.strip().startswith(f'{key}='):
                    # Toggle: if 'on', set to true; if not present, set to false
                    # Checkbox: unchecked means the field is not sent
                    new_val = 'true' if value == 'on' else 'false'
                    lines[i] = f'{key} = {new_val}\n'
                    break

        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        return jsonify({"success": True, "message": f"{section}.{key} updated"})
    except Exception as e:
        current_app.logger.error(f"[ADMIN] settings save failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# v1.9.5: SIEM Export endpoints
@admin_bp.route('/siem/export')
@require_auth
def siem_export():
    """Export detection records as SIEM-formatted events (JSON Lines / CEF)."""
    fmt = request.args.get('format', '')
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
        from anteumbra.infrastructure.suspicious_registry import get_all
        exporter = get_siem_exporter()
        if fmt:
            exporter._format = fmt
        records = get_all(include_deleted=False)
        count = exporter.export_existing(records)
        export_path = exporter._export_path
        return jsonify({
            "success": True,
            "exported": count,
            "format": exporter._format,
            "file": str(export_path),
            "size_bytes": export_path.stat().st_size if export_path.exists() else 0,
        })
    except Exception as e:
        current_app.logger.error(f"[ADMIN] SIEM export failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@admin_bp.route('/siem/stats')
@require_auth
def siem_stats():
    """Get SIEM exporter statistics."""
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
        return jsonify(get_siem_exporter().get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# v1.9.5: Settings panels — SIEM, Storage, Plugin status
@admin_bp.route('/settings/siem-status')
@require_auth
def settings_siem_status():
    """SIEM export status panel for Settings page."""
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
        e = get_siem_exporter()
        s = e.get_stats()
        from pathlib import Path
        export_path = Path(s["export_file"])
        has_data = export_path.exists() and export_path.stat().st_size > 0
        return render_template('admin/panels/siem_status.html',
            enabled=s["enabled"], format=s["format"],
            total_exported=s["total_exported"], file_size_mb=s["file_size_mb"],
            syslog_active=s["syslog_active"], has_data=has_data,
            export_file=str(export_path))
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'


@admin_bp.route('/settings/storage-status')
@require_auth
def settings_storage_status():
    """Storage backend status panel for Settings page."""
    try:
        from anteumbra.infrastructure.config.registry import ConfigRegistry
        cfg = ConfigRegistry.get_raw_config().get("storage", {})
        backend = cfg.get("backend", "json")
        db_path = cfg.get("db_path", "data/trident.db")
        from pathlib import Path
        db = Path(db_path)
        db_exists = db.exists()
        db_size = round(db.stat().st_size / 1024 / 1024, 2) if db_exists else 0
        json_size = 0
        json_files = list(Path("data").glob("*.json"))
        for f in json_files:
            if f.exists():
                json_size += f.stat().st_size
        json_mb = round(json_size / 1024 / 1024, 2)
        return render_template('admin/panels/storage_status.html',
            backend=backend, db_exists=db_exists, db_size=db_size,
            json_mb=json_mb, json_files=len(json_files))
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'


@admin_bp.route('/settings/plugin-status')
@require_auth
def settings_plugin_status():
    """Plugin system status panel for Settings page."""
    try:
        from anteumbra.application.plugin_manager import get_plugin_manager
        pm = get_plugin_manager()
        plugins = pm.list_all()
        detector_count = len(pm.detectors)
        notifier_count = len(pm.notifiers)
        source_count = len(pm.event_sources)
        return render_template('admin/panels/plugin_status.html',
            enabled=pm.is_enabled, plugins=plugins,
            detector_count=detector_count, notifier_count=notifier_count,
            source_count=source_count)
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'


@admin_bp.route('/dashboard_content')
@require_auth
def dashboard_content():
    """v1.7.9: 安全报告 Dashboard"""
    try:
        from anteumbra.infrastructure.suspicious_registry import get_all
        from anteumbra.infrastructure.quarantine import get_quarantine_stats

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
                file_name = r.get("file_path", "").split('\\')[-1].split("/")[-1]
            except:
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
        from anteumbra.infrastructure.monitoring.metrics import get_metrics
        metrics = get_metrics()

        # 安全获取指标，避免psutil异常
        try:
            metrics.record_memory_usage()
        except Exception as e:
            # Windows权限问题或psutil未安装
            metrics._stats["memory_mb"] = 0
            print(f"[WARNING][METRICS] 内存监控失败: {e}", file=sys.stderr)

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
        from anteumbra.infrastructure.monitoring.metrics import get_metrics
        m = get_metrics()
        data = m.get()
    except Exception:
        pass
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
        from anteumbra.infrastructure.monitoring.metrics import get_metrics
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
@admin_bp.route('/stream_logs')
def stream_logs():
    """v1.7.6终极修复：读取配置进行日志分级过滤（支持热加载）"""
    token = request.args.get('token')
    if not token:
        abort(403)

    client_ip = request.remote_addr

    # ========== 核心修复：连接数检查与清理（同步计数）==========
    # 获取配置化限制
    config = ConfigRegistry.get_raw_config()
    web_admin_cfg = config.get("web_admin", {})
    def _to_int(val, default=5):
        try:
            s = str(val).split('#')[0].strip()
            return int(s)
        except Exception:
            return default
    limits = {
        'per_ip': _to_int(web_admin_cfg.get("sse_max_clients_per_ip", 5)),
        'total': _to_int(web_admin_cfg.get("sse_max_total_clients", 20), 20)
    }

    # 精确统计该IP的活跃连接数
    ip_connections = [
        q for q in _sse_clients
        if getattr(q, '_client_ip', None) == client_ip
    ]
    ip_client_count = len(ip_connections)

    # 如果超限，强制清理该IP的所有旧连接（确保计数同步）
    if ip_client_count >= limits['per_ip']:
        for old_queue in ip_connections:
            unregister_sse_client(old_queue)  # 确保从列表移除
        logging.getLogger("monitor.admin_sse").info(
            f"[SSE] IP {client_ip} 清理了 {len(ip_connections)} 个旧连接"
        )
        ip_client_count = 0  # 清理后重置计数

    # 认证逻辑（保持不变）
    try:
        decoded = base64.b64decode(token).decode('utf-8')
        username, random_part = decoded.split(':', 1)
        expected_username, password_hash, allowed_ips = get_admin_credentials()
        if username != expected_username or client_ip not in allowed_ips:
            abort(403)
    except Exception as e:
        abort(403)

    logger = current_app.logger
    site_name = request.args.get('site')
    if not site_name:
        try:
            websites = ConfigRegistry.get_enabled_websites()
            site_name = websites[0].name if websites else "Website-PhpStudy"
        except:
            site_name = "Website-PhpStudy"

    log_file = normalize_path(f"logs/{site_name}/monitor.log")

    # v2.0: ?levels=all → Log Analyzer 全量日志; 默认 → 按配置过滤
    show_all_levels = request.args.get('levels', '') == 'all'

    # v1.7.6新增：读取日志级别配置（支持热加载）
    if not show_all_levels:
        try:
            config = ConfigRegistry.get_raw_config()
            web_admin_cfg = config.get("web_admin", {})
            allowed_levels = web_admin_cfg.get("sse_log_levels", ["INFO", "ERROR", "CRITICAL"])
            # 转换为集合用于快速查找（标准化为大写），默认排除 DEBUG
            allowed_levels_set = set(level.upper() for level in allowed_levels)
            allowed_levels_set.discard("DEBUG")
            logger.debug(f"[SSE] 允许日志级别: {allowed_levels_set}")
        except Exception as e:
            logger.warning(f"[SSE] 读取日志级别配置失败: {e}，使用默认值")
            allowed_levels_set = {"INFO", "WARNING", "ERROR", "CRITICAL"}
    else:
        allowed_levels_set = None  # None = no filtering, show all
        logger.info("[SSE][ANALYZER] 全量日志模式")

    def generate():
        """v1.7.6终极修复：日志分级过滤"""
        client_queue = None
        try:
            # ========== 核心修复：先注册队列，再创建生成器 ==========
            client_queue = register_sse_client()
            if not client_queue:
                yield "data: [SSE][ERROR] 客户端注册失败\n\n"
                return

            client_queue._client_ip = client_ip

            # ========== 核心修复：确保首次yield绝对纯净 ==========
            # 不调用任何logger，直接yield初始消息
            yield "data: [SSE] 连接到日志流...\n\n"

            # ========== 核心修复：Windows文件共享模式优化 ==========
            if sys.platform == "win32":
                # Windows：使用更兼容的打开模式
                f = open(log_file, 'r', encoding='utf-8', errors='ignore', buffering=1)
                # 确保文件指针在末尾
                try:
                    f.seek(0, 2)
                except:
                    pass  # 如果文件被轮转，忽略seek失败
            else:
                # Linux：标准模式
                f = open(log_file, 'r', encoding='utf-8', errors='ignore', buffering=1)
                f.seek(0, 2)

            yield "data: [SSE] 开始监控日志...\n\n"

            # ========== 核心修复：简单可靠的读取循环 ==========
            while True:
                # 检查Registry更新信号（高频，非阻塞）
                try:
                    signal = client_queue.get_nowait()
                    if signal == "registry_update":
                        yield f"data: [REGISTRY][UPDATE] 清单更新\n\n"
                        continue
                except queue.Empty:
                    pass
                except Exception:
                    break  # 队列异常，退出循环

                line = f.readline()
                if line:
                    # 日志分级过滤
                    log_line = line.strip()

                    if allowed_levels_set is not None:
                        # 提取日志级别（格式: [timestamp] LEVEL - message）
                        level_match = re.search(r'\] (\w+) -', log_line)
                        if level_match:
                            level = level_match.group(1).upper()
                            if level not in allowed_levels_set:
                                continue  # 跳过不允许的级别

                    # 避免SSE自我循环
                    if "[SSE]" in log_line:
                        continue

                    # 确保yield格式绝对正确
                    cleaned = log_line.replace('\n', ' ').replace('\r', ' ')
                    persist_log_line(cleaned)  # 持久化到磁盘
                    yield f"data: {cleaned}\n\n"
                else:
                    # 没有新内容，短暂休眠
                    time.sleep(0.1)  # 100ms，降低CPU

        except Exception as e:
            # 错误消息也要确保SSE格式
            error_msg = str(e).replace('\n', ' ')
            yield f"data: [SSE][ERROR] {error_msg}\n\n"
        finally:
            if client_queue:
                unregister_sse_client(client_queue)
                logger.debug(f"[SSE] client {client_ip} disconnected, {len(_sse_clients)} remaining")

    response = Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )
    return response




# ==================== 日志历史预加载（LIVE LOG STREAM初始化）====================
@admin_bp.route('/logs/history')
@require_auth
def logs_history():
    """返回最近1000条日志的HTML片段，用于LIVE LOG STREAM初始化
    v1.8.2: 优先读取 data/sse_log_buffer.json，回退到 monitor.log"""
    try:
        from anteumbra.infrastructure.utils.path_utils import normalize_path
        import json

        lines = []
        # 优先读取 SSE 日志缓冲区
        buffer_file = normalize_path("data/sse_log_buffer.json")
        if buffer_file.exists():
            try:
                with open(buffer_file, 'r', encoding='utf-8') as f:
                    buffer_data = json.load(f)
                if isinstance(buffer_data, list):
                    lines = buffer_data[-1000:]
            except Exception as e:
                current_app.logger.warning(f"[LOGS_HISTORY] 缓冲区读取失败: {e}")

        # 回退到 monitor.log
        if not lines:
            log_file = normalize_path("logs/Trident/monitor.log")
            if log_file.exists():
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(0, 2)
                    size = f.tell()
                    buf_size = min(size, 500 * 1024)
                    f.seek(max(0, size - buf_size))
                    chunk = f.read()
                    lines = chunk.splitlines()[-1000:]

        if not lines:
            return "<div class='log-line info'>[INFO] No log history found</div>"

        # 渲染为HTML
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

        return ''.join(html_parts) if html_parts else "<div class='log-line info'>[INFO] No recent logs</div>"
    except Exception as e:
        current_app.logger.error(f"[LOGS_HISTORY] 读取失败: {e}", exc_info=True)
        return f"<div class='log-line error'>[ERROR] Failed to load history: {str(e)[:50]}</div>"
@admin_bp.route('/test')
def test():
    return "SSE Test <script>alert('JS working');</script>"


@admin_bp.route('/debug/routes')
def debug_routes():
    """调试：查看所有已注册路由"""
    routes = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith('/admin'):
            routes.append(f"{rule.rule} → {rule.endpoint}")
    return jsonify(routes)


@admin_bp.route('/wal')
@require_auth
def wal_manager():
    """WAL管理页面"""
    return render_template('admin/wal_manager.html')


@admin_bp.route('/wal/current')
@require_auth
def wal_current():
    """返回当前WAL文件信息"""
    from core import wal_manager
    info = wal_manager.get_wal_info()
    if not info:
        return "<p style='color: #ff4444;'>WAL文件不存在</p>"
    size_mb = info['size_mb']
    return f"""
    <div style="background: #2a2a2a; padding: 10px; border-left: 4px solid #00ff00;">
        <strong>当前WAL:</strong> {info['name']}<br>
        <strong>大小:</strong> {size_mb:.2f} MB<br>
        <strong>路径:</strong> {info['path']}<br>
        <strong>状态:</strong> {'<span style="color: #00ff00;">正常写入</span>' if size_mb < 10 else '<span style="color: #ffaa00;">接近阈值</span>'}
    </div>
    """

@admin_bp.route('/wal/list')
@require_auth
def wal_list():
    """返回WAL归档列表"""
    from core import wal_manager
    archives = wal_manager.list_archives()
    if not archives:
        return "<p style='color: #888;'>暂无归档WAL文件</p>"
    html = ""
    for f in archives[:20]:  # 显示最近20个
        mtime_str = datetime.fromtimestamp(f['mtime']).strftime('%Y-%m-%d %H:%M:%S')
        html += f"""
        <div style="background: #1a1a1a; padding: 8px; margin: 5px 0; border-left: 4px solid #00ff00;">
            <strong>{f['name']}</strong> | 大小: {f['size_mb']:.2f}MB | 时间: {mtime_str}
        </div>
        """
    return html

@admin_bp.route('/wal/replay', methods=['POST'])
@require_auth
def wal_replay():
    """手动触发WAL重放"""
    try:
        from anteumbra.infrastructure.wal_manager import replay
        recovered = replay()
        log_with_symbol("notice", "info", f"手动WAL重放完成，恢复 {recovered} 条记录", current_app.logger)
        return jsonify({"success": True, "recovered": recovered})
    except Exception as e:
        current_app.logger.error(f"WAL重放失败: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route('/registry')
@require_auth
def registry_monitor():
    """Registry监控页面"""
    return render_template('admin/registry_monitor.html')


@admin_bp.route('/registry/count')
@require_auth
def registry_count():
    """返回Registry记录数"""
    from anteumbra.infrastructure.suspicious_registry import get_all
    total = len(get_all(include_deleted=True))
    active = len(get_all(include_deleted=False))
    return f"{active} / {total}"


@admin_bp.route('/registry/queue')
@require_auth
def registry_queue():
    """返回异步保存队列状态"""
    from anteumbra.infrastructure.suspicious_registry import _async_save_queue, _async_save_enabled
    if not _async_save_enabled:
        return "同步模式"
    try:
        size = _async_save_queue.qsize()
        return f"{size} 条待保存"
    except:
        return "队列未初始化"


@admin_bp.route('/registry/last-save')
@require_auth
def registry_last_save():
    """返回最后保存时间"""
    from anteumbra.infrastructure.suspicious_registry import _REGISTRY_PATH
    if _REGISTRY_PATH and _REGISTRY_PATH.exists():
        mtime = _REGISTRY_PATH.stat().st_mtime
        return datetime.fromtimestamp(mtime).strftime('%H:%M:%S')
    return "从未保存"


@admin_bp.route('/registry/compact', methods=['POST'])
@require_auth
def registry_compact():
    """手动触发Registry压缩"""
    try:
        from anteumbra.infrastructure.suspicious_registry import compact_registry
        compact_registry()
        log_with_symbol("notice", "info", "手动Registry压缩完成", current_app.logger)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route('/session')
@require_auth
def session_manager():
    """Session管理页面"""
    return render_template('admin/session_manager.html')


@admin_bp.route('/session/list')
@require_auth
def session_list():
    """返回Session列表（支持分页，0硬编码）"""
    from flask_session import Session
    session_dir = current_app.config.get('SESSION_FILE_DIR')
    if not session_dir:
        return "<p style='color: #888;'>Session存储未配置</p>"
    session_path = Path(session_dir)
    if not session_path.exists():
        return "<p style='color: #888;'>暂无Session文件</p>"

    # 分页参数
    page = max(1, request.args.get('page', 1, type=int))
    config = ConfigRegistry.get_raw_config()
    per_page = config.get("web_admin", {}).get("session_items_per_page", 20)

    sessions = []
    for sess_file in session_path.iterdir():
        if sess_file.is_dir():
            continue
        filename = sess_file.name
        is_session = re.match(r'^[a-f0-9]{32}$', filename, re.IGNORECASE)
        if not is_session:
            continue
        stat = sess_file.stat()
        sessions.append({
            'name': filename,
            'size_kb': round(stat.st_size / 1024, 2),
            'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        })

    if not sessions:
        return "<p style='color: #888;'>暂无活跃Session</p>"

    total = len(sessions)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = sessions[start:end]

    html = ""
    for s in paginated:
        html += f"""
        <div style="background: #1a1a1a; padding: 8px; margin: 5px 0; border-left: 4px solid #00ff00;">
            <strong>{s['name']}</strong> | 大小: {s['size_kb']:.2f}KB | 最后访问: {s['mtime']}
        </div>
        """

    # 分页控件
    if total_pages > 1:
        prev_disabled = "disabled" if page <= 1 else ""
        next_disabled = "disabled" if page >= total_pages else ""
        html += f'<div class="pagination-bar" style="margin-top: 10px;">'
        html += f'<button class="btn btn-ghost btn-sm" {prev_disabled} hx-get="/admin/session/list?page={page - 1}" hx-target="#session-list" hx-swap="innerHTML">← Prev</button>'
        html += f'<span class="page-info">Page {page} / {total_pages} ({total} total)</span>'
        html += f'<div class="page-jump"><input type="number" class="form-input" style="width: 60px; text-align: center;" min="1" max="{total_pages}" value="{page}" onkeydown="if(event.key===\"Enter\"){{var p=this.value;htmx.ajax(\"GET\",\"/admin/session/list?page=\"+p,{{target:\"#session-list",swap:\"innerHTML"}})}}"></div>'
        html += f'<button class="btn btn-ghost btn-sm" {next_disabled} hx-get="/admin/session/list?page={page + 1}" hx-target="#session-list" hx-swap="innerHTML">Next →</button>'
        html += '</div>'
    return html


@admin_bp.route('/session/cleanup', methods=['POST'])
@require_auth
def session_cleanup():
    """清理过期Session"""
    try:
        from tools.cleanup_sessions import cleanup_sessions
        deleted = cleanup_sessions(days=7)
        log_with_symbol("notice", "info", f"清理过期Session: {deleted}个", current_app.logger)
        return jsonify({"success": True, "deleted": deleted})
    except Exception as e:
        current_app.logger.error(f"Session清理失败: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route('/config')
@require_auth
def config_watcher_status():
    """配置监控页面"""
    return render_template('admin/config_watcher.html')


@admin_bp.route('/config/history')
@require_auth
def config_history():
    """返回配置加载历史（从日志提取 + 分页，0硬编码）"""
    from anteumbra.infrastructure.utils.path_utils import normalize_path
    log_file = normalize_path("logs/Trident/system.log")
    if not log_file.exists():
        return "<p style='color: #888;'>暂无配置加载历史</p>"

    # 分页参数
    page = max(1, request.args.get('page', 1, type=int))
    config = ConfigRegistry.get_raw_config()
    per_page = config.get("web_admin", {}).get("config_items_per_page", 10)

    history = []
    try:
        for line in log_file.read_text(encoding='utf-8').splitlines():
            if '[CONFIG][RELOAD]' in line or '[CONFIG][START]' in line:
                history.append(line)
    except:
        pass

    if not history:
        return "<p style='color: #888;'>暂无配置加载记录</p>"

    total = len(history)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = history[start:end]

    html = ""
    for h in paginated:
        html += f"<div style='background: #1a1a1a; padding: 5px; margin: 3px 0; font-size: 11px;'>{h}</div>"

    # 分页控件
    if total_pages > 1:
        prev_disabled = "disabled" if page <= 1 else ""
        next_disabled = "disabled" if page >= total_pages else ""
        html += f'<div class="pagination-bar" style="margin-top: 10px;">'
        html += f'<button class="btn btn-ghost btn-sm" {prev_disabled} hx-get="/admin/config/history?page={page - 1}" hx-target="#config-history" hx-swap="innerHTML">← Prev</button>'
        html += f'<span class="page-info">Page {page} / {total_pages} ({total} total)</span>'
        html += f'<div class="page-jump"><input type="number" class="form-input" style="width: 60px; text-align: center;" min="1" max="{total_pages}" value="{page}" onkeydown="if(event.key===\"Enter\"){{var p=this.value;htmx.ajax(\"GET\",\"/admin/config/history?page=\"+p,{{target:\"#config-history",swap:\"innerHTML"}})}}"></div>'
        html += f'<button class="btn btn-ghost btn-sm" {next_disabled} hx-get="/admin/config/history?page={page + 1}" hx-target="#config-history" hx-swap="innerHTML">Next →</button>'
        html += '</div>'
    return html


@admin_bp.route('/config/signature')
@require_auth
def config_signature():
    """返回当前配置签名（MD5）"""
    from anteumbra.infrastructure.config.registry import ConfigRegistry
    import hashlib
    try:
        config_data = json.dumps(ConfigRegistry.get_raw_config(), sort_keys=True)
        md5 = hashlib.md5(config_data.encode()).hexdigest()[:8]
        return f"config.toml [{md5}]"
    except:
        return "无法计算签名"


@admin_bp.app_template_filter('to_hash')
def to_hash(value):
    import hashlib
    return hashlib.md5(value.encode()).hexdigest()[:8]


# 系统管理四象限路由
@admin_bp.route('/system')
@require_auth
def system_management():
    """系统管理四象限主页面 - v1.7.6-Patch27: 传递session_count"""
    try:
        auth_header = session.get('sse_token')
        if not auth_header:
            username = session.get('username', 'admin')
            auth_str = f"{username}:session_fallback"
            auth_bytes = auth_str.encode('utf-8')
            auth_header = base64.b64encode(auth_bytes).decode('utf-8')
            session['sse_token'] = auth_header

        # 获取Session数量
        session_count = 0
        try:
            session_dir = current_app.config.get('SESSION_FILE_DIR')
            if session_dir:
                session_path = Path(session_dir)
                if session_path.exists():
                    sessions = list(session_path.glob("*.sess"))
                    session_count = len(sessions)
        except:
            pass

        return render_template(
            'admin/system_management.html',
            auth_header=auth_header,
            username=session.get('username'),
            client_ip=request.remote_addr,
            session_count=session_count  # 传递Session数量
        )
    except Exception as e:
        current_app.logger.error(f"[SYSTEM] 渲染失败: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@admin_bp.route('/system/registry_panel')
@require_auth
def system_registry_panel():
    """Registry状态监控数据（独立刷新，移除队列积压显示）"""
    try:
        from anteumbra.infrastructure.suspicious_registry import _REGISTRY_PATH, get_all
        from anteumbra.infrastructure.monitoring.metrics import get_metrics
        from core import wal_manager

        # 加载所有数据
        all_records = get_all(include_deleted=True)
        active_records = get_all(include_deleted=False)

        # 计算WAL大小
        wal_info = wal_manager.get_wal_info()
        wal_size_mb = wal_info['size_mb'] if wal_info else 0.0

        # 队列状态（简化显示）
        queue_status = "同步模式"
        if hasattr(core.suspicious_registry, '_async_save_enabled') and core.suspicious_registry._async_save_enabled:
            try:
                from anteumbra.infrastructure.suspicious_registry import _async_save_queue
                if _async_save_queue:
                    queue_status = f"异步模式"
            except:
                pass

        # 最后保存时间
        last_save = "从未保存"
        if _REGISTRY_PATH and _REGISTRY_PATH.exists():
            mtime = _REGISTRY_PATH.stat().st_mtime
            last_save = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

        return render_template(
            'admin/panels/registry_panel.html',
            registry_data=all_records,  # 传递原始数据给模板
            total_records=len(all_records),
            active_records=len(active_records),
            queue_status=queue_status,
            last_save=last_save,
            wal_size_mb=wal_size_mb,
            wal_status='normal' if wal_size_mb < 10 else 'warning'
        )
    except Exception as e:
        current_app.logger.error(f"[REGISTRY_PANEL] 加载失败: {e}", exc_info=True)
        return f'<div style="color: #ff4444; padding: 20px;">加载失败: {str(e)}</div>', 500

@admin_bp.route('/system/wal_panel')
@require_auth
def system_wal_panel():
    """WAL管理数据（v1.7.6-Patch4：修复持续500错误 + 滚动显示问题）"""
    try:
        # v1.8.4: 使用 wal_manager 高内聚封装
        from core import wal_manager

        wal_info = wal_manager.get_wal_info()
        archives = wal_manager.list_archives()

        wal_status, wal_status_text, wal_size_mb = wal_manager.get_status_text()

        current_wal = None
        if wal_info:
            current_wal = {
                'name': wal_info['name'],
                'size_mb': wal_info['size_mb'],
                'path': wal_info['path']
            }

        return render_template(
            'admin/panels/wal_panel.html',
            current_wal=current_wal,
            files=archives[:20],
            wal_status=wal_status,
            wal_status_text=wal_status_text,
            wal_size_mb=wal_size_mb,
            error=None
        )

    except Exception as e:
        # 终极防线：捕获所有未预料的异常
        current_app.logger.critical(f"[WAL_PANEL] 致命错误: {e}", exc_info=True)
        return render_template(
            'admin/panels/wal_panel.html',
            current_wal=None,
            files=[],  # 空列表避免模板渲染错误
            wal_status='error',
            wal_status_text='系统错误',
            wal_size_mb=0.0,
            error=f"系统异常: {str(e)[:30]}..."
        ), 500

@admin_bp.route('/system/session_panel')
@require_auth
def system_session_panel():
    """Session管理数据（增强版：状态计算 + 颜色标识 + 分页）"""
    try:
        session_dir = current_app.config.get('SESSION_FILE_DIR')
        if not session_dir:
            return render_template(
                'admin/panels/session_panel.html',
                sessions=[],
                session_count=0,
                active_count=0,
                page=1, total_pages=1,
                error="Session存储未配置"
            )

        session_path = Path(session_dir)
        if not session_path.exists():
            return render_template(
                'admin/panels/session_panel.html',
                sessions=[],
                session_count=0,
                active_count=0,
                page=1, total_pages=1,
                error="Session目录不存在"
            )

        # 分页参数（从配置读取，0硬编码）
        page = max(1, request.args.get('page', 1, type=int))
        config = ConfigRegistry.get_raw_config()
        per_page = config.get("web_admin", {}).get("session_items_per_page", 20)

        # 获取当前时间
        now = datetime.now()
        all_sessions = []

        for sess_file in session_path.iterdir():
            if sess_file.is_dir():
                continue

            filename = sess_file.name
            is_session = re.match(r'^[a-f0-9]{32}$', filename, re.IGNORECASE)
            if not is_session:
                continue

            try:
                stat = sess_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime)
                age_days = (now - mtime).days
                state = "active" if age_days < 30 else "inactive"

                all_sessions.append({
                    'name': filename,
                    'size_kb': round(stat.st_size / 1024, 2),
                    'mtime': mtime.strftime('%Y-%m-%d %H:%M:%S'),
                    'age_days': age_days,
                    'state': state
                })
            except Exception as e:
                current_app.logger.debug(f"跳过文件 {sess_file}: {e}")
                continue

        # 按修改时间倒序
        all_sessions.sort(key=lambda x: x['mtime'], reverse=True)

        active_count = sum(1 for s in all_sessions if s['state'] == 'active')
        total = len(all_sessions)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)

        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_sessions[start:end]

        return render_template(
            'admin/panels/session_panel.html',
            sessions=paginated,
            session_count=total,
            active_count=active_count,
            page=page,
            total_pages=total_pages,
            error=None
        )
    except Exception as e:
        current_app.logger.error(f"[SESSION_PANEL] 加载失败: {e}", exc_info=True)
        return render_template(
            'admin/panels/session_panel.html',
            sessions=[],
            session_count=0,
            active_count=0,
            page=1, total_pages=1,
            error=f"加载失败: {str(e)}"
        )


# 第四象限：配置热加载监控面板
@admin_bp.route('/system/config_panel')
@require_auth
def system_config_panel():
    """配置热加载监控数据（从持久化文件读取 + 分页）"""
    try:
        import hashlib
        config = ConfigRegistry.get_raw_config()
        config_data = json.dumps(config, sort_keys=True)
        config_signature = hashlib.md5(config_data.encode()).hexdigest()[:8]

        # 分页参数（从配置读取，0硬编码）
        page = max(1, request.args.get('page', 1, type=int))
        per_page = config.get("web_admin", {}).get("config_items_per_page", 10)

        from tools.config_watcher_logger import get_config_watcher_logger
        history_logger = get_config_watcher_logger()
        raw_history = history_logger.get_history(limit=1000)  # 读取大量数据再分页
        formatted_history = []
        for record in raw_history:
            item = f"[{record['timestamp_display']}] 热加载完成"
            if record['changed_keys']:
                changes = ', '.join(record['changed_keys'][:5])
                item += f" | 变更: {changes}"
            if record['duration_ms']:
                item += f" | 耗时: {record['duration_ms']}ms"
            formatted_history.append(item)

        total = len(formatted_history)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)

        start = (page - 1) * per_page
        end = start + per_page
        paginated_history = formatted_history[start:end]

        from anteumbra.infrastructure.detection.yara_engine import get_yara_engine
        engine = get_yara_engine(current_app.logger)
        rule_stats = engine.get_rule_stats() if hasattr(engine, 'get_rule_stats') else {}
        return render_template(
            'admin/panels/config_panel.html',
            config_signature=config_signature,
            config_path=str(ConfigRegistry._config_path),
            history=paginated_history,
            page=page,
            total_pages=total_pages,
            total=total,
            rule_stats=rule_stats,
            yara_enabled=len(rule_stats) > 0
        )
    except Exception as e:
        current_app.logger.error(f"[CONFIG_PANEL] 加载失败: {e}", exc_info=True)
        return f'<div style="color: #ff4444; padding: 20px;">加载失败: {str(e)}</div>', 500


# ==================== 新增：操作型接口（返回HTML片段而非JSON） ====================

@admin_bp.route('/system/registry/compact', methods=['POST'])
@require_auth
def system_registry_compact():
    """手动压缩Registry（增强反馈）"""
    try:
        if hasattr(current_app, '_registry_compacting'):
            return render_template(
                'admin/panels/registry_panel.html',
                error="压缩操作正在进行中，请稍后再试"
            )

        current_app._registry_compacting = True

        # 执行压缩并获取结果
        from anteumbra.infrastructure.suspicious_registry import compact_registry
        result = compact_registry()

        delattr(current_app, '_registry_compacting')

        # v1.7.6-Patch30: 重新加载数据并传递操作结果
        from anteumbra.infrastructure.suspicious_registry import _REGISTRY_PATH, get_all

        all_records = get_all(include_deleted=True)
        active_records = get_all(include_deleted=False)

        # 计算WAL大小
        from core import wal_manager
        wal_info = wal_manager.get_wal_info()
        wal_size_mb = wal_info['size_mb'] if wal_info else 0.0

        # 队列状态
        queue_status = "同步模式"
        if hasattr(core.suspicious_registry, '_async_save_enabled') and core.suspicious_registry._async_save_enabled:
            try:
                from anteumbra.infrastructure.suspicious_registry import _async_save_queue
                if _async_save_queue:
                    queue_status = f"异步模式"
            except:
                pass

        # 最后保存时间
        last_save = "从未保存"
        if _REGISTRY_PATH and _REGISTRY_PATH.exists():
            mtime = _REGISTRY_PATH.stat().st_mtime
            last_save = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

        # 构建操作结果消息
        message = None
        message_type = None
        if isinstance(result, dict):
            if "error" in result:
                message = f"压缩失败: {result['error']}"
                message_type = "error"
            else:
                if result['cleaned'] > 0:
                    message = f"Registry压缩完成，清理 {result['cleaned']} 条过期记录"
                    message_type = "success"
                else:
                    message = f"Registry压缩完成，扫描 {result['total']} 条记录，无过期记录需要清理（阈值: 30天）"
                    message_type = "success"

        log_with_symbol("notice", "info", "Registry压缩操作完成", current_app.logger)

        return render_template(
            'admin/panels/registry_panel.html',
            registry_data=all_records,
            total_records=len(all_records),
            active_records=len(active_records),
            queue_status=queue_status,
            last_save=last_save,
            wal_size_mb=wal_size_mb,
            wal_status='normal' if wal_size_mb < 10 else 'warning',
            message=message,
            message_type=message_type
        )

    except Exception as e:
        current_app.logger.error(f"[COMPACT] 失败: {e}", exc_info=True)
        return render_template(
            'admin/panels/registry_panel.html',
            error=f"压缩失败: {str(e)}",
            message_type="error"
        )

@admin_bp.route('/system/wal/replay', methods=['POST'])
@require_auth
def system_wal_replay():
    """手动触发WAL重放（返回渲染后的面板HTML）- v1.8.5: 使用 wal_manager"""
    try:
        from anteumbra.infrastructure.wal_manager import replay
        recovered = replay()

        # 重新加载数据并渲染面板
        from core import wal_manager

        wal_status, wal_status_text, wal_size_mb = wal_manager.get_status_text()
        wal_info = wal_manager.get_wal_info()
        archives = wal_manager.list_archives()

        current_wal = None
        if wal_info:
            current_wal = {
                'name': wal_info['name'],
                'size_mb': wal_info['size_mb'],
                'path': wal_info['path']
            }

        log_with_symbol("notice", "info", f"WAL重放完成，恢复 {recovered} 条记录", current_app.logger)

        return render_template(
            'admin/panels/wal_panel.html',
            current_wal=current_wal,
            files=archives[:10],
            wal_status=wal_status,
            wal_status_text=wal_status_text,
            wal_size_mb=wal_size_mb,
            message=f"WAL重放完成，恢复 {recovered} 条记录",
            operation_message=f"WAL重放完成，恢复 {recovered} 条记录",
            message_type="success",
        )

    except Exception as e:
        current_app.logger.error(f"[WAL_REPLAY] 失败: {e}", exc_info=True)
        return render_template(
            'admin/panels/wal_panel.html',
            operation_message=f"WAL重放失败: {str(e)}",
            error=f"WAL重放失败: {str(e)}",
            message_type="error"
        )


@admin_bp.route('/system/session/cleanup', methods=['POST'])
@require_auth
def system_session_cleanup():
    """清理过期Session（返回渲染后的面板HTML + 分页）"""
    try:
        from tools.cleanup_sessions import cleanup_sessions
        deleted = cleanup_sessions(days=7)

        # 重新加载Session数据
        session_dir = current_app.config.get('SESSION_FILE_DIR')
        all_sessions = []

        if session_dir:
            session_path = Path(session_dir)
            if session_path.exists():
                now = datetime.now()
                for sess_file in session_path.iterdir():
                    if sess_file.is_dir():
                        continue
                    filename = sess_file.name
                    is_session = re.match(r'^[a-f0-9]{32}$', filename, re.IGNORECASE)
                    if not is_session:
                        continue
                    try:
                        stat = sess_file.stat()
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        age_days = (now - mtime).days
                        state = "active" if age_days < 30 else "inactive"
                        all_sessions.append({
                            'name': filename,
                            'size_kb': round(stat.st_size / 1024, 2),
                            'mtime': mtime.strftime('%Y-%m-%d %H:%M:%S'),
                            'age_days': age_days,
                            'state': state
                        })
                    except:
                        continue
                all_sessions.sort(key=lambda x: x['mtime'], reverse=True)

        # 分页计算（0硬编码，从配置读取）
        page = 1
        config = ConfigRegistry.get_raw_config()
        per_page = config.get("web_admin", {}).get("session_items_per_page", 20)
        total = len(all_sessions)
        total_pages = max(1, (total + per_page - 1) // per_page)
        active_count = sum(1 for s in all_sessions if s['state'] == 'active')
        paginated = all_sessions[:per_page]

        log_with_symbol("notice", "info", f"清理过期Session: {deleted}个", current_app.logger)

        return render_template(
            'admin/panels/session_panel.html',
            sessions=paginated,
            session_count=total,
            active_count=active_count,
            page=page,
            total_pages=total_pages,
            error=None,
            message=f"清理完成，删除 {deleted} 个过期Session",
            message_type="success"
        )

    except Exception as e:
        current_app.logger.error(f"[SESSION_CLEANUP] 失败: {e}", exc_info=True)
        return render_template(
            'admin/panels/session_panel.html',
            sessions=[],
            session_count=0,
            active_count=0,
            page=1,
            total_pages=1,
            error=f"清理失败: {str(e)}",
            message_type="error"
        )


@admin_bp.route('/system/config/reload', methods=['POST'])
@require_auth
def system_config_reload():
    """手动触发配置热加载（返回渲染后的面板HTML）"""
    try:
        from core.config_watcher import ConfigReloadHandler
        handler = ConfigReloadHandler(ConfigRegistry, current_app.logger)
        handler.on_modified(type('Event', (), {'src_path': ConfigRegistry._config_path})())

        # 重新加载配置数据
        import hashlib
        config_data = json.dumps(ConfigRegistry.get_raw_config(), sort_keys=True)
        config_signature = hashlib.md5(config_data.encode()).hexdigest()[:8]

        from tools.config_watcher_logger import get_config_watcher_logger
        history_logger = get_config_watcher_logger()
        raw_history = history_logger.get_history(limit=10)
        formatted_history = []
        for record in raw_history:
            item = f"[{record['timestamp_display']}] 热加载完成"
            if record['changed_keys']:
                changes = ', '.join(record['changed_keys'][:5])
                item += f" | 变更: {changes}"
            if record['duration_ms']:
                item += f" | 耗时: {record['duration_ms']}ms"
            formatted_history.append(item)

        from anteumbra.infrastructure.detection.yara_engine import get_yara_engine
        engine = get_yara_engine(current_app.logger)
        rule_stats = engine.get_rule_stats() if hasattr(engine, 'get_rule_stats') else {}

        log_with_symbol("notice", "info", "配置热加载已触发", current_app.logger)

        return render_template(
            'admin/panels/config_panel.html',
            config_signature=config_signature,
            config_path=str(ConfigRegistry._config_path),
            history=formatted_history,
            rule_stats=rule_stats,
            yara_enabled=len(rule_stats) > 0,
            message="配置热加载已触发",
            message_type="success"
        )

    except Exception as e:
        current_app.logger.error(f"[CONFIG_RELOAD] 失败: {e}", exc_info=True)
        return render_template(
            'admin/panels/config_panel.html',
            error=f"热加载失败: {str(e)}",
            message_type="error"
        )


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

@admin_bp.route('/sse/history', methods=['GET'])
@require_auth
def sse_history():
    """返回持久化的历史日志"""
    try:
        from anteumbra.infrastructure.utils.sse_manager import get_log_buffer

        config = ConfigRegistry.get_raw_config()
        web_admin_cfg = config.get("web_admin", {})
        allowed_levels = web_admin_cfg.get("sse_log_levels", ["INFO", "ERROR", "CRITICAL"])

        buffer_logs = get_log_buffer()

        # 级别过滤
        filtered = []
        for log_line in buffer_logs:
            level_match = re.search(r'\] (\w+) -', log_line)
            if level_match:
                level = level_match.group(1).upper()
                if level in allowed_levels:
                    filtered.append(log_line)

        return jsonify({
            "success": True,
            "logs": filtered
        })

    except Exception as e:
        import traceback
        return jsonify({
            "success": False,
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500


@admin_bp.route('/registry/wal-status')
@require_auth
def registry_wal_status():
    """返回WAL回放状态HTML片段"""
    try:
        from anteumbra.infrastructure.wal_manager import is_replaying
        replaying = is_replaying()
        status = "Replaying" if replaying else "Idle"
        color = "var(--color-warning)" if replaying else "var(--color-text-secondary)"
        return f'<div class="metric-value" style="color:{color};font-size:14px;">{status}</div>'
    except Exception as e:
        current_app.logger.error(f"[ADMIN] registry_wal_status error: {e}")
        return '<div class="metric-value" style="color:var(--color-danger)">N/A</div>'


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
        from anteumbra.infrastructure.config.loader import load_toml_config
        load_toml_config()
    except Exception:
        status["status"] = "degraded"

    try:
        from core import wal_manager
        wal_manager.get_wal_info()
    except Exception:
        status["status"] = "degraded"

    http_code = 200 if status["status"] == "healthy" else 503
    return jsonify(status), http_code


@admin_bp.route('/admin/health', methods=['GET'])
def admin_health():
    """Authenticated health check with full diagnostics.

    Requires login. Returns version, component status, and detailed checks.
    """
    """Health check endpoint for Docker HEALTHCHECK and monitoring systems."""
    from anteumbra.infrastructure.config.version import get_version
    from anteumbra.infrastructure.config.loader import load_toml_config as load_config
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
        from core import wal_manager
        wal_manager.get_wal_info()
        status['checks']['wal'] = 'ok'
    except Exception as e:
        status['checks']['wal'] = f'error: {str(e)}'
        status['status'] = 'degraded'

    # Check registry module (function-based, no class)
    try:
        from core import suspicious_registry
        suspicious_registry.get_all(include_deleted=False)
        status['checks']['registry'] = 'ok'
    except Exception as e:
        status['checks']['registry'] = f'error: {str(e)}'
        status['status'] = 'degraded'

    # Check YARA engine
    try:
        from anteumbra.infrastructure.detection.yara_engine import get_yara_engine
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

MAX_VIEW_SIZE = 512 * 1024  # 512KB 上限


def _verify_file_in_registry(file_path: str) -> bool:
    """验证文件是否在 Registry 中（白名单）"""
    try:
        from anteumbra.infrastructure.suspicious_registry import get_all
        from anteumbra.infrastructure.utils.path_utils import path_to_key
        target = path_to_key(file_path)
        for record in get_all(include_deleted=True):
            if record.get("file_path") == target:
                return True
        return False
    except Exception:
        return False


def _verify_file_in_quarantine(qid: str) -> Optional[Path]:
    """验证 quarantine_id 是否在隔离库中，返回隔离路径或 None"""
    try:
        from anteumbra.infrastructure.quarantine import get_quarantine_detail
        record = get_quarantine_detail(qid)
        if record:
            qpath = record.get("quarantine_path", "")
            if qpath and Path(qpath).exists():
                return Path(qpath)
        return None
    except Exception:
        return None


# v1.0.5: _html_escape removed — use _shared.html_escape (markupsafe.escape) instead
