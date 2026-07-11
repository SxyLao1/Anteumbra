# -*- coding: utf-8 -*-
"""
v1.0.6: Monitor Blueprint — extracted from admin_bp.py
Routes: /stream_logs, /logs/*, /wal/*, /registry/*, /session/*, /sse/*, /config/*
"""
import base64
import hmac
import json
import logging
import queue
import re
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, render_template, request, jsonify, abort,
    Response, current_app, stream_with_context, session,
)

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.application.registry_service import (
    get_all, compact_registry,
    get_registry_path, is_async_save_enabled, get_async_save_queue_size,
)
from anteumbra.application.logging_service import log_with_symbol
from anteumbra.application.session_service import cleanup_sessions
from anteumbra.infrastructure.utils.path_utils import normalize_path
from anteumbra.application.sse_service import (
    register_sse_client, unregister_sse_client, get_connected_client_count,
    get_ip_client_count, get_ip_clients, persist_log_line,
)
from anteumbra.interfaces.web.auth import require_auth, get_admin_credentials

logger = logging.getLogger(__name__)

monitor_bp = Blueprint('monitor', __name__, url_prefix='/admin')


# -- SSE Live Log Stream --

@monitor_bp.route('/stream_logs')
def stream_logs():
    """v1.7.6: SSE log stream with level filtering (config-driven, hot-reloadable)"""
    token = request.args.get('token')
    if not token:
        abort(403)

    client_ip = request.remote_addr

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

    ip_client_count = get_ip_client_count(client_ip)
    ip_connections = get_ip_clients(client_ip)

    if ip_client_count >= limits['per_ip']:
        for old_queue in ip_connections:
            unregister_sse_client(old_queue)
        logging.getLogger("monitor.admin_sse").info(
            f"[SSE] IP {client_ip} cleaned {len(ip_connections)} old connections"
        )
        ip_client_count = 0

    session_token = session.get('sse_token')
    if not session.get('authenticated') or not session_token:
        abort(403)
    if not hmac.compare_digest(str(token), str(session_token)):
        abort(403)

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
            site_name = websites[0].name if websites else "Default Website"
        except Exception:
            site_name = "Default Website"

    log_file = normalize_path(f"logs/{site_name}/monitor.log")
    show_all_levels = request.args.get('levels', '') == 'all'

    if not show_all_levels:
        try:
            config = ConfigRegistry.get_raw_config()
            web_admin_cfg = config.get("web_admin", {})
            allowed_levels = web_admin_cfg.get("sse_log_levels", ["INFO", "ERROR", "CRITICAL"])
            allowed_levels_set = set(level.upper() for level in allowed_levels)
            allowed_levels_set.discard("DEBUG")
        except Exception as e:
            logger.warning(f"[SSE] Failed to read log level config: {e}, using defaults")
            allowed_levels_set = {"INFO", "WARNING", "ERROR", "CRITICAL"}
    else:
        allowed_levels_set = None
        logger.info("[SSE][ANALYZER] Full log mode")

    def generate():
        client_queue = None
        try:
            client_queue = register_sse_client()
            if not client_queue:
                yield "data: [SSE][ERROR] Client registration failed\n\n"
                return

            client_queue._client_ip = client_ip
            # v1.0.10: 确保日志文件存在（首次运行 / 新网站尚无 monitor.log）
            log_file.parent.mkdir(parents=True, exist_ok=True)
            if not log_file.exists():
                log_file.touch()
                logger.info(f"[SSE] Log file created: {log_file}")

            if sys.platform == "win32":
                f = open(log_file, 'r', encoding='utf-8', errors='ignore', buffering=1)
                try:
                    f.seek(0, 2)
                except Exception:
                    logger.debug("Failed to seek to end of log file in SSE stream", exc_info=True)
            else:
                f = open(log_file, 'r', encoding='utf-8', errors='ignore', buffering=1)
                f.seek(0, 2)

            while True:
                try:
                    signal = client_queue.get_nowait()
                    if signal == "registry_update":
                        yield "data: [REGISTRY][UPDATE] Registry updated\n\n"
                        continue
                except queue.Empty:
                    pass
                except Exception:
                    break

                line = f.readline()
                if line:
                    log_line = line.strip()
                    if allowed_levels_set is not None:
                        level_match = re.search(r'\] (\w+) -', log_line)
                        if level_match:
                            level = level_match.group(1).upper()
                            if level not in allowed_levels_set:
                                continue
                    if "[SSE]" in log_line:
                        continue
                    cleaned = log_line.replace('\n', ' ').replace('\r', ' ')
                    persist_log_line(cleaned)
                    yield f"data: {cleaned}\n\n"
                else:
                    time.sleep(0.1)

        except Exception as e:
            error_msg = str(e).replace('\n', ' ')
            yield f"data: [SSE][ERROR] {error_msg}\n\n"
        finally:
            if client_queue:
                unregister_sse_client(client_queue)
                remaining = get_connected_client_count()
                logger.debug(f"[SSE] client {client_ip} disconnected, {remaining} remaining")

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


# -- Log History --

@monitor_bp.route('/logs/history')
@require_auth
def logs_history():
    """Return last 1000 log lines as HTML fragment for LIVE LOG STREAM init.
    v1.8.2: prefer data/sse_log_buffer.json, fallback to monitor.log"""
    try:
        lines = []
        buffer_file = normalize_path("data/sse_log_buffer.json")
        if buffer_file.exists():
            try:
                with open(buffer_file, 'r', encoding='utf-8') as f:
                    buffer_data = json.load(f)
                if isinstance(buffer_data, list):
                    lines = buffer_data[-1000:]
            except Exception as e:
                current_app.logger.warning(f"[LOGS_HISTORY] Buffer read failed: {e}")

        if not lines:
            log_candidates = []
            try:
                websites = ConfigRegistry.get_enabled_websites()
                for website in websites:
                    log_candidates.append(normalize_path(f"logs/{website.name}/monitor.log"))
            except Exception:
                current_app.logger.debug("Failed to resolve website log candidates", exc_info=True)
            log_candidates.extend([
                normalize_path("logs/Default Website/monitor.log"),
                normalize_path("logs/Website-PhpStudy/monitor.log"),
                normalize_path("logs/Anteumbra/monitor.log"),
            ])

            seen = set()
            for log_file in log_candidates:
                key = str(log_file)
                if key in seen or not log_file.exists():
                    continue
                seen.add(key)
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(0, 2)
                    size = f.tell()
                    buf_size = min(size, 500 * 1024)
                    f.seek(max(0, size - buf_size))
                    chunk = f.read()
                    lines = chunk.splitlines()[-1000:]
                if lines:
                    break

        if not lines:
            return "<div class='log-line info'>[INFO] No log history found</div>"

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
            if line.startswith('[SSE]'):
                continue
            safe_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(f'<div class="log-line {log_class}">{safe_line}</div>')

        return ''.join(html_parts) if html_parts else "<div class='log-line info'>[INFO] No recent logs</div>"
    except Exception as e:
        current_app.logger.error(f"[LOGS_HISTORY] Read failed: {e}", exc_info=True)
        return f"<div class='log-line error'>[ERROR] Failed to load history: {str(e)[:50]}</div>"


# -- WAL Management --

@monitor_bp.route('/wal')
@require_auth
def wal_manager():
    """WAL management page"""
    return render_template('admin/wal_manager.html')


@monitor_bp.route('/wal/current')
@require_auth
def wal_current():
    """Return current WAL file info"""
    from anteumbra.application.wal_service import get_wal_info
    info = get_wal_info()
    if not info:
        return "<p style='color: #ff4444;'>WAL file not found</p>"
    size_mb = info['size_mb']
    return f"""
    <div style="background: #2a2a2a; padding: 10px; border-left: 4px solid #00ff00;">
        <strong>Current WAL:</strong> {info['name']}<br>
        <strong>Size:</strong> {size_mb:.2f} MB<br>
        <strong>Path:</strong> {info['path']}<br>
        <strong>Status:</strong> {'<span style="color: #00ff00;">Normal</span>' if size_mb < 10 else '<span style="color: #ffaa00;">Near threshold</span>'}
    </div>
    """


@monitor_bp.route('/wal/list')
@require_auth
def wal_list():
    """Return WAL archive list"""
    from anteumbra.application.wal_service import list_archives
    archives = list_archives()
    if not archives:
        return "<p style='color: #888;'>No archived WAL files</p>"
    html = ""
    for f in archives[:20]:
        mtime_str = datetime.fromtimestamp(f['mtime']).strftime('%Y-%m-%d %H:%M:%S')
        html += f"""
        <div style="background: #1a1a1a; padding: 8px; margin: 5px 0; border-left: 4px solid #00ff00;">
            <strong>{f['name']}</strong> | Size: {f['size_mb']:.2f}MB | Time: {mtime_str}
        </div>
        """
    return html


@monitor_bp.route('/wal/replay', methods=['POST'])
@require_auth
def wal_replay():
    """Manual WAL replay trigger"""
    try:
        from anteumbra.application.wal_service import replay
        recovered = replay()
        log_with_symbol("notice", "info", f"Manual WAL replay done, recovered {recovered} records", current_app.logger)
        return jsonify({"success": True, "recovered": recovered})
    except Exception as e:
        current_app.logger.error(f"WAL replay failed: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# -- Registry Monitor --

@monitor_bp.route('/registry')
@require_auth
def registry_monitor():
    """Registry monitor page"""
    return render_template('admin/registry_monitor.html')


@monitor_bp.route('/registry/count')
@require_auth
def registry_count():
    """Return registry record count"""
    total = len(get_all(include_deleted=True))
    active = len(get_all(include_deleted=False))
    return f"{active} / {total}"


@monitor_bp.route('/registry/queue')
@require_auth
def registry_queue():
    """Return async save queue status"""
    if not is_async_save_enabled():
        return "Sync mode"
    try:
        size = get_async_save_queue_size()
        return f"{size} pending saves"
    except Exception:
        return "Queue not initialized"


@monitor_bp.route('/registry/last-save')
@require_auth
def registry_last_save():
    """Return last save timestamp"""
    rp = get_registry_path()
    if rp and rp.exists():
        mtime = rp.stat().st_mtime
        return datetime.fromtimestamp(mtime).strftime('%H:%M:%S')
    return "Never saved"


@monitor_bp.route('/registry/compact', methods=['POST'])
@require_auth
def registry_compact():
    """Manual registry compaction trigger"""
    try:
        compact_registry()
        log_with_symbol("notice", "info", "Manual registry compaction done", current_app.logger)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# -- Session Monitor --

@monitor_bp.route('/session')
@require_auth
def session_manager():
    """Session management page"""
    return render_template('admin/session_manager.html')


@monitor_bp.route('/session/list')
@require_auth
def session_list():
    """Return session list (paginated)"""
    from flask_session import Session
    session_dir = current_app.config.get('SESSION_FILE_DIR')
    if not session_dir:
        return "<p style='color: #888;'>Session storage not configured</p>"
    session_path = Path(session_dir)
    if not session_path.exists():
        return "<p style='color: #888;'>No session files</p>"

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
        return "<p style='color: #888;'>No active sessions</p>"

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
            <strong>{s['name']}</strong> | Size: {s['size_kb']:.2f}KB | Last access: {s['mtime']}
        </div>
        """

    if total_pages > 1:
        prev_disabled = "disabled" if page <= 1 else ""
        next_disabled = "disabled" if page >= total_pages else ""
        html += '<div class="pagination-bar" style="margin-top: 10px;">'
        html += f'<button class="btn btn-ghost btn-sm" {prev_disabled} hx-get="/admin/session/list?page={page - 1}" hx-target="#session-list" hx-swap="innerHTML">Prev</button>'
        html += f'<span class="page-info">Page {page} / {total_pages} ({total} total)</span>'
        html += f'<div class="page-jump"><input type="number" class="form-input" style="width: 60px; text-align: center;" min="1" max="{total_pages}" value="{page}" onkeydown="if(event.key===&quot;Enter&quot;){{var p=this.value;htmx.ajax(&quot;GET&quot;,&quot;/admin/session/list?page=&quot;+p,{{target:&quot;#session-list&quot;,swap:&quot;innerHTML&quot;}})}}"></div>'
        html += f'<button class="btn btn-ghost btn-sm" {next_disabled} hx-get="/admin/session/list?page={page + 1}" hx-target="#session-list" hx-swap="innerHTML">Next</button>'
        html += '</div>'
    return html


@monitor_bp.route('/session/cleanup', methods=['POST'])
@require_auth
def session_cleanup():
    """Clean up expired sessions"""
    try:
        deleted = cleanup_sessions(current_app.config.get('SESSION_FILE_DIR'), days=7)
        log_with_symbol("notice", "info", f"Cleaned up expired sessions: {deleted}", current_app.logger)
        return jsonify({"success": True, "deleted": deleted})
    except Exception as e:
        current_app.logger.error(f"Session cleanup failed: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# -- Config Watcher --

@monitor_bp.route('/config')
@require_auth
def config_watcher_status():
    """Config monitor page"""
    return render_template('admin/config_watcher.html')


@monitor_bp.route('/config/history')
@require_auth
def config_history():
    """Return config reload history (paginated)"""
    log_file = normalize_path("logs/Anteumbra/system.log")
    if not log_file.exists():
        return "<p style='color: #888;'>No config reload history</p>"

    page = max(1, request.args.get('page', 1, type=int))
    config = ConfigRegistry.get_raw_config()
    per_page = config.get("web_admin", {}).get("config_items_per_page", 10)

    history = []
    try:
        for line in log_file.read_text(encoding='utf-8').splitlines():
            if '[CONFIG][RELOAD]' in line or '[CONFIG][START]' in line:
                history.append(line)
    except Exception:
        logger.debug("Failed to read config reload history from system.log", exc_info=True)

    if not history:
        return "<p style='color: #888;'>No config reload records</p>"

    total = len(history)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = history[start:end]

    html = ""
    for h in paginated:
        html += f"<div style='background: #1a1a1a; padding: 5px; margin: 3px 0; font-size: 11px;'>{h}</div>"

    if total_pages > 1:
        prev_disabled = "disabled" if page <= 1 else ""
        next_disabled = "disabled" if page >= total_pages else ""
        html += '<div class="pagination-bar" style="margin-top: 10px;">'
        html += f'<button class="btn btn-ghost btn-sm" {prev_disabled} hx-get="/admin/config/history?page={page - 1}" hx-target="#config-history" hx-swap="innerHTML">Prev</button>'
        html += f'<span class="page-info">Page {page} / {total_pages} ({total} total)</span>'
        html += f'<div class="page-jump"><input type="number" class="form-input" style="width: 60px; text-align: center;" min="1" max="{total_pages}" value="{page}" onkeydown="if(event.key===&quot;Enter&quot;){{var p=this.value;htmx.ajax(&quot;GET&quot;,&quot;/admin/config/history?page=&quot;+p,{{target:&quot;#config-history&quot;,swap:&quot;innerHTML&quot;}})}}"></div>'
        html += f'<button class="btn btn-ghost btn-sm" {next_disabled} hx-get="/admin/config/history?page={page + 1}" hx-target="#config-history" hx-swap="innerHTML">Next</button>'
        html += '</div>'
    return html


@monitor_bp.route('/config/signature')
@require_auth
def config_signature():
    """Return current config signature for display only."""
    import hashlib
    try:
        config_data = json.dumps(ConfigRegistry.get_raw_config(), sort_keys=True)
        md5 = hashlib.md5(config_data.encode(), usedforsecurity=False).hexdigest()[:8]
        return f"config.toml [{md5}]"
    except Exception:
        return "Cannot compute signature"


# -- SSE History --

@monitor_bp.route('/sse/history', methods=['GET'])
@require_auth
def sse_history():
    """Return persisted log history"""
    try:
        from anteumbra.application.sse_service import get_log_buffer
        config = ConfigRegistry.get_raw_config()
        web_admin_cfg = config.get("web_admin", {})
        allowed_levels = web_admin_cfg.get("sse_log_levels", ["INFO", "ERROR", "CRITICAL"])
        buffer_logs = get_log_buffer()
        # ... (rest of sse_history logic)
        return jsonify({"logs": buffer_logs, "levels": allowed_levels})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@monitor_bp.route('/registry/wal-status')
@require_auth
def registry_wal_status():
    """Return registry + WAL combined status"""
    try:
        from anteumbra.application.wal_service import get_wal_info
        wal_info = get_wal_info()
        wal_size = wal_info['size_mb'] if wal_info else 0.0
        total = len(get_all(include_deleted=True))
        active = len(get_all(include_deleted=False))
        return jsonify({
            "total": total,
            "active": active,
            "wal_size_mb": round(wal_size, 2),
            "wal_status": "normal" if wal_size < 10 else "warning",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
