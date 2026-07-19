# -*- coding: utf-8 -*-
"""
v1.0.6: Monitor Blueprint — extracted from admin_bp.py
Routes: /stream_logs, /logs/*, /wal/*, /registry/*, /session/*, /sse/*, /config/*
"""
import base64
import html
import hmac
import json
import logging
import queue
import re
import time
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, render_template, request, jsonify, abort,
    Response, current_app, stream_with_context, session,
)

from anteumbra.application.session_service import cleanup_sessions
from anteumbra.domain.logging import log_with_symbol
from anteumbra.domain.site import SiteIdentity
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


def _registry():
    """Return the Registry owned by the current Flask runtime."""
    return get_runtime().registry

monitor_bp = Blueprint('monitor', __name__, url_prefix='/admin')


# -- SSE Live Log Stream --

@monitor_bp.route('/stream_logs')
def stream_logs():
    """v1.7.6: SSE log stream with level filtering (config-driven, hot-reloadable)"""
    token = request.args.get('token')
    if not token:
        abort(403)

    client_ip = request.remote_addr
    runtime = get_runtime()
    sse = runtime.sse
    if sse is None:
        abort(503)

    config = runtime.config.get()
    web_admin_cfg = config.get("web_admin", {})
    limits = sse.get_limits()

    ip_client_count = sse.ip_client_count(client_ip)
    ip_connections = sse.ip_clients(client_ip)

    if ip_client_count >= limits['per_ip']:
        for old_queue in ip_connections:
            sse.unregister_client(old_queue)
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
        if username != expected_username or not is_ip_allowed(client_ip, allowed_ips):
            abort(403)
    except Exception:
        abort(403)

    logger = current_app.logger
    requested_site = request.args.get('site_id') or request.args.get('site')
    try:
        websites = runtime.config.get_enabled_websites()
    except Exception:
        logger.warning("[SSE] Failed to resolve configured sites", exc_info=True)
        abort(503)
    if requested_site:
        requested_id = requested_site.strip().lower()
        websites = [
            site
            for site in websites
            if site.site_id == requested_id or site.name == requested_site
        ]
        if not websites:
            abort(404)
    if not websites:
        abort(503)
    log_files = [
        runtime.logging.get_site_log_path(
            SiteIdentity.from_values(site.site_id, site.name)
        )
        for site in websites
    ]
    show_all_levels = request.args.get('levels', '') == 'all'

    if not show_all_levels:
        try:
            config = runtime.config.get()
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
        handles = []
        try:
            client_queue = sse.register_client(client_ip)
            if not client_queue:
                yield "data: [SSE][ERROR] Client registration failed\n\n"
                return

            for log_file in log_files:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                log_file.touch(exist_ok=True)
                handle = open(
                    log_file,
                    'r',
                    encoding='utf-8',
                    errors='ignore',
                    buffering=1,
                )
                handle.seek(0, 2)
                handles.append(handle)

            last_heartbeat = time.monotonic()
            while True:
                try:
                    signal = client_queue.get_nowait()
                    if signal is None:
                        return
                    if signal == "registry_update":
                        yield "data: [REGISTRY][UPDATE] Registry updated\n\n"
                        continue
                except queue.Empty:
                    pass
                except Exception:
                    break

                emitted = False
                for handle in handles:
                    line = handle.readline()
                    if not line:
                        continue
                    emitted = True
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
                    sse.persist_log_line(cleaned)
                    yield f"data: {cleaned}\n\n"

                now = time.monotonic()
                if now - last_heartbeat >= 15.0:
                    yield "data: [SSE][HEARTBEAT]\n\n"
                    last_heartbeat = now
                    emitted = True
                if not emitted:
                    time.sleep(0.1)

        except Exception as e:
            error_msg = str(e).replace('\n', ' ')
            yield f"data: [SSE][ERROR] {error_msg}\n\n"
        finally:
            for handle in handles:
                try:
                    handle.close()
                except OSError:
                    logger.debug("Failed to close SSE log handle", exc_info=True)
            if client_queue:
                sse.unregister_client(client_queue)
                remaining = sse.connected_client_count()
                logger.debug(f"[SSE] client {client_ip} disconnected, {remaining} remaining")

    response = Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )
    return response


# -- Log History --

@monitor_bp.route('/logs/history')
@require_auth
def logs_history():
    """Return escaped runtime-owned history for LIVE LOG STREAM initialization."""
    try:
        lines = collect_log_history(
            get_runtime(),
            limit=1000,
            log=current_app.logger,
        )
        return render_log_history(
            lines,
            empty_message="[INFO] No log history found",
        )
    except Exception as e:
        current_app.logger.error(f"[LOGS_HISTORY] Read failed: {e}", exc_info=True)
        message = html.escape(str(e)[:50])
        return f'<div class="log-line error">[ERROR] Failed to load history: {message}</div>'


@monitor_bp.route('/logs/access-analysis')
@require_auth
def access_log_analysis():
    """Render a read-only access-log behavior analysis for the Log Analyzer modal."""
    def line(level: str, text: str) -> str:
        return f'<div class="log-line {level}">{html.escape(text)}</div>'

    parts = [line("info", "[ACCESS_ANALYSIS] Web access log analysis")]
    try:
        from anteumbra.application.log_analysis_service import analyze_access_logs

        results = analyze_access_logs(get_runtime().config.get_enabled_websites())
    except Exception as exc:
        current_app.logger.warning("[ACCESS_ANALYSIS] failed: %s", exc, exc_info=True)
        parts.append(line("error", f"[ACCESS_ANALYSIS][ERROR] {exc}"))
        return ''.join(parts)

    if not results:
        parts.append(line("warn", "[ACCESS_ANALYSIS][DISABLED] No enabled websites are configured."))
        return ''.join(parts)

    for result in results:
        site = result["website"]
        status = result["status"]
        parts.append(line("info", f"[ACCESS_ANALYSIS][SITE] {site}"))
        if status == "disabled":
            parts.append(line("warn", f"[ACCESS_ANALYSIS][DISABLED] {site}"))
            continue
        if status in {"missing", "error"}:
            parts.append(line(
                "error",
                f"[ACCESS_ANALYSIS][{status.upper()}] {site}: {result['error']} "
                f"path={result['configured_path']}",
            ))
            continue

        parts.append(line("info", f"[ACCESS_ANALYSIS][SOURCE] selected={result['selected_path']}"))
        stats = result["stats"]
        parts.append(line(
            "info",
            f"[ACCESS_ANALYSIS][SUMMARY] analyzed={stats.get('total_analyzed', 0)} alerts={stats.get('total_alerts', 0)} ips={stats.get('ips_tracked', 0)}",
        ))
        if not result["events"]:
            parts.append(line("info", "[ACCESS_ANALYSIS][CLEAN] No suspicious access-log behavior detected."))
            continue
        for event in result["events"]:
            severity = str(event.get("severity", "medium")).upper()
            event_type = event.get("type", "unknown")
            ip = event.get("ip", "unknown")
            target = event.get("path") or event.get("user_agent") or event.get("tools") or ""
            detail = event.get("reason") or event.get("count") or event.get("unique_paths") or ""
            parts.append(line("warn", f"[ACCESS_ANALYSIS][{severity}] {event_type} ip={ip} target={target} detail={detail}"))

    return ''.join(parts)


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
    info = get_runtime().wal.get_info()
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
    archives = get_runtime().wal.list_archives()
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
        recovered = get_runtime().registry.replay_wal()
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
    total = len(_registry().get_all(include_deleted=True))
    active = len(_registry().get_all(include_deleted=False))
    return f"{active} / {total}"


@monitor_bp.route('/registry/queue')
@require_auth
def registry_queue():
    """Return the authoritative Registry persistence mode."""
    return "Synchronous atomic mode"


@monitor_bp.route('/registry/last-save')
@require_auth
def registry_last_save():
    """Return last save timestamp"""
    rp = _registry().path
    if rp and rp.exists():
        mtime = rp.stat().st_mtime
        return datetime.fromtimestamp(mtime).strftime('%H:%M:%S')
    return "Never saved"


@monitor_bp.route('/registry/compact', methods=['POST'])
@require_auth
def registry_compact():
    """Manual registry compaction trigger"""
    try:
        _registry().compact()
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
    session_dir = current_app.config.get('SESSION_FILE_DIR')
    if not session_dir:
        return "<p style='color: #888;'>Session storage not configured</p>"
    session_path = Path(session_dir)
    if not session_path.exists():
        return "<p style='color: #888;'>No session files</p>"

    page = max(1, request.args.get('page', 1, type=int))
    config = get_runtime().config.get()
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
    runtime = get_runtime()
    page = max(1, request.args.get('page', 1, type=int))
    config = runtime.config.get()
    try:
        per_page = max(
            1,
            int(config.get("web_admin", {}).get("config_items_per_page", 10)),
        )
    except (TypeError, ValueError):
        per_page = 10
    history = runtime.config_history.get_history(limit=1000)

    if not history:
        return "<p style='color: #888;'>No config reload records</p>"

    total = len(history)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = history[start:end]

    output = ""
    for record in paginated:
        text = f"[{record.get('timestamp_display', '')}] Hot reload complete"
        changed_keys = record.get("changed_keys", [])
        if changed_keys:
            text += (
                " | Changes: "
                + ", ".join(str(key) for key in changed_keys[:5])
            )
        duration_ms = record.get("duration_ms")
        if duration_ms is not None:
            text += f" | Duration: {duration_ms}ms"
        output += (
            "<div style='background: #1a1a1a; padding: 5px; margin: 3px 0; "
            f"font-size: 11px;'>{html.escape(text)}</div>"
        )

    if total_pages > 1:
        prev_disabled = "disabled" if page <= 1 else ""
        next_disabled = "disabled" if page >= total_pages else ""
        output += '<div class="pagination-bar" style="margin-top: 10px;">'
        output += f'<button class="btn btn-ghost btn-sm" {prev_disabled} hx-get="/admin/config/history?page={page - 1}" hx-target="#config-history" hx-swap="innerHTML">Prev</button>'
        output += f'<span class="page-info">Page {page} / {total_pages} ({total} total)</span>'
        output += f'<div class="page-jump"><input type="number" class="form-input" style="width: 60px; text-align: center;" min="1" max="{total_pages}" value="{page}" onkeydown="if(event.key===&quot;Enter&quot;){{var p=this.value;htmx.ajax(&quot;GET&quot;,&quot;/admin/config/history?page=&quot;+p,{{target:&quot;#config-history&quot;,swap:&quot;innerHTML&quot;}})}}"></div>'
        output += f'<button class="btn btn-ghost btn-sm" {next_disabled} hx-get="/admin/config/history?page={page + 1}" hx-target="#config-history" hx-swap="innerHTML">Next</button>'
        output += '</div>'
    return output


@monitor_bp.route('/config/signature')
@require_auth
def config_signature():
    """Return current config signature for display only."""
    import hashlib
    try:
        config_data = json.dumps(get_runtime().config.get(), sort_keys=True)
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
        config = get_runtime().config.get()
        web_admin_cfg = config.get("web_admin", {})
        allowed_levels = web_admin_cfg.get("sse_log_levels", ["INFO", "ERROR", "CRITICAL"])
        buffer_logs = get_runtime().sse.get_log_buffer()
        # ... (rest of sse_history logic)
        return jsonify({"logs": buffer_logs, "levels": allowed_levels})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@monitor_bp.route('/registry/wal-status')
@require_auth
def registry_wal_status():
    """Return registry + WAL combined status"""
    try:
        wal_info = get_runtime().wal.get_info()
        wal_size = wal_info['size_mb'] if wal_info else 0.0
        total = len(_registry().get_all(include_deleted=True))
        active = len(_registry().get_all(include_deleted=False))
        return jsonify({
            "total": total,
            "active": active,
            "wal_size_mb": round(wal_size, 2),
            "wal_status": "normal" if wal_size < 10 else "warning",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
