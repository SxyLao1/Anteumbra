"""Administrative WAL, registry, session, config, and SSE history routes."""

import html
import json
import re
from datetime import datetime
from pathlib import Path

from flask import current_app, jsonify, render_template, request

from anteumbra.application.session_service import cleanup_sessions
from anteumbra.domain.logging import log_with_symbol
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.blueprints.monitor_bp import monitor_bp
from anteumbra.interfaces.web.runtime import get_runtime


def _registry():
    return get_runtime().registry


# -- WAL Management --


@monitor_bp.route("/wal")
@require_auth
def wal_manager():
    """WAL management page"""
    return render_template("admin/wal_manager.html")


@monitor_bp.route("/wal/current")
@require_auth
def wal_current():
    """Return current WAL file info"""
    info = get_runtime().wal.get_info()
    if not info:
        return "<p style='color: #ff4444;'>WAL file not found</p>"
    size_mb = info["size_mb"]
    return f"""
    <div style="background: #2a2a2a; padding: 10px; border-left: 4px solid #00ff00;">
        <strong>Current WAL:</strong> {info["name"]}<br>
        <strong>Size:</strong> {size_mb:.2f} MB<br>
        <strong>Path:</strong> {info["path"]}<br>
        <strong>Status:</strong> {'<span style="color: #00ff00;">Normal</span>' if size_mb < 10 else '<span style="color: #ffaa00;">Near threshold</span>'}
    </div>
    """


@monitor_bp.route("/wal/list")
@require_auth
def wal_list():
    """Return WAL archive list"""
    archives = get_runtime().wal.list_archives()
    if not archives:
        return "<p style='color: #888;'>No archived WAL files</p>"
    html = ""
    for f in archives[:20]:
        mtime_str = datetime.fromtimestamp(f["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
        html += f"""
        <div style="background: #1a1a1a; padding: 8px; margin: 5px 0; border-left: 4px solid #00ff00;">
            <strong>{f["name"]}</strong> | Size: {f["size_mb"]:.2f}MB | Time: {mtime_str}
        </div>
        """
    return html


@monitor_bp.route("/wal/replay", methods=["POST"])
@require_auth
def wal_replay():
    """Manual WAL replay trigger"""
    try:
        recovered = get_runtime().registry.replay_wal()
        log_with_symbol(
            "notice",
            "info",
            f"Manual WAL replay done, recovered {recovered} records",
            current_app.logger,
        )
        return jsonify({"success": True, "recovered": recovered})
    except Exception as e:
        current_app.logger.error(f"WAL replay failed: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# -- Registry Monitor --


@monitor_bp.route("/registry")
@require_auth
def registry_monitor():
    """Registry monitor page"""
    return render_template("admin/registry_monitor.html")


@monitor_bp.route("/registry/count")
@require_auth
def registry_count():
    """Return registry record count"""
    total = len(_registry().get_all(include_deleted=True))
    active = len(_registry().get_all(include_deleted=False))
    return f"{active} / {total}"


@monitor_bp.route("/registry/queue")
@require_auth
def registry_queue():
    """Return the authoritative Registry persistence mode."""
    return "Synchronous atomic mode"


@monitor_bp.route("/registry/last-save")
@require_auth
def registry_last_save():
    """Return last save timestamp"""
    rp = _registry().path
    if rp and rp.exists():
        mtime = rp.stat().st_mtime
        return datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
    return "Never saved"


@monitor_bp.route("/registry/compact", methods=["POST"])
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


@monitor_bp.route("/session")
@require_auth
def session_manager():
    """Session management page"""
    return render_template("admin/session_manager.html")


@monitor_bp.route("/session/list")
@require_auth
def session_list():
    """Return session list (paginated)"""
    session_dir = current_app.config.get("SESSION_FILE_DIR")
    if not session_dir:
        return "<p style='color: #888;'>Session storage not configured</p>"
    session_path = Path(session_dir)
    if not session_path.exists():
        return "<p style='color: #888;'>No session files</p>"

    page = max(1, request.args.get("page", 1, type=int))
    config = get_runtime().config.get()
    per_page = config.get("web_admin", {}).get("session_items_per_page", 20)

    sessions = []
    for sess_file in session_path.iterdir():
        if sess_file.is_dir():
            continue
        filename = sess_file.name
        is_session = re.match(r"^[a-f0-9]{32}$", filename, re.IGNORECASE)
        if not is_session:
            continue
        stat = sess_file.stat()
        sessions.append(
            {
                "name": filename,
                "size_kb": round(stat.st_size / 1024, 2),
                "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

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
            <strong>{s["name"]}</strong> | Size: {s["size_kb"]:.2f}KB | Last access: {s["mtime"]}
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
        html += "</div>"
    return html


@monitor_bp.route("/session/cleanup", methods=["POST"])
@require_auth
def session_cleanup():
    """Clean up expired sessions"""
    try:
        deleted = cleanup_sessions(current_app.config.get("SESSION_FILE_DIR"), days=7)
        log_with_symbol(
            "notice", "info", f"Cleaned up expired sessions: {deleted}", current_app.logger
        )
        return jsonify({"success": True, "deleted": deleted})
    except Exception as e:
        current_app.logger.error(f"Session cleanup failed: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# -- Config Watcher --


@monitor_bp.route("/config")
@require_auth
def config_watcher_status():
    """Config monitor page"""
    return render_template("admin/config_watcher.html")


@monitor_bp.route("/config/history")
@require_auth
def config_history():
    """Return config reload history (paginated)"""
    runtime = get_runtime()
    page = max(1, request.args.get("page", 1, type=int))
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
            text += " | Changes: " + ", ".join(str(key) for key in changed_keys[:5])
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
        output += "</div>"
    return output


@monitor_bp.route("/config/signature")
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


@monitor_bp.route("/sse/history", methods=["GET"])
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


@monitor_bp.route("/registry/wal-status")
@require_auth
def registry_wal_status():
    """Return registry + WAL combined status"""
    try:
        wal_info = get_runtime().wal.get_info()
        wal_size = wal_info["size_mb"] if wal_info else 0.0
        total = len(_registry().get_all(include_deleted=True))
        active = len(_registry().get_all(include_deleted=False))
        return jsonify(
            {
                "total": total,
                "active": active,
                "wal_size_mb": round(wal_size, 2),
                "wal_status": "normal" if wal_size < 10 else "warning",
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
