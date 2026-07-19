# -*- coding: utf-8 -*-
"""
v1.0.6: System Blueprint — extracted from admin_bp.py
Routes: /system/* (9) — four-quadrant system management + operations
"""
import base64
import hashlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path

from flask import Blueprint, render_template, request, jsonify, current_app, session

from anteumbra.application.config_history_service import get_config_history_logger
from anteumbra.application.session_service import cleanup_sessions
from anteumbra.domain.logging import log_with_symbol
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)


def _registry():
    """Return the Registry owned by the current Flask runtime."""
    return get_runtime().registry

system_bp = Blueprint('system', __name__, url_prefix='/admin')


@system_bp.route('/system')
@require_auth
def system_management():
    """System management four-quadrant main page"""
    try:
        auth_header = session.get('sse_token')
        if not auth_header:
            username = session.get('username', 'admin')
            auth_str = f"{username}:session_fallback"
            auth_bytes = auth_str.encode('utf-8')
            auth_header = base64.b64encode(auth_bytes).decode('utf-8')
            session['sse_token'] = auth_header

        session_count = 0
        try:
            session_dir = current_app.config.get('SESSION_FILE_DIR')
            if session_dir:
                session_path = Path(session_dir)
                if session_path.exists():
                    sessions = list(session_path.glob("*.sess"))
                    session_count = len(sessions)
        except Exception:
            logger.debug("Failed to count session files in system_management", exc_info=True)

        return render_template(
            'admin/system_management.html',
            auth_header=auth_header,
            username=session.get('username'),
            client_ip=request.remote_addr,
            session_count=session_count
        )
    except Exception as e:
        current_app.logger.error(f"[SYSTEM] Render failed: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@system_bp.route('/system/registry_panel')
@require_auth
def system_registry_panel():
    """Registry status monitoring data (independent refresh)"""
    try:
        all_records = _registry().get_all(include_deleted=True)
        active_records = _registry().get_all(include_deleted=False)

        wal_info = get_runtime().wal.get_info()
        wal_size_mb = wal_info['size_mb'] if wal_info else 0.0

        queue_status = "Synchronous atomic mode"

        last_save = "Never saved"
        rp = _registry().path
        if rp and rp.exists():
            mtime = rp.stat().st_mtime
            last_save = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

        return render_template(
            'admin/panels/registry_panel.html',
            registry_data=all_records,
            total_records=len(all_records),
            active_records=len(active_records),
            queue_status=queue_status,
            last_save=last_save,
            wal_size_mb=wal_size_mb,
            wal_status='normal' if wal_size_mb < 10 else 'warning'
        )
    except Exception as e:
        current_app.logger.error(f"[REGISTRY_PANEL] Load failed: {e}", exc_info=True)
        return f'<div style="color: #ff4444; padding: 20px;">Load failed: {str(e)}</div>', 500


@system_bp.route('/system/wal_panel')
@require_auth
def system_wal_panel():
    """WAL management data panel"""
    try:
        wal = get_runtime().wal
        wal_info = wal.get_info()
        archives = wal.list_archives()
        wal_status, wal_status_text, wal_size_mb = wal.get_status()

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
        current_app.logger.critical(f"[WAL_PANEL] Fatal error: {e}", exc_info=True)
        return render_template(
            'admin/panels/wal_panel.html',
            current_wal=None, files=[],
            wal_status='error', wal_status_text='System error',
            wal_size_mb=0.0, error=f"System exception: {str(e)[:30]}..."
        ), 500


@system_bp.route('/system/session_panel')
@require_auth
def system_session_panel():
    """Session management data panel (enhanced: status calculation + color + pagination)"""
    try:
        session_dir = current_app.config.get('SESSION_FILE_DIR')
        if not session_dir:
            return render_template(
                'admin/panels/session_panel.html',
                sessions=[], session_count=0, active_count=0,
                page=1, total_pages=1, error="Session storage not configured"
            )

        session_path = Path(session_dir)
        if not session_path.exists():
            return render_template(
                'admin/panels/session_panel.html',
                sessions=[], session_count=0, active_count=0,
                page=1, total_pages=1, error="Session directory not found"
            )

        page = max(1, request.args.get('page', 1, type=int))
        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("session_items_per_page", 20)

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
                current_app.logger.debug(f"Skipping file {sess_file}: {e}")
                continue

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
        current_app.logger.error(f"[SESSION_PANEL] Load failed: {e}", exc_info=True)
        return render_template(
            'admin/panels/session_panel.html',
            sessions=[], session_count=0, active_count=0,
            page=1, total_pages=1,
            error=f"Load failed: {str(e)}"
        )


@system_bp.route('/system/config_panel')
@require_auth
def system_config_panel():
    """Config hot-reload monitoring data"""
    try:
        config = get_runtime().config.get()
        config_data = json.dumps(config, sort_keys=True)
        config_signature = hashlib.md5(config_data.encode(), usedforsecurity=False).hexdigest()[:8]

        page = max(1, request.args.get('page', 1, type=int))
        per_page = config.get("web_admin", {}).get("config_items_per_page", 10)

        history_logger = get_config_history_logger()
        raw_history = history_logger.get_history(limit=1000)
        formatted_history = []
        for record in raw_history:
            item = f"[{record['timestamp_display']}] Hot reload complete"
            if record['changed_keys']:
                changes = ', '.join(record['changed_keys'][:5])
                item += f" | Changes: {changes}"
            if record['duration_ms']:
                item += f" | Duration: {record['duration_ms']}ms"
            formatted_history.append(item)

        total = len(formatted_history)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)

        start = (page - 1) * per_page
        end = start + per_page
        paginated_history = formatted_history[start:end]

        engine = get_runtime().yara_engine
        if engine is None:
            raise RuntimeError("YaraEngine is not configured")
        rule_stats = engine.get_rule_stats() if hasattr(engine, 'get_rule_stats') else {}

        return render_template(
            'admin/panels/config_panel.html',
            config_signature=config_signature,
            config_path=str(get_runtime().config.path),
            history=paginated_history,
            page=page, total_pages=total_pages, total=total,
            rule_stats=rule_stats,
            yara_enabled=len(rule_stats) > 0
        )
    except Exception as e:
        current_app.logger.error(f"[CONFIG_PANEL] Load failed: {e}", exc_info=True)
        return f'<div style="color: #ff4444; padding: 20px;">Load failed: {str(e)}</div>', 500


# -- System Operations (return panel HTML fragments) --

@system_bp.route('/system/registry/compact', methods=['POST'])
@require_auth
def system_registry_compact():
    """Manual registry compaction (enhanced feedback)"""
    try:
        if hasattr(current_app, '_registry_compacting'):
            return render_template(
                'admin/panels/registry_panel.html',
                error="Compaction in progress, please try again later"
            )

        current_app._registry_compacting = True
        result = _registry().compact()
        delattr(current_app, '_registry_compacting')

        all_records = _registry().get_all(include_deleted=True)
        active_records = _registry().get_all(include_deleted=False)

        wal_info = get_runtime().wal.get_info()
        wal_size_mb = wal_info['size_mb'] if wal_info else 0.0

        queue_status = "Synchronous atomic mode"

        last_save = "Never saved"
        rp = _registry().path
        if rp and rp.exists():
            mtime = rp.stat().st_mtime
            last_save = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

        message = None
        message_type = None
        if isinstance(result, dict):
            if "error" in result:
                message = f"Compaction failed: {result['error']}"
                message_type = "error"
            else:
                if result['cleaned'] > 0:
                    message = f"Registry compacted, cleaned {result['cleaned']} expired records"
                    message_type = "success"
                else:
                    message = f"Registry compacted, scanned {result['total']} records, no expired records (threshold: 30 days)"
                    message_type = "success"

        log_with_symbol("notice", "info", "Registry compaction completed", current_app.logger)

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
        current_app.logger.error(f"[COMPACT] Failed: {e}", exc_info=True)
        return render_template(
            'admin/panels/registry_panel.html',
            error=f"Compaction failed: {str(e)}",
            message_type="error"
        )


@system_bp.route('/system/wal/replay', methods=['POST'])
@require_auth
def system_wal_replay():
    """Manual WAL replay (returns rendered panel HTML)"""
    try:
        runtime = get_runtime()
        recovered = runtime.registry.replay_wal()

        wal_status, wal_status_text, wal_size_mb = runtime.wal.get_status()
        wal_info = runtime.wal.get_info()
        archives = runtime.wal.list_archives()

        current_wal = None
        if wal_info:
            current_wal = {
                'name': wal_info['name'],
                'size_mb': wal_info['size_mb'],
                'path': wal_info['path']
            }

        log_with_symbol("notice", "info", f"WAL replay done, recovered {recovered} records", current_app.logger)

        return render_template(
            'admin/panels/wal_panel.html',
            current_wal=current_wal,
            files=archives[:10],
            wal_status=wal_status,
            wal_status_text=wal_status_text,
            wal_size_mb=wal_size_mb,
            message=f"WAL replay done, recovered {recovered} records",
            operation_message=f"WAL replay done, recovered {recovered} records",
            message_type="success",
        )
    except Exception as e:
        current_app.logger.error(f"[WAL_REPLAY] Failed: {e}", exc_info=True)
        return render_template(
            'admin/panels/wal_panel.html',
            error=f"WAL replay failed: {str(e)}",
            message_type="error"
        )


@system_bp.route('/system/session/cleanup', methods=['POST'])
@require_auth
def system_session_cleanup():
    """Clean up expired sessions (returns rendered panel HTML + pagination)"""
    try:
        session_dir = current_app.config.get('SESSION_FILE_DIR')
        deleted = cleanup_sessions(session_dir, days=7)
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
                    except OSError:
                        current_app.logger.debug(
                            "Skipping unreadable session file %s",
                            sess_file,
                            exc_info=True,
                        )
                        continue
                all_sessions.sort(key=lambda x: x['mtime'], reverse=True)

        page = 1
        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("session_items_per_page", 20)
        total = len(all_sessions)
        total_pages = max(1, (total + per_page - 1) // per_page)
        active_count = sum(1 for s in all_sessions if s['state'] == 'active')
        paginated = all_sessions[:per_page]

        log_with_symbol("notice", "info", f"Cleaned up expired sessions: {deleted}", current_app.logger)

        return render_template(
            'admin/panels/session_panel.html',
            sessions=paginated,
            session_count=total,
            active_count=active_count,
            page=page,
            total_pages=total_pages,
            error=None,
            message=f"Cleanup done, deleted {deleted} expired sessions",
            message_type="success"
        )
    except Exception as e:
        current_app.logger.error(f"[SESSION_CLEANUP] Failed: {e}", exc_info=True)
        return render_template(
            'admin/panels/session_panel.html',
            sessions=[], session_count=0, active_count=0,
            page=1, total_pages=1,
            error=f"Cleanup failed: {str(e)}",
            message_type="error"
        )


@system_bp.route('/system/config/reload', methods=['POST'])
@require_auth
def system_config_reload():
    """Manual config hot-reload (returns rendered panel HTML)"""
    try:
        get_runtime().config.reload()

        config_data = json.dumps(get_runtime().config.get(), sort_keys=True)
        config_signature = hashlib.md5(config_data.encode(), usedforsecurity=False).hexdigest()[:8]

        history_logger = get_config_history_logger()
        raw_history = history_logger.get_history(limit=10)
        formatted_history = []
        for record in raw_history:
            item = f"[{record['timestamp_display']}] Hot reload complete"
            if record['changed_keys']:
                changes = ', '.join(record['changed_keys'][:5])
                item += f" | Changes: {changes}"
            if record['duration_ms']:
                item += f" | Duration: {record['duration_ms']}ms"
            formatted_history.append(item)

        engine = get_runtime().yara_engine
        if engine is None:
            raise RuntimeError("YaraEngine is not configured")
        rule_stats = engine.get_rule_stats() if hasattr(engine, 'get_rule_stats') else {}

        log_with_symbol("notice", "info", "Config hot-reload triggered", current_app.logger)

        return render_template(
            'admin/panels/config_panel.html',
            config_signature=config_signature,
            config_path=str(get_runtime().config.path),
            history=formatted_history,
            rule_stats=rule_stats,
            yara_enabled=len(rule_stats) > 0,
            message="Config hot-reload triggered",
            message_type="success"
        )
    except Exception as e:
        current_app.logger.error(f"[CONFIG_RELOAD] Failed: {e}", exc_info=True)
        return render_template(
            'admin/panels/config_panel.html',
            error=f"Hot reload failed: {str(e)}",
            message_type="error"
        )
