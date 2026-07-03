# -*- coding: utf-8 -*-
"""
v1.0.6: Settings Blueprint — extracted from admin_bp.py
Routes: /settings/* (11) + /siem/* (2)
"""
import json
import os
from pathlib import Path

from flask import Blueprint, render_template, request, jsonify, current_app, session

from anteumbra.infrastructure.config.loader import load_config
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.interfaces.web.auth import require_auth

settings_bp = Blueprint('settings', __name__, url_prefix='/admin')


@settings_bp.route('/settings')
@require_auth
def settings_page():
    """v1.8.0: Settings -- system + account + notification config merged view"""
    try:
        return render_template('admin/settings.html')
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] settings failed: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@settings_bp.route('/settings/notifications')
@require_auth
def settings_notifications():
    """v1.8.0: Web Config Panel -- notification config form"""
    try:
        cfg = load_config()
        notifier = cfg.get('notifier', {})
        email = notifier.get('email', {})
        wechat = notifier.get('wechat', {})
        webhook = notifier.get('webhook', {})
        return render_template('admin/panels/notify_config.html',
            email=email, wechat=wechat, webhook=webhook)
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] notifications failed: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">Load failed: {e}</div>', 500


@settings_bp.route('/settings/config/editor')
@require_auth
def settings_config_editor():
    """v1.8.0: Dynamic config.toml editor -- server-side struct parsing, template rendering"""
    try:
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

        levels = {}
        for sec_name in sections:
            depth = sec_name.count('.')
            levels[sec_name] = depth

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
        current_app.logger.error(f"[SETTINGS] config editor failed: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">Config load error: {e}</div>', 500


@settings_bp.route('/settings/config/save', methods=['POST'])
@require_auth
def settings_config_save():
    """v1.9.5: Fix -- use tomli_w for proper TOML serialization"""
    try:
        import tomli_w
        data = request.get_json()
        changes = data.get('changes', {})
        if not changes:
            return jsonify({'success': False, 'error': 'No changes'}), 400
        config_path = ConfigRegistry._config_path
        raw = ConfigRegistry.get_raw_config()
        for full_key, new_val in changes.items():
            parts = full_key.split('.')
            target = raw
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]
            key = parts[-1]
            s = str(new_val).strip() if not isinstance(new_val, (bool, int, float, list)) else new_val
            if isinstance(s, bool):
                target[key] = s
            elif isinstance(s, (int, float)):
                target[key] = s
            elif isinstance(s, str):
                if s.lower() in ('true', 'false'):
                    target[key] = s.lower() == 'true'
                elif s.startswith('[') and s.endswith(']'):
                    try:
                        target[key] = json.loads(s)
                    except Exception:
                        target[key] = s
                else:
                    try:
                        if '.' in s:
                            target[key] = float(s)
                        else:
                            target[key] = int(s)
                    except ValueError:
                        target[key] = s
            else:
                target[key] = new_val
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(tomli_w.dumps(raw))
        try:
            ConfigRegistry.initialize(force=True)
        except Exception:
            pass
        return jsonify({'success': True, 'message': 'Config saved'})
    except Exception as e:
        current_app.logger.error(f'[SETTINGS] config save failed: {e}', exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/settings/config/data')
@require_auth
def settings_config_data():
    """v1.8.0: Return config.toml structured data + comment descriptions"""
    try:
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
                sections[current_section] = {'title': current_section, 'fields': {}}
                continue
            if '=' in stripped and current_section:
                key, _, value = stripped.partition('=')
                key = key.strip()
                value = value.strip().rstrip('#').strip()
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
        current_app.logger.error(f"[SETTINGS] config data failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/settings/env/save', methods=['POST'])
@require_auth
def settings_env_save():
    """v1.8.0: Save .env file (structured variables)"""
    try:
        data = request.get_json()
        vars_data = data.get('vars', {})
        config_path = ConfigRegistry._config_path
        env_path = os.path.join(os.path.dirname(config_path), '.env')

        existing = {}
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        existing[k.strip()] = line

        for k, v in vars_data.items():
            if v:
                existing[k] = f'{k}={v}'

        with open(env_path, 'w', encoding='utf-8') as f:
            f.write('# Anteumbra .env -- managed via Settings UI\n')
            for k in sorted(existing.keys()):
                f.write(existing[k] + '\n')

        for k, v in vars_data.items():
            if v:
                os.environ[k] = v
        try:
            ConfigRegistry.initialize(force=True)
        except Exception:
            pass

        return jsonify({'success': True, 'message': '.env saved + config reloaded'})
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] env save failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/settings/env/hash', methods=['POST'])
@require_auth
def settings_env_hash():
    """v1.8.0: Generate scrypt password hash"""
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


@settings_bp.route('/settings/notifications/save', methods=['POST'])
@require_auth
def settings_notifications_save():
    """v1.8.0: Save notification toggle state to config.toml"""
    try:
        section = request.form.get('section', '')
        key = request.form.get('key', '')
        value = request.form.get('value', 'on')

        if section not in ('email', 'wechat', 'webhook') or key not in ('enabled',):
            return jsonify({"error": "Invalid parameters"}), 400

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
                    break
                if line.strip().startswith(f'{key} =') or line.strip().startswith(f'{key}='):
                    new_val = 'true' if value == 'on' else 'false'
                    lines[i] = f'{key} = {new_val}\n'
                    break

        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        return jsonify({"success": True, "message": f"{section}.{key} updated"})
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] save failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# -- SIEM Export endpoints --

@settings_bp.route('/siem/export')
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
        current_app.logger.error(f"[SETTINGS] SIEM export failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@settings_bp.route('/siem/stats')
@require_auth
def siem_stats():
    """Get SIEM exporter statistics."""
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
        return jsonify(get_siem_exporter().get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -- Settings status panels --

@settings_bp.route('/settings/siem-status')
@require_auth
def settings_siem_status():
    """SIEM export status panel for Settings page."""
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
        e = get_siem_exporter()
        s = e.get_stats()
        export_path = Path(s["export_file"])
        has_data = export_path.exists() and export_path.stat().st_size > 0
        return render_template('admin/panels/siem_status.html',
            enabled=s["enabled"], format=s["format"],
            total_exported=s["total_exported"], file_size_mb=s["file_size_mb"],
            syslog_active=s["syslog_active"], has_data=has_data,
            export_file=str(export_path))
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'


@settings_bp.route('/settings/storage-status')
@require_auth
def settings_storage_status():
    """Storage backend status panel for Settings page."""
    try:
        cfg = ConfigRegistry.get_raw_config().get("storage", {})
        backend = cfg.get("backend", "json")
        db_path = cfg.get("db_path", "data/anteumbra.db")
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


@settings_bp.route('/settings/plugin-status')
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
