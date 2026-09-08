# -*- coding: utf-8 -*-
"""
v1.0.6: Settings Blueprint — extracted from admin_bp.py
Routes: /settings/* (11) + /siem/* (2)
"""

import json
import logging
import os
import re
from pathlib import Path

import tomli_w
from flask import Blueprint, current_app, jsonify, render_template, request

from anteumbra.cli.config_support import load_toml_value, validate_config_file
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.pages import render_page
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

settings_bp = Blueprint("settings", __name__, url_prefix="/admin")

# -- Config editor helpers (config.toml round-trip safety) --------------------
#
# Why: tomli_w persists arrays as multi-line blocks, but the pre-v1.0.36
# editor parsed config.toml line by line. A multi-line array therefore
# surfaced as the truncated string "[" plus stray key fragments, and saving
# wrote those fragments back — silently corrupting every list value and
# locking admins out via web_admin.allowed_ips. Editor values now come from
# the parsed runtime config (rendered single-line), and the save endpoint
# rejects anything it cannot round-trip instead of storing raw text.

_CONFIG_KEY_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")


def _contains_tables(value) -> bool:
    if isinstance(value, dict):
        return True
    if isinstance(value, list):
        return any(_contains_tables(item) for item in value)
    return False


def _inline_value_text(value) -> str:
    """Render a config value as single-line text for an ``<input>`` field.

    HTML inputs cannot hold newlines, so arrays of scalars are rendered as
    JSON (valid TOML arrays) and table-bearing values via tomli_w with
    whitespace collapsed. The output must parse back through
    ``load_toml_value`` on save.
    """
    if _contains_tables(value):
        text = tomli_w.dumps({"v": value}).split("=", 1)[1].strip()
        return " ".join(text.split())
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:  # e.g. TOML datetimes inside arrays
        text = tomli_w.dumps({"v": value}).split("=", 1)[1].strip()
        return " ".join(text.split())


def _harvest_descriptions(config_path: Path) -> dict[str, str]:
    """Best-effort ``# @desc:`` extraction. Display-only and junk-tolerant."""
    descriptions: dict[str, str] = {}
    section = ""
    pending = None
    try:
        lines = Path(config_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return descriptions
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# @desc:"):
            pending = stripped.split("@desc:", 1)[1].strip()
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            inner = stripped[2:-2] if stripped.startswith("[[") else stripped[1:-1]
            section = inner.strip()
            continue
        if "=" in stripped and pending:
            key = stripped.partition("=")[0].strip()
            dotted = f"{section}.{key}" if section else key
            descriptions[dotted] = pending
            pending = None
    return descriptions


def _editor_field(key: str, value, description: str) -> dict:
    field = {
        "key": key,
        "value": value,
        "raw": str(value),
        "type": "string",
        "desc": description,
        "is_env": False,
        "display": value,
    }
    if isinstance(value, bool):
        field["type"] = "bool"
    elif isinstance(value, int):
        field["type"] = "int"
    elif isinstance(value, float):
        field["type"] = "float"
    elif isinstance(value, str):
        raw = value.strip()
        if raw.startswith("${") and raw.endswith("}"):
            field["is_env"] = True
            field["display"] = "(env: " + raw[2:-1].split(":-")[0] + ")"
    else:  # lists (incl. tables), datetimes and other non-scalar TOML values
        inline = _inline_value_text(value)
        field["type"] = "array"
        field["raw"] = inline
        field["value"] = inline
    return field


def _collect_editor_sections(config: dict, descriptions: dict[str, str]) -> dict[str, list]:
    """Build ``{section: [field, ...]}`` from the parsed config, in order.

    Tables become sections (dotted names); lists of tables such as
    ``ip_blocker.devices`` stay a single array field so they round-trip
    intact through the editor input and the save endpoint.
    """
    sections: dict[str, list] = {}

    def walk(prefix: str, table: dict) -> list[dict]:
        fields: list[dict] = []
        for key, value in table.items():
            dotted = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                sections[dotted] = []  # reserve document order before recursing
                sections[dotted] = walk(dotted, value)
            else:
                fields.append(_editor_field(key, value, descriptions.get(dotted, "")))
        return fields

    root_fields = walk("", config)
    if root_fields:
        sections[""] = root_fields
    return sections


def _coerce_config_value(key: str, new_val):
    """Coerce a submitted editor value; reject unparseable array/table text.

    The legacy path stored any string verbatim, which is how a multi-line
    array truncated to "[" was written into config.toml. Array-looking text
    must now parse as a TOML value or the whole save is rejected with 400.
    """
    if isinstance(new_val, (bool, int, float, list, dict)):
        return new_val
    if not isinstance(new_val, str):
        raise ValueError(f"Unsupported value type for {key}: {type(new_val).__name__}")
    stripped = new_val.strip()
    if stripped.lower() in ("true", "false"):
        return stripped.lower() == "true"
    if stripped.startswith(("[", "{")):
        try:
            return load_toml_value(stripped)
        except Exception as exc:
            raise ValueError(
                f"Invalid array/table value for {key} (TOML parse failed): {stripped!r}"
            ) from exc
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    return stripped


def _set_dotted(config: dict, dotted_key: str, value) -> None:
    parts = dotted_key.split(".")
    target = config
    for part in parts[:-1]:
        if not isinstance(target.get(part), dict):
            target[part] = {}
        target = target[part]
    target[parts[-1]] = value


def _siem_exporter():
    return get_runtime().siem_exporter


@settings_bp.route("/settings")
@require_auth
def settings_page():
    """v1.8.0: Settings -- system + account + notification config merged view"""
    try:
        return render_page("admin/settings.html")
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] settings failed: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


@settings_bp.route("/settings/notifications")
@require_auth
def settings_notifications():
    """v1.8.0: Web Config Panel -- notification config form"""
    try:
        cfg = get_runtime().config.get()
        notifier = cfg.get("notifier", {})
        email = notifier.get("email", {})
        wechat = notifier.get("wechat", {})
        webhook = notifier.get("webhook", {})
        return render_page(
            "admin/panels/notify_config.html", email=email, wechat=wechat, webhook=webhook
        )
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] notifications failed: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">Load failed: {e}</div>', 500


@settings_bp.route("/settings/config/editor")
@require_auth
def settings_config_editor():
    """v1.0.36: config.toml editor fed by the parsed runtime config.

    Values come from ``config.get()`` (tomllib semantics) so multi-line
    arrays and tables survive; raw file lines are only scanned for
    ``# @desc:`` tooltips.
    """
    try:
        config_path = Path(get_runtime().config.path)
        config = get_runtime().config.get()
        sections = _collect_editor_sections(config, _harvest_descriptions(config_path))
        levels = {name: name.count(".") for name in sections}

        env_vars = {}
        env_path = config_path.parent / ".env"
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip()

        return render_page(
            "admin/panels/config_editor.html",
            sections=sections,
            sections_levels=levels,
            config_path=str(config_path),
            env_vars=env_vars,
            os=os,
        )
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] config editor failed: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">Config load error: {e}</div>', 500


@settings_bp.route("/settings/config/save", methods=["POST"])
@require_auth
def settings_config_save():
    """v1.0.36: round-trip safe config save.

    Array/table text must parse as TOML; malformed keys and values are
    rejected with 400 instead of being written. The candidate file is
    validated before it atomically replaces config.toml, so a save can no
    longer introduce config errors the runtime would refuse (e.g. an
    invalid allowed_ips entry that locks the admin out).
    """
    tmp_path = None
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid request body"}), 400
        changes = data.get("changes", {})
        if not isinstance(changes, dict) or not changes:
            return jsonify({"success": False, "error": "No changes"}), 400
        config_path = Path(get_runtime().config.path)
        raw = get_runtime().config.get()
        for full_key, new_val in changes.items():
            if not _CONFIG_KEY_RE.fullmatch(str(full_key)):
                return jsonify(
                    {"success": False, "error": f"Invalid config key: {full_key!r}"}
                ), 400
            try:
                coerced = _coerce_config_value(str(full_key), new_val)
            except ValueError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400
            _set_dotted(raw, str(full_key), coerced)

        # Write a sibling temp file, validate it, then atomically replace.
        # Delta validation: only errors newly introduced by this save block
        # it, so saving into an already-warning config keeps working.
        tmp_path = config_path.with_name(config_path.name + ".tmp")
        tmp_path.write_text(tomli_w.dumps(raw), encoding="utf-8")
        baseline_errors, _ = validate_config_file(config_path)
        candidate_errors, _ = validate_config_file(tmp_path)
        new_errors = [error for error in candidate_errors if error not in baseline_errors]
        if new_errors:
            tmp_path.unlink(missing_ok=True)
            tmp_path = None
            return jsonify(
                {"success": False, "error": "Invalid config: " + "; ".join(new_errors[:3])}
            ), 400
        os.replace(tmp_path, config_path)
        tmp_path = None
        try:
            get_runtime().config.reload()
        except Exception:
            logger.debug("Runtime config reload failed after config save", exc_info=True)
        return jsonify({"success": True, "message": "Config saved"})
    except Exception as e:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        current_app.logger.error(f"[SETTINGS] config save failed: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@settings_bp.route("/settings/config/data")
@require_auth
def settings_config_data():
    """v1.8.0: config.toml structured data (values from the parsed config)."""
    try:
        config_path = Path(get_runtime().config.path)
        config = get_runtime().config.get()
        descriptions = _harvest_descriptions(config_path)
        sections_out = {}
        for sec_name, fields in _collect_editor_sections(config, descriptions).items():
            sections_out[sec_name] = {
                "title": sec_name,
                "fields": {
                    field["key"]: {
                        "value": field["raw"] if field["type"] == "array" else field["value"],
                        "type": field["type"],
                        "desc": field["desc"],
                    }
                    for field in fields
                },
            }
        return jsonify({"sections": sections_out, "path": str(config_path)})
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] config data failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@settings_bp.route("/settings/env/save", methods=["POST"])
@require_auth
def settings_env_save():
    """v1.8.0: Save .env file (structured variables)"""
    try:
        data = request.get_json()
        vars_data = data.get("vars", {})
        config_path = get_runtime().config.path
        env_path = os.path.join(os.path.dirname(config_path), ".env")

        existing = {}
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        existing[k.strip()] = line

        for k, v in vars_data.items():
            if v:
                existing[k] = f"{k}={v}"

        with open(env_path, "w", encoding="utf-8") as f:
            f.write("# Anteumbra .env -- managed via Settings UI\n")
            for k in sorted(existing.keys()):
                f.write(existing[k] + "\n")

        for k, v in vars_data.items():
            if v:
                os.environ[k] = v
        try:
            get_runtime().config.reload()
        except Exception:
            logger.debug("Runtime config reload failed after .env save", exc_info=True)

        return jsonify({"success": True, "message": ".env saved + config reloaded"})
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] env save failed: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@settings_bp.route("/settings/env/hash", methods=["POST"])
@require_auth
def settings_env_hash():
    """v1.8.0: Generate scrypt password hash"""
    try:
        data = request.get_json()
        password = data.get("password", "")
        if not password or len(password) < 6:
            return jsonify({"error": "Password too short (min 6 chars)"}), 400
        from werkzeug.security import generate_password_hash

        h = generate_password_hash(password, method="scrypt:32768:8:1")
        return jsonify({"hash": h})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@settings_bp.route("/settings/notifications/save", methods=["POST"])
@require_auth
def settings_notifications_save():
    """v1.8.0: Save notification toggle state to config.toml"""
    try:
        section = request.form.get("section", "")
        key = request.form.get("key", "")
        value = request.form.get("value", "on")

        if section not in ("email", "wechat", "webhook") or key not in ("enabled",):
            return jsonify({"error": "Invalid parameters"}), 400

        config_path = get_runtime().config.path
        with open(config_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_target_section = False
        section_header = f"[notifier.{section}]"
        for i, line in enumerate(lines):
            if line.strip() == section_header:
                in_target_section = True
                continue
            if in_target_section:
                if line.strip().startswith("["):
                    break
                if line.strip().startswith(f"{key} =") or line.strip().startswith(f"{key}="):
                    new_val = "true" if value == "on" else "false"
                    lines[i] = f"{key} = {new_val}\n"
                    break

        with open(config_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        return jsonify({"success": True, "message": f"{section}.{key} updated"})
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] save failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# -- SIEM Export endpoints --


@settings_bp.route("/siem/export")
@require_auth
def siem_export():
    """Export detection records as SIEM-formatted events (JSON Lines / CEF)."""
    fmt = request.args.get("format", "")
    try:
        exporter = _siem_exporter()
        if fmt:
            exporter.set_format(fmt)
        records = get_runtime().registry.get_all(include_deleted=False)
        count = exporter.export_existing(records)
        export_path = exporter.export_path
        return jsonify(
            {
                "success": True,
                "exported": count,
                "format": exporter.format,
                "file": str(export_path),
                "size_bytes": export_path.stat().st_size if export_path.exists() else 0,
            }
        )
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] SIEM export failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@settings_bp.route("/siem/stats")
@require_auth
def siem_stats():
    """Get SIEM exporter statistics."""
    try:
        return jsonify(_siem_exporter().get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -- Settings status panels --


@settings_bp.route("/settings/siem-status")
@require_auth
def settings_siem_status():
    """SIEM export status panel for Settings page."""
    try:
        e = _siem_exporter()
        s = e.get_stats()
        export_path = Path(s["export_file"])
        has_data = export_path.exists() and export_path.stat().st_size > 0
        return render_page(
            "admin/panels/siem_status.html",
            enabled=s["enabled"],
            format=s["format"],
            total_exported=s["total_exported"],
            file_size_mb=s["file_size_mb"],
            syslog_active=s["syslog_active"],
            has_data=has_data,
            export_file=str(export_path),
        )
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'


@settings_bp.route("/settings/storage-status")
@require_auth
def settings_storage_status():
    """Storage backend status panel for Settings page."""
    try:
        cfg = get_runtime().config.get().get("storage", {})
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
        return render_page(
            "admin/panels/storage_status.html",
            backend=backend,
            db_exists=db_exists,
            db_size=db_size,
            json_mb=json_mb,
            json_files=len(json_files),
        )
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'


@settings_bp.route("/settings/plugin-status")
@require_auth
def settings_plugin_status():
    """Plugin system status panel for Settings page."""
    try:
        pm = current_app.extensions.get("anteumbra.plugin_manager")
        if pm is None:
            return render_page(
                "admin/panels/plugin_status.html",
                enabled=False,
                plugins=[],
                detector_count=0,
                notifier_count=0,
                source_count=0,
            )
        plugins = pm.list_all()
        detector_count = len(pm.detectors)
        notifier_count = len(pm.notifiers)
        source_count = len(pm.event_sources)
        return render_page(
            "admin/panels/plugin_status.html",
            enabled=pm.is_enabled,
            plugins=plugins,
            detector_count=detector_count,
            notifier_count=notifier_count,
            source_count=source_count,
        )
    except Exception as e:
        return f'<div style="color:#ff4444;">Error: {e}</div>'
