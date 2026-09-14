# -*- coding: utf-8 -*-
"""
v1.0.6: Settings Blueprint — extracted from admin_bp.py
Routes: /settings/* (11) + /siem/* (2)
"""

import json
import logging
import os
import re
import shutil
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import tomli_w
from flask import Blueprint, current_app, jsonify, render_template, request, session
from flask_babel import gettext

from anteumbra.cli.config_support import (
    load_toml_file,
    load_toml_value,
    set_dotted_value,
    validate_config_file,
    write_env_value,
    write_toml_file,
)
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.pages import render_page
from anteumbra.interfaces.web.runtime import get_runtime
from anteumbra.plugins.config_schema import (
    ConfigField,
    field_values_equal,
    has_builtin_schema,
    normalize_fields,
)

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
_MISSING = object()


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


def _coerce_config_value(key: str, new_val, current=_MISSING):
    """Coerce a submitted editor value using the field's current TOML type.

    The editor posts plain text, so the type cannot be recovered from the
    string alone: ``logging.symbols.success = "[MONITOR][START][SUCCESS]"``
    is a *string* that looks exactly like an array.  The value already in
    config.toml is therefore the authority:

    * the current value is an array/table -> the text must parse as TOML, so
      a truncated ``"["`` is still rejected instead of being stored (that
      guard is what stopped the allowed_ips lockout)
    * the current value is a scalar -> text that parses into an array/table
      is honoured as a type change, otherwise the text is kept verbatim
    """
    if isinstance(new_val, (bool, int, float, list, dict)):
        return new_val
    if not isinstance(new_val, str):
        raise ValueError(f"Unsupported value type for {key}: {type(new_val).__name__}")
    stripped = new_val.strip()
    current_is_container = isinstance(current, (list, dict))
    if stripped.startswith(("[", "{")):
        try:
            parsed = load_toml_value(stripped)
        except Exception as exc:
            if current_is_container:
                raise ValueError(
                    f"Invalid array/table value for {key} (TOML parse failed): {stripped!r}"
                ) from exc
            return stripped
        if isinstance(parsed, (list, dict)):
            return parsed
        if current_is_container:
            return parsed
        return stripped
    if current_is_container:
        raise ValueError(f"Value for {key} must stay an array/table (got {stripped!r})")
    if stripped.lower() in ("true", "false"):
        return stripped.lower() == "true"
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


_MISSING = object()


def _get_dotted(config: dict, dotted_key: str):
    """Return the current value for a dotted key, or ``_MISSING`` when unset."""
    target = config
    for part in dotted_key.split("."):
        if not isinstance(target, dict) or part not in target:
            return _MISSING
        target = target[part]
    return target


def _siem_exporter():
    return get_runtime().siem_exporter


# -- Settings page structure -------------------------------------------------
#
# The page grew one card at a time until it was a single wall an operator had to
# scroll to reach "where do I put the mail password".  Sections are now ordered
# by importance with the secrets first, every one of them collapsible, and each
# header carries a one-line state summary so the page can be read without
# expanding anything.
#
# Expansion state lives in the query string ("?open=a,b"), which the section
# headers push into the address bar, and is mirrored into the session so coming
# back through the sidebar lands on the same sections.  Both mechanisms are
# server-rendered: no script has to run for the page to remember.

SETTINGS_SECTIONS: tuple[str, ...] = (
    "environment",
    "account",
    "sites",
    "detection",
    "notifications",
    "storage",
    "plugins",
    "advanced",
)

#: Only the first section is open on a first visit.
DEFAULT_OPEN_SECTIONS: tuple[str, ...] = ("environment",)

#: ``.env`` variables the environment section edits: the credentials, tokens and
#: keys an operator needs to finish a deployment.  ``ANTEUMBRA_PASSWORD_HASH`` is
#: displayed read-only (the account panel owns the password) and
#: ``ANTEUMBRA_SECRET_KEY`` is deliberately absent - rotating it silently signs
#: every session out, which is not a side effect a "save" button may have.
ENVIRONMENT_KEYS: tuple[str, ...] = (
    "ANTEUMBRA_EMAIL_USERNAME",
    "ANTEUMBRA_EMAIL_PASSWORD",
    "ANTEUMBRA_EMAIL_FROM",
    "ANTEUMBRA_EMAIL_TO",
    "ANTEUMBRA_WECHAT_API_KEY",
    "ANTEUMBRA_WAF_API_KEY",
    "ANTEUMBRA_WEBHOOK_SECRET",
)

# -- Readability filters ------------------------------------------------------
#
# The page is long and its values gave no clue which of the three possible
# sources was actually in effect.  Two server-side filters answer the question an
# operator actually asks ("what did I change here?"), and the jump-to-section
# control is a plain link list, so all of it works without a script and lands in
# the address bar like the expansion state already does.

#: ``?only=`` values the page understands.  ``changed`` compares every value
#: against the built-in default the plugin or runtime falls back to; ``shipped``
#: compares against the value in the config.toml template this deployment was
#: created from, which is the stricter question.
SETTINGS_FILTERS: tuple[str, ...] = ("all", "changed", "shipped")

DEFAULT_SETTINGS_FILTER = "all"

#: Filter labels, keyed for the picker's own links.
SETTINGS_FILTER_LABELS: dict[str, str] = {
    "all": "All values",
    "changed": "Only non-default values",
    "shipped": "Only changed from shipped defaults",
}

#: Which config.toml keys belong to which page section, so a section header can
#: report how many of its values differ from the shipped defaults.  Keys are
#: dotted and absolute; a key absent from both the live config and the template
#: does not count.
SECTION_CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    "environment": (),
    "account": ("web_admin.username", "web_admin.password_hash"),
    "sites": (
        "website.name",
        "website.id",
        "website.path",
        "website.port",
        "website.enabled",
        "website.log_config.log_monitor_enabled",
        "website.log_config.access_log_path",
    ),
    "detection": (
        "paths.monitor_paths",
        "paths.monitor_extensions",
        "quarantine.auto_quarantine_enabled",
        "quarantine.quarantine_dir",
        "quarantine.retention_days",
        "ip_blocker.auto_block_enabled",
        "ip_blocker.block_threshold",
        "ip_blocker.block_duration_minutes",
        "ip_blocker.devices",
        "waf_source.enabled",
        "waf_source.type",
        "waf_source.url",
    ),
    "notifications": (
        "notifier.enabled",
        "notifier.email.enabled",
        "notifier.wechat.enabled",
        "notifier.webhook.enabled",
    ),
    "storage": ("storage.backend", "storage.db_path", "paths.data_dir", "paths.log_dir"),
    "advanced": ("siem.enabled", "siem.format", "logging.level"),
}


# -- Dangerous keys -----------------------------------------------------------
#
# These four keys are the ones where a plausible-looking edit removes a
# protection instead of adding a feature: an admin can lock themselves out, stop
# containment, or downgrade session cookies on a proxied deployment.  They carry
# a one-line explanation wherever the settings page shows them, and the plugin
# form refuses to apply ``allowed_ips`` without an explicit acknowledgement.

DANGEROUS_KEYS: dict[str, str] = {
    "quarantine.auto_quarantine_enabled": (
        "Switching this off stops every automatic quarantine: detections are still "
        "recorded and alerted, but no file is moved again."
    ),
    "ip_blocker.auto_block_enabled": (
        "Switching this off stops automatic IP blocking. Records and alerts continue; "
        "repeat offenders are no longer contained."
    ),
    "ip_blocker.devices": (
        "Each entry defines a device the blocker writes to. A wrong or missing device "
        "means the block is recorded but never enforced."
    ),
    "web_admin.allowed_ips": (
        "Only addresses in this list may open the admin UI. Removing the address you "
        "are connected from locks you out of the web interface."
    ),
    "web_admin.session_cookie_secure": (
        "Setting this to false sends the admin session cookie over plain HTTP; only do "
        "it for a deployment that is never reachable over the network."
    ),
}



def _read_env_values(config_path: Path) -> dict[str, str]:
    """Configured ``.env`` values, keyed by variable name."""
    env_vars: dict[str, str] = {}
    try:
        env_path = Path(config_path).parent / ".env"
        if not env_path.exists():
            return env_vars
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, value = stripped.split("=", 1)
                env_vars[key.strip()] = value.strip()
    except OSError:
        logger.debug("Failed to read .env for the settings page", exc_info=True)
    return env_vars


def _parse_open_sections(raw) -> list[str] | None:
    """Requested sections from ``?open=``; ``None`` when the parameter is absent."""
    if raw is None:
        return None
    requested = {part.strip() for part in str(raw).split(",")}
    return [name for name in SETTINGS_SECTIONS if name in requested]


def _open_sections() -> list[str]:
    """Which sections are expanded: the query string first, then the session."""
    requested = _parse_open_sections(request.args.get("open"))
    if requested is not None:
        session["settings_open_sections"] = requested
        return requested
    stored = session.get("settings_open_sections")
    if isinstance(stored, list):
        # An explicitly empty set is a real choice ("everything collapsed");
        # only a session that never saw the page falls back to the default.
        return [name for name in SETTINGS_SECTIONS if name in stored]
    return list(DEFAULT_OPEN_SECTIONS)


def _settings_filter() -> str:
    """Which readability filter is active: the query string, then the session.

    The plugin panel's own HTMX requests (configure, save) read the same value,
    so a form refresh cannot silently drop the filter the operator chose.
    """
    requested = request.args.get("only")
    if requested is not None:
        value = str(requested).strip().lower()
        if value in SETTINGS_FILTERS:
            session["settings_filter"] = value
            return value
        return DEFAULT_SETTINGS_FILTER
    stored = session.get("settings_filter")
    return stored if stored in SETTINGS_FILTERS else DEFAULT_SETTINGS_FILTER


def _settings_page_url(*, open_sections: list[str] | None = None, only: str | None = None) -> str:
    """A settings URL carrying an explicit pointer state.

    The default filter is left out of the URL rather than written as
    ``only=all``: the address bar stays short, and every existing bookmark or
    header link keeps the shape it had before the filters existed.
    """
    params = []
    if open_sections is not None:
        params.append("open=" + ",".join(open_sections))
    if only and only != DEFAULT_SETTINGS_FILTER:
        params.append("only=" + str(only))
    return "/admin/settings" + ("?" + "&".join(params) if params else "")


def _section_toggle_url(open_sections: list[str], section_id: str, only: str = "") -> str:
    """URL that re-renders the page with ``section_id`` flipped.

    The active filter rides along, because toggling a section must not silently
    reset which values the operator asked to see.
    """
    if section_id in open_sections:
        toggled = [name for name in open_sections if name != section_id]
    else:
        toggled = [*open_sections, section_id]
    ordered = [name for name in SETTINGS_SECTIONS if name in toggled]
    return _settings_page_url(
        open_sections=ordered,
        only=only if only in SETTINGS_FILTERS else None,
    )



def _enabled_website_count(config: Mapping) -> int:
    websites = config.get("website")
    if isinstance(websites, Mapping):
        return 1 if websites.get("enabled", True) else 0
    if isinstance(websites, list):
        return sum(
            1
            for site in websites
            if isinstance(site, Mapping) and site.get("enabled", True)
        )
    return 0


def _website_log_config(config: Mapping) -> Mapping:
    websites = config.get("website")
    if isinstance(websites, list):
        websites = next((site for site in websites if isinstance(site, Mapping)), {})
    if not isinstance(websites, Mapping):
        return {}
    log_config = websites.get("log_config", {})
    return log_config if isinstance(log_config, Mapping) else {}


def _settings_summaries(config_path: Path) -> dict[str, str]:
    """One-line current state per section, so nothing needs expanding to be read."""
    summaries = {name: "" for name in SETTINGS_SECTIONS}
    try:
        config = get_runtime().config.get()
    except Exception:
        logger.debug("Settings summaries without a runtime config", exc_info=True)
        return summaries
    if not isinstance(config, Mapping):
        return summaries

    env_values = _read_env_values(config_path)
    filled = sum(1 for value in env_values.values() if str(value).strip())
    mail_ready = bool(
        str(env_values.get("ANTEUMBRA_EMAIL_USERNAME", "")).strip()
        and str(env_values.get("ANTEUMBRA_EMAIL_PASSWORD", "")).strip()
    )
    summaries["environment"] = " · ".join(
        [
            gettext("%(count)s credentials set", count=filled),
            gettext("mail configured") if mail_ready else gettext("mail not configured"),
        ]
    )

    username = ""
    try:
        username = str(session.get("username") or "")
    except Exception:
        username = ""
    if not username:
        web_admin = config.get("web_admin", {})
        web_admin = web_admin if isinstance(web_admin, Mapping) else {}
        username = str(web_admin.get("username", "admin"))
    summaries["account"] = gettext("signed in as %(user)s", user=username)

    summaries["sites"] = gettext(
        "%(count)s site(s) enabled", count=_enabled_website_count(config)
    )

    paths = config.get("paths", {})
    paths = paths if isinstance(paths, Mapping) else {}
    watched = paths.get("monitor_paths") or paths.get("watch_paths") or []
    watched_count = len(watched) if isinstance(watched, (list, tuple)) else 0
    log_config = _website_log_config(config)
    log_enabled = bool(log_config.get("log_monitor_enabled"))
    summaries["detection"] = gettext(
        "%(count)s watched path(s)", count=watched_count
    ) + " · " + (
        gettext("access log on") if log_enabled else gettext("access log off")
    )

    notifier = config.get("notifier", {})
    notifier = notifier if isinstance(notifier, Mapping) else {}
    channels = [
        name
        for name in ("email", "wechat", "webhook")
        if isinstance(notifier.get(name), Mapping) and notifier[name].get("enabled")
    ]
    summaries["notifications"] = (
        gettext("%(count)s channel(s) enabled", count=len(channels))
        if channels
        else gettext("notifications off")
    )

    storage = config.get("storage", {})
    storage = storage if isinstance(storage, Mapping) else {}
    summaries["storage"] = gettext(
        "backend %(backend)s", backend=str(storage.get("backend", "json"))
    )

    try:
        manager = _plugin_panel_manager()
        if manager is None:
            summaries["plugins"] = gettext("plugin system not attached")
        else:
            rows = _plugin_rows(manager, _plugin_config_table(get_runtime()))
            summaries["plugins"] = gettext(
                "%(loaded)s loaded / %(total)s available",
                loaded=sum(1 for row in rows if row["loaded"]),
                total=len(rows),
            )
    except Exception:
        logger.debug("Plugin summary unavailable", exc_info=True)
        summaries["plugins"] = ""

    summaries["advanced"] = gettext("config file %(name)s", name=config_path.name)
    return summaries


def _site_rows(config: Mapping) -> list[dict]:
    """Website entries as the settings page renders them."""
    websites = config.get("website", [])
    if isinstance(websites, Mapping):
        websites = [websites]
    rows = []
    for site in websites if isinstance(websites, list) else []:
        if not isinstance(site, Mapping):
            continue
        log_config = site.get("log_config", {})
        log_config = log_config if isinstance(log_config, Mapping) else {}
        rows.append(
            {
                "name": str(site.get("name") or site.get("id") or site.get("site_id") or "?"),
                "path": str(site.get("path", "")),
                "port": site.get("port", ""),
                "enabled": bool(site.get("enabled", True)),
                "log_monitor_enabled": bool(log_config.get("log_monitor_enabled")),
                "access_log": str(log_config.get("access_log_path", "")),
            }
        )
    return rows


def _render_settings_page(**extra):
    """Render the settings page with its section state and live summaries."""
    config_path = Path(get_runtime().config.path)
    try:
        config = get_runtime().config.get()
    except Exception:
        config = {}
    config = config if isinstance(config, Mapping) else {}
    # A POST that re-renders the page may name the section the operator was
    # working in; the session remembers it, so the state survives the next load.
    override = extra.get("open_sections_override")
    if override:
        requested = [name for name in SETTINGS_SECTIONS if name in set(override)]
        session["settings_open_sections"] = requested
        open_sections = requested
    else:
        open_sections = _open_sections()
    active_filter = _settings_filter()

    paths = config.get("paths", {})
    paths = paths if isinstance(paths, Mapping) else {}
    watched = paths.get("monitor_paths") or paths.get("watch_paths") or []
    extensions = paths.get("monitor_extensions") or []
    log_config = _website_log_config(config)
    waf_source = config.get("waf_source", {})
    waf_source = waf_source if isinstance(waf_source, Mapping) else {}
    quarantine = config.get("quarantine", {})
    quarantine = quarantine if isinstance(quarantine, Mapping) else {}
    ip_blocker = config.get("ip_blocker", {})
    ip_blocker = ip_blocker if isinstance(ip_blocker, Mapping) else {}

    section_changes = _section_change_counts(config, config_path)
    plugin_config = _plugin_config_table(get_runtime())
    manager = _plugin_panel_manager()

    context = {
        "open_sections": open_sections,
        "section_toggle_urls": {
            name: _section_toggle_url(open_sections, name, active_filter)
            for name in SETTINGS_SECTIONS
        },
        "section_summaries": _settings_summaries(config_path),
        "section_change_counts": section_changes,
        "section_change_labels": {
            name: gettext("%(count)s changed") % {"count": count}
            if count
            else gettext("all defaults")
            for name, count in section_changes.items()
        },
        "active_filter": active_filter,
        "filter_labels": SETTINGS_FILTER_LABELS,
        "filter_urls": {
            name: _settings_page_url(open_sections=open_sections, only=name)
            for name in SETTINGS_FILTERS
        },
        "jump_urls": {
            name: _settings_page_url(
                open_sections=[*open_sections, name] if name not in open_sections else open_sections,
                only=active_filter,
            )
            + f"#settings-{name}"
            for name in SETTINGS_SECTIONS
        },
        "section_titles": {
            "environment": gettext("ENVIRONMENT & SECRETS"),
            "account": gettext("ACCOUNT"),
            "sites": gettext("SITE CONFIGURATION"),
            "detection": gettext("MONITORING & DETECTION"),
            "notifications": gettext("NOTIFICATIONS"),
            "storage": gettext("STORAGE & PATHS"),
            "plugins": gettext("PLUGINS"),
            "advanced": gettext("ADVANCED"),
        },
        "dangerous_keys": _dangerous_key_rows(config, _read_shipped_defaults(config_path)[0]),
        "env_vars": _read_env_values(config_path),
        "env_keys": ENVIRONMENT_KEYS,
        "env_notice": None,
        "config_path": str(config_path),
        "site_rows": _site_rows(config),
        "watched_paths": [str(item) for item in watched if str(item).strip()]
        if isinstance(watched, (list, tuple))
        else [],
        "monitored_extensions": [str(item) for item in extensions]
        if isinstance(extensions, (list, tuple))
        else [],
        "log_monitor_enabled": bool(log_config.get("log_monitor_enabled")),
        "access_log_path": str(log_config.get("access_log_path", "")),
        "auto_quarantine": bool(quarantine.get("auto_quarantine_enabled", True)),
        "auto_block": bool(ip_blocker.get("auto_block_enabled", False)),
        "waf_enabled": bool(waf_source.get("enabled")),
        "waf_type": str(waf_source.get("type", "")) or gettext("not configured"),
        "waf_url": str(waf_source.get("url", "")),
        # The plugin panel is an HTMX fragment, so it must be handed the same
        # filter and the same page state the page was rendered with.
        "plugin_panel_url": "/admin/settings/plugin-status"
        + (f"?only={active_filter}" if active_filter != DEFAULT_SETTINGS_FILTER else ""),
        "plugin_manager_present": manager is not None,
        "plugin_available_count": len(_plugin_rows(manager, plugin_config)) if manager else 0,
        "password_notice": None,
        # The advanced section owns the link to the full config editor page; the
        # environment section is the single place that edits .env.
        "advanced_editor_url": "/admin/config",
    }
    context.update(extra)
    return render_page("admin/settings.html", **context)


# -- Dangerous keys and section diffs -----------------------------------------


def _dangerous_key_rows(config: Mapping, shipped: Mapping) -> list[dict]:
    """The guarded keys with their current value, source and risk explanation.

    Deliberately read-only.  ``web_admin.allowed_ips`` and
    ``web_admin.session_cookie_secure`` are edited on the config editor page,
    which owns the full validation story for them; repeating that write path here
    would mean two places where an admin can lock themselves out.
    """
    rows: list[dict] = []
    for dotted, reason in DANGEROUS_KEYS.items():
        current = _get_dotted(config, dotted)
        source = gettext("config.toml")
        if current is _MISSING:
            current = _get_dotted(shipped, dotted)
            source = gettext("shipped default")
        if current is _MISSING:
            continue
        rows.append(
            {
                "key": dotted,
                "value": _display_value(current),
                "source": source,
                "reason": reason,
            }
        )
    return rows


def _section_change_counts(config: Mapping, config_path: Path) -> dict[str, int]:
    """How many values per section differ from the shipped defaults.

    Counted over the keys declared in ``SECTION_CONFIG_KEYS`` plus every
    ``[plugins.<name>]`` field that declares a schema, so the number in a section
    header is about values a reader can actually see on the page.
    """
    shipped, _ = _read_shipped_defaults(config_path)
    counts = {name: 0 for name in SETTINGS_SECTIONS}

    for section, keys in SECTION_CONFIG_KEYS.items():
        for dotted in keys:
            current = _get_dotted(config, dotted)
            baseline = _get_dotted(shipped, dotted)
            if current is _MISSING or baseline is _MISSING:
                continue
            if not field_values_equal(current, baseline):
                counts[section] += 1

    counts["plugins"] = len(_plugin_change_entries(config, config_path))
    return counts


def _plugin_change_entries(config: Mapping, config_path: Path) -> list[dict]:
    """Every plugin field whose effective value differs from its default.

    Used for the plugins section header count and for the "only changed" view of
    the panel, and computed from the same resolver the plugin forms use - a
    second implementation would drift from what the forms show.
    """
    manager = _plugin_panel_manager()
    plugin_config = _plugin_config_table(get_runtime())
    template_defaults, _ = _read_shipped_defaults(config_path)
    env_values = _read_env_values(config_path)
    entries: list[dict] = []

    builtin = _builtin_list(plugin_config)
    sections = {
        key
        for key, value in plugin_config.items()
        if isinstance(value, Mapping) and key != "builtin"
    }
    for name in sorted(set(builtin) | sections):
        section = _plugin_section_name(name)
        section_config = plugin_config.get(section)
        section_config = section_config if isinstance(section_config, Mapping) else {}
        template_section = {
            key.split(".", 1)[1]: value
            for key, value in template_defaults.items()
            if key.startswith(f"plugins.{section}.")
        }
        fields = _plugin_config_fields(
            manager, name, section, {**template_section, **section_config}
        )
        changed = []
        for field in fields:
            effective = _plugin_effective_value(
                field,
                live=section_config,
                template=template_section,
                env_values=env_values,
            )
            if effective["differs_from_default"]:
                changed.append(field.name)
        if changed:
            entries.append({"name": name, "section": section, "changed": changed})
    return entries


@settings_bp.route("/settings")
@require_auth
def settings_page():
    """v1.0.38: Settings -- ordered, collapsible sections with live state.

    The .env / mail / token editor is the first section: it is the one part of
    this page a new operator cannot finish without, and it used to sit at the
    bottom of the config editor, below every config.toml field.
    """
    try:
        return _render_settings_page()
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] settings failed: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


@settings_bp.route("/settings/environment/save", methods=["POST"])
@require_auth
def settings_environment_save():
    """Save the environment/secrets section through the CLI's ``.env`` writer.

    Only fields the operator actually filled in are written, so submitting the
    section cannot blank a credential that was configured elsewhere.  The
    response is the re-rendered page: the section keeps its values and shows the
    result inline, and a bad write is an inline error rather than a 500.
    """
    notice = None
    try:
        env_path = Path(get_runtime().config.path).parent / ".env"
        written = []
        for key in ENVIRONMENT_KEYS:
            raw = request.form.get(key)
            if raw is None:
                continue
            value = str(raw).strip()
            if not value:
                continue
            write_env_value(env_path, key, value)
            os.environ[key] = value
            written.append(key)
        try:
            get_runtime().config.reload()
        except Exception:
            logger.debug("Runtime config reload failed after .env save", exc_info=True)
        notice = {
            "level": "success" if written else "info",
            "text": gettext("%(count)s value(s) written to .env", count=len(written))
            if written
            else gettext("Nothing to save: every field was left empty."),
        }
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error(f"[SETTINGS] environment save failed: {exc}", exc_info=True)
        notice = {
            "level": "error",
            "text": gettext("Environment save failed: %(detail)s", detail=str(exc)),
        }
    try:
        return _render_settings_page(env_notice=notice)
    except Exception as exc:  # noqa: BLE001 - the page must still answer
        current_app.logger.error(f"[SETTINGS] settings re-render failed: {exc}", exc_info=True)
        return f'<div style="color:#ff4444;">Error: {exc}</div>'


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

        return render_page(
            "admin/panels/config_editor.html",
            sections=sections,
            sections_levels=levels,
            config_path=str(config_path),
            env_vars=_read_env_values(config_path),
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
                coerced = _coerce_config_value(
                    str(full_key), new_val, _get_dotted(raw, str(full_key))
                )
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


#: Minimum admin password length, matching ``anteumbra config password``.
MIN_ADMIN_PASSWORD_LENGTH = 6


@settings_bp.route("/settings/password/save", methods=["POST"])
@require_auth
def settings_password_save():
    """Set a new admin password by hashing it, never by storing text.

    ``web_admin.password_hash`` is a scrypt hash: it cannot be edited as text, and
    a form that offered the hash for editing would invite someone to paste a
    plaintext password into it.  This endpoint therefore takes a *new password*,
    hashes it with werkzeug exactly as ``anteumbra config password`` does, and
    writes only the hash to ``.env``.  The submitted plaintext is never echoed,
    logged, or stored.

    Re-renders the advanced section with an inline notice, so a failed write is
    reported where the operator typed it instead of as a 500.
    """
    notice = None
    try:
        password = str(request.form.get("new_password") or "")
        confirm = str(request.form.get("confirm_password") or "")
        if len(password) < MIN_ADMIN_PASSWORD_LENGTH:
            notice = _notice(
                "error",
                gettext(
                    "Password too short: at least %(count)s characters are required.",
                    count=MIN_ADMIN_PASSWORD_LENGTH,
                ),
            )
        elif confirm and confirm != password:
            notice = _notice("error", gettext("The two passwords do not match."))
        else:
            from werkzeug.security import generate_password_hash

            env_path = Path(get_runtime().config.path).parent / ".env"
            write_env_value(env_path, "ANTEUMBRA_PASSWORD_HASH", generate_password_hash(password))
            notice = _notice(
                "success",
                gettext(
                    "New password hash written to .env. Existing sessions stay signed in "
                    "until they expire; the next sign-in uses the new password."
                ),
            )
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error(f"[SETTINGS] password change failed: {exc}", exc_info=True)
        notice = _notice(
            "error",
            gettext("Changing the password failed: %(detail)s", detail=str(exc)),
        )
    try:
        return _render_settings_page(password_notice=notice, open_sections_override=("advanced",))
    except Exception as exc:  # noqa: BLE001 - the page must still answer
        current_app.logger.error(f"[SETTINGS] settings re-render failed: {exc}", exc_info=True)
        return f'<div style="color:#ff4444;">Error: {exc}</div>'


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
    except ValueError as e:
        # An unsupported format is a caller error, not a server fault.
        return jsonify({"success": False, "error": str(e)}), 400
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


def _plugin_section_name(name: str) -> str:
    """Return the ``[plugins.<name>]`` section a plugin reads its settings from.

    Adapters are registered under their package path (``waf_adapters.syslog_waf``)
    while the instance and its config section use the plugin's own name
    (``syslog_waf``), so the section is the last dotted segment.
    """
    return name.rsplit(".", 1)[-1] if name else ""


def _plugin_config_table(runtime) -> dict:
    """The ``[plugins]`` table of the current runtime configuration."""
    try:
        config = runtime.config.get()
    except Exception:
        logger.error("plugin config lookup failed", exc_info=True)
        return {}
    table = config.get("plugins", {}) if isinstance(config, Mapping) else {}
    return dict(table) if isinstance(table, Mapping) else {}


def _builtin_list(plugin_config: Mapping) -> list[str]:
    """``[plugins] builtin`` as a plain list of factory keys."""
    builtin = plugin_config.get("builtin") if isinstance(plugin_config, Mapping) else None
    return [str(item) for item in builtin] if isinstance(builtin, (list, tuple)) else []


def _plugin_panel_manager():
    """The plugin manager of the current app, when one was attached."""
    return current_app.extensions.get("anteumbra.plugin_manager")


# -- Per-plugin configuration forms ------------------------------------------
#
# The panel could switch a plugin on and off and nothing else, so SMTP hosts,
# webhook URLs, poll intervals, thresholds and cooldowns were reachable only by
# editing config.toml by hand.  Every installed plugin now renders a typed form
# for its own ``[plugins.<name>]`` section, and every field states its EFFECTIVE
# value and the SOURCE it came from (config.toml, .env, or the built-in default)
# - that single fact is what made the old page unreadable.
#
# The schema comes from the plugin itself where it can (``config_schema()``,
# resolved by ``PluginManager.plugin_config_schema``) and falls back to the keys
# present in the shipped config.toml and in the live section, so a plugin with no
# schema still gets real controls rather than nothing.

#: How many changed values a row may report before the header just says "many".
_SOURCE_LABELS: dict[str, str] = {
    "config": "config.toml",
    "env": ".env",
    "builtin": "built-in default",
}

#: Placeholder syntax ``infrastructure/config/loader.py`` resolves at load time.
_ENV_PLACEHOLDER_RE = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([\-?])([^}]*))?\}$"
)

#: A dotted-config key: plugin sections and field names both live in this space.
_PLUGIN_FIELD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: Config sections whose form may be written.  Only ``[plugins.<name>]`` is
#: editable here; see the endpoint docstrings for why the rest is not.
_PLUGIN_SECTION_PREFIX = "plugins."


def _shipped_config_path(config_path: Path, template: dict) -> Path:
    """Where this deployment's config.toml template lives.

    Three candidates, in order of how much they can be trusted:

    * a template beside the live file (``config.toml.example``, or the package's
      own ``config.toml`` when the live file sits one level deeper), which is what
      "shipped defaults" means for a source checkout;
    * the installed package's ``config.toml``, which is the template
      ``anteumbra config init`` copies;
    * nothing (``template`` stays empty), and the page then reports the built-in
      defaults only.

    A candidate is only accepted when it is a *different* file that actually
    parses and carries a ``[plugins]`` table, so a broken symlink or the live file
    itself can never be mistaken for the template.
    """
    candidates: list[Path] = []
    parent = config_path.parent
    candidates.extend([parent / "config.toml.example", parent / "config.example.toml"])
    try:
        import anteumbra

        package_config = Path(anteumbra.__file__).resolve().parent / "config.toml"
        candidates.append(package_config)
    except Exception:  # pragma: no cover - an unimportable package keeps defaults
        logger.debug("Package config.toml is unavailable for shipped defaults", exc_info=True)
    try:
        candidates.append(parent.parent / "config.toml")
    except Exception:  # pragma: no cover - a path with no parent
        pass

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved == config_path.resolve() or not candidate.is_file():
                continue
            data = load_toml_file(candidate)
        except Exception:
            continue
        if isinstance(data.get("plugins"), Mapping):
            return candidate
    return Path()


def _read_shipped_defaults(config_path: Path) -> tuple[dict, Path]:
    """``{dotted_key: value}`` for the shipped config.toml template.

    Read from the template rather than from the live file on purpose: the whole
    point of the "changed from shipped defaults" filter is to compare against the
    values the deployment *started* with, and the live file is what someone has
    been editing.
    """
    try:
        config_path = Path(config_path).resolve()
    except Exception:  # pragma: no cover - an unresolvable path has no template
        return {}, Path()
    try:
        raw = load_toml_file(config_path)
    except Exception:
        logger.debug("Shipped defaults unavailable: the live config is unreadable", exc_info=True)
        raw = {}
    template_path = _shipped_config_path(config_path, raw if isinstance(raw, dict) else {})
    if not template_path:
        return {}, Path()
    try:
        template = load_toml_file(template_path)
    except Exception:
        logger.debug("Shipped config template is unreadable", exc_info=True)
        return {}, Path()
    defaults: dict[str, object] = {}

    def walk(prefix: str, table: Mapping) -> None:
        for key, value in table.items():
            dotted = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, Mapping):
                walk(dotted, value)
            else:
                defaults[dotted] = value

    walk("", template if isinstance(template, Mapping) else {})
    return defaults, template_path


def _toml_inline(value) -> str:
    """One-line TOML for a value: what ``config.toml`` would say on one line."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    try:
        text = tomli_w.dumps({"v": value}).split("=", 1)[1].strip()
    except Exception:  # pragma: no cover - unusual TOML types
        return json.dumps(str(value), ensure_ascii=False)
    return " ".join(text.split())


def _env_placeholder(raw) -> tuple[str, bool, str]:
    """``(VAR_NAME, HAS_FALLBACK, FALLBACK)`` for a ``${VAR...}`` string value."""
    if not isinstance(raw, str):
        return "", False, ""
    match = _ENV_PLACEHOLDER_RE.match(raw.strip())
    if not match:
        return "", False, ""
    return match.group(1), match.group(2) == "-", match.group(3) or ""


def _display_value(value) -> str:
    """The text a form field shows for a value (never for a secret)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _env_var_is_set(env_values: Mapping[str, str], var_name: str) -> bool:
    """Whether ``.env`` or the process environment defines this variable."""
    if not var_name:
        return False
    if str(env_values.get(var_name, "")).strip():
        return True
    return str(os.environ.get(var_name, "")).strip() != ""


def _plugin_section(table: Mapping) -> Mapping:
    """The ``[plugins]`` table of a parsed config, or an empty mapping."""
    plugins = table.get("plugins") if isinstance(table, Mapping) else None
    return plugins if isinstance(plugins, Mapping) else {}


def _fallback_schema_fields(section: str, named: Mapping) -> list[ConfigField]:
    """Typed fields inferred from the keys a plugin's config section actually has.

    Used for a plugin that declares no ``config_schema()``: the keys in the
    shipped template come first (they describe what the plugin expected), then any
    extra key found in the live section, so an operator still gets real controls
    instead of a read-only row.  Types are inferred from the value, which is
    strictly better than text for the three cases that matter (boolean, number,
    container).
    """
    fields: list[ConfigField] = []
    seen: set[str] = set()
    for key in ("enabled",):
        if key in named and isinstance(named.get(key), bool):
            fields.append(ConfigField(name=key, type="toggle", default=False))
            seen.add(key)
    for key, value in named.items():
        key = str(key)
        if key in seen or key in {"builtin"}:
            continue
        if isinstance(value, bool):
            field = ConfigField(name=key, type="toggle", default=False)
        elif isinstance(value, int):
            field = ConfigField(name=key, type="number", default=value)
        elif isinstance(value, float):
            field = ConfigField(name=key, type="number", default=value)
        elif isinstance(value, (list, tuple)):
            field = ConfigField(name=key, type="list", default=list(value))
        elif isinstance(value, Mapping):
            continue  # nested tables are not rendered as one field
        else:
            field = ConfigField(name=key, type="text", default=str(value))
        fields.append(field)
        seen.add(key)
    return fields


def _plugin_config_fields(manager, name: str, section: str, named: Mapping) -> list[ConfigField]:
    """The fields a plugin's form renders: declared schema first, keys second."""
    declared = []
    if manager is not None:
        getter = getattr(manager, "plugin_config_schema", None)
        if callable(getter):
            try:
                declared = normalize_fields(getter(name))
            except Exception:  # noqa: BLE001 - the fallback below still renders a form
                logger.error("Plugin schema lookup failed for %s", name, exc_info=True)
    if not declared and has_builtin_schema(name):
        # The manager has no implementation for it in this build (or no manager is
        # attached), but the build still knows what the plugin's keys are.
        from anteumbra.plugins.config_schema import schema_for_module

        declared = normalize_fields(schema_for_module(name))
    if declared:
        return declared
    return _fallback_schema_fields(section, named)


def _plugin_effective_value(
    field: ConfigField,
    *,
    live: Mapping,
    template: Mapping,
    env_values: Mapping[str, str],
) -> dict:
    """Resolve one field's effective value, its source, and its two baselines.

    Precedence mirrors ``infrastructure/config/loader.py``: a ``${VAR}`` placeholder
    with the variable present resolves from ``.env``/the environment, otherwise the
    literal value in config.toml is used, and a key that is absent everywhere falls
    back to the default declared by the plugin itself.

    Two comparisons come out of it:

    * ``differs_from_default`` - the effective value is not the plugin's own
      built-in default.  This is what the "only non-default values" filter uses.
    * ``differs_from_shipped`` - the effective value is not what the shipped
      config.toml template says.  This is the stricter "did anybody change this"
      question, and it is reported separately because a key can legitimately be at
      its built-in default and still differ from the shipped file.
    """
    key = field.name
    in_template = key in template
    template_raw = template.get(key) if in_template else None
    in_live = key in live
    live_raw = live.get(key) if in_live else None

    placeholder_var, _, _ = _env_placeholder(template_raw)
    env_var = field.env_key or placeholder_var
    env_set = _env_var_is_set(env_values, env_var)
    # The runtime config has placeholders already resolved, so the effective value
    # for a non-secret field is simply what the runtime sees.
    effective = live_raw if in_live else (template_raw if in_template else field.default)

    source = "builtin"
    if field.type == "secret":
        source = "env" if env_set else "config"
    elif env_var:
        source = "env" if env_set else "builtin"
    elif in_live:
        source = "config"

    secret_set = False
    if field.type == "secret":
        secret_set = env_set or bool(str(effective or "").strip())
        shown_value = ""
    else:
        shown_value = _display_value(effective)

    return {
        "key": key,
        "type": field.type,
        "label": field.label or key,
        "description": field.description,
        "default": field.default,
        "default_text": _display_value(field.default),
        "raw": shown_value,
        "display": shown_value,
        "source": source,
        "source_label": gettext(_SOURCE_LABELS[source]),
        "env_var": env_var,
        "env_set": env_set,
        "secret_set": secret_set,
        "secret_original": bool(str(effective or "").strip()) if field.type == "secret" else False,
        "writable": _field_is_writable(field, env_var),
        "in_config": in_live,
        "in_template": in_template,
        "differs_from_default": not field_values_equal(effective, field.default),
        "differs_from_shipped": in_template
        and not field_values_equal(effective, template_raw),
        "min": field.min,
        "max": field.max,
        "step": "any" if _is_float_default(field.default) else "1",
        "choices": list(field.choices),
        "pattern": field.pattern,
        "pattern_hint": field.pattern_hint,
        "item_pattern": field.item_pattern,
        "item_pattern_hint": field.item_pattern_hint,
        "required": field.required,
        "restart_required": field.restart_required,
        "set": _display_value(effective).strip() != "",
    }


def _is_float_default(value) -> bool:
    return isinstance(value, float) and not float(value).is_integer()


def _field_is_writable(field: ConfigField, env_var: str = "") -> bool:
    """Whether a form may write this field.

    Everything except a secret is written to ``config.toml``.  A secret is written
    to ``.env`` only, and that needs a variable name: with neither ``env_key`` in
    the schema nor a ``${VAR}`` placeholder in the template there is nowhere to put
    it, and putting a credential into config.toml is exactly what this page must
    not do.
    """
    if field.type != "secret":
        return True
    return bool(field.env_key or env_var)


# -- Server-side field validation ---------------------------------------------
#
# The form marks problems before saving, but the endpoint is the authority: a
# rejected value is never written.  These rules are the same ones the input
# attributes express (min/max, choice list, pattern), which is why a field can
# report its error next to itself instead of as a generic failure.


def _coerce_plugin_field_value(field: ConfigField, raw) -> tuple[Any, str]:
    """Validate and type one submitted value. Returns ``(value, error)``.

    The error text is operator-facing and names the expected shape, so a rejected
    save explains itself without the operator reading the schema.
    """
    if field.type == "secret":
        value = "" if raw is None else str(raw).strip()
        if value == "" and field.required:
            return None, gettext("This value is required.")
        return value, ""

    if field.type == "toggle":
        if isinstance(raw, bool):
            return raw, ""
        text = str(raw if raw is not None else "").strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True, ""
        if text in {"0", "false", "no", "off", ""}:
            return False, ""
        return None, gettext("Expected a boolean (true or false).")

    if field.type == "number":
        text = str(raw if raw is not None else "").strip()
        if text == "":
            if field.required:
                return None, gettext("This value is required.")
            return None, gettext("Expected a number.")
        try:
            number: float = float(text)
        except ValueError:
            return None, gettext("Expected a number.")
        if field.min is not None and number < float(field.min):
            return None, gettext("Must be at least %(min)s.", min=field.min)
        if field.max is not None and number > float(field.max):
            return None, gettext("Must be at most %(max)s.", max=field.max)
        if _is_float_default(field.default) or not float(number).is_integer():
            return number, ""
        return int(number), ""

    # text, select and list share the same text handling below.
    text = str(raw if raw is not None else "").strip()

    if field.type == "select":
        if text not in field.choices:
            return None, gettext(
                "Must be one of: %(choices)s.", choices=", ".join(field.choices)
            )
        return text, ""

    if field.type == "list":
        if text in ("", "[]"):
            items: list[str] = []
        elif text.startswith("["):
            try:
                parsed = json.loads(text)
            except ValueError:
                return None, gettext("Expected a list, for example a, b, c.")
            if not isinstance(parsed, list):
                return None, gettext("Expected a list, for example a, b, c.")
            items = [str(item).strip() for item in parsed if str(item).strip()]
        else:
            items = [part.strip() for part in re.split(r"[,\n]", text) if part.strip()]
        if not items and field.required:
            return None, gettext("At least one value is required.")
        if field.item_pattern:
            for item in items:
                if not re.fullmatch(field.item_pattern, item):
                    return None, gettext(
                        "Every entry must be %(hint)s: %(item)s",
                        hint=field.item_pattern_hint or gettext("valid"),
                        item=item,
                    )
        return items, ""

    if text == "":
        if field.required or not field.allow_empty:
            return None, gettext("This value is required.")
        return "", ""
    if field.pattern and not re.fullmatch(field.pattern, text):
        return None, gettext(
            "Expected %(hint)s.", hint=field.pattern_hint or gettext("a different format")
        )
    return text, ""


def _plugin_key(rows: Mapping, name: str) -> str:
    """Resolve a submitted plugin name to the inventory key it belongs to.

    The panel offers dotted names (``waf_adapters.syslog_waf``) while a form may
    be posted with the config section name (``syslog_waf``) - both mean the same
    row, and a save that could not find it would re-render the wrong panel and
    hide the very error it was reporting.
    """
    if name in rows:
        return name
    for key, row in rows.items():
        if row.get("section") == name or key.rsplit(".", 1)[-1] == name:
            return key
    return ""


def _plugin_form_context(
    name: str,
    *,
    manager,
    plugin_config: Mapping,
    notices: list[dict] | None = None,
    errors: Mapping | None = None,
    filter_name: str = DEFAULT_SETTINGS_FILTER,
) -> dict:
    """Everything ``admin/panels/plugin_config_form.html`` renders."""
    section = _plugin_section_name(name)
    runtime = get_runtime()
    try:
        config_path = Path(runtime.config.path)
    except Exception:
        config_path = Path("config.toml")
        logger.debug("Plugin form without a resolvable config path", exc_info=True)

    template_defaults, template_path = _read_shipped_defaults(config_path)
    env_values = _read_env_values(config_path)
    section_config = plugin_config.get(section) if isinstance(plugin_config, Mapping) else None
    section_config = section_config if isinstance(section_config, Mapping) else {}
    template_section = {
        key.split(".", 1)[1]: value
        for key, value in template_defaults.items()
        if key.startswith(f"plugins.{section}.")
    }

    fields = _plugin_config_fields(manager, name, section, {**template_section, **section_config})
    resolved = [
        _plugin_effective_value(
            field, live=section_config, template=template_section, env_values=env_values
        )
        for field in fields
    ]

    field_errors = dict(errors or {})
    secret_fields = [entry for entry in resolved if entry["type"] == "secret"]
    writable_secrets = [entry for entry in secret_fields if entry["writable"]]
    blocked_secrets = [entry for entry in secret_fields if not entry["writable"]]
    changed = [entry for entry in resolved if entry["differs_from_default"]]
    shown = [
        entry
        for entry in resolved
        if filter_name == "all"
        or (filter_name == "changed" and entry["differs_from_default"])
        or (filter_name == "shipped" and entry["differs_from_shipped"])
    ]

    form_notices = list(notices or [])
    if blocked_secrets:
        form_notices.append(
            _notice(
                "warning",
                gettext(
                    "%(fields)s has no .env variable name in this build, so it stays "
                    "read-only here. Set it in .env and reference it from config.toml.",
                    fields=", ".join(entry["label"] for entry in blocked_secrets),
                ),
            )
        )
    if any(entry["restart_required"] for entry in resolved):
        form_notices.append(
            _notice(
                "info",
                gettext(
                    "The plugin reads this section once, at activation: a saved value "
                    "takes effect after the plugin is reloaded or Anteumbra is restarted."
                ),
            )
        )

    return {
        "plugin_name": name,
        "plugin_section": section,
        "plugin_loaded": name in _loaded_plugin_names(manager),
        "plugin_installed": _plugin_is_installed(manager, name),
        "fields": shown,
        "field_count": len(resolved),
        "shown_count": len(shown),
        "changed_count": len(changed),
        "changed_fields": changed,
        "secret_count": len(writable_secrets),
        "secret_fields": writable_secrets,
        "has_schema": bool(fields),
        "filter_name": filter_name,
        "config_path": str(config_path),
        "template_path": str(template_path) if template_path else "",
        "errors": field_errors,
        "notices": form_notices,
        "form_url": "/admin/settings/plugins/config",
        "save_url": "/admin/settings/plugins/config/save",
        "panel_url": "/admin/settings/plugin-status",
    }


def _loaded_plugin_names(manager) -> set[str]:
    """Names (and short names) the running manager has registered."""
    if manager is None:
        return set()
    names: set[str] = set()
    try:
        entries = manager.list_all()
    except Exception:  # noqa: BLE001 - a broken manager must not break the form
        return names
    for entry in entries if isinstance(entries, (list, tuple)) else []:
        name = str((entry or {}).get("name") or "")
        if name:
            names.add(name)
            names.add(name.rsplit(".", 1)[-1])
    return names


def _plugin_is_installed(manager, name: str) -> bool:
    """Whether a fresh instance could be built in this process."""
    if manager is None:
        return False
    try:
        rows = manager.available_plugins()
    except Exception:  # noqa: BLE001 - presence is best-effort here
        return False
    return any(str(row.get("name")) == name and row.get("installed") for row in rows or [])




def _sync_plugin_config(manager, plugin_config: Mapping) -> None:
    """Let the manager see the ``[plugins]`` table that is on disk right now.

    ``available_plugins()`` reports what the manager read at startup, so a plugin
    added to ``[plugins] builtin`` - or switched off in its own section - by an
    edit elsewhere would stay invisible here until a restart.  The inventory is
    the operator's answer to "is this plugin installed?", so it reads the live
    table instead of a snapshot.
    """
    if manager is None or not isinstance(plugin_config, Mapping):
        return
    apply_config = getattr(manager, "apply_plugin_config", None)
    if not callable(apply_config):
        return
    try:
        apply_config(plugin_config)
    except Exception:  # noqa: BLE001 - the panel still renders from the snapshot
        logger.debug("Plugin manager refused the refreshed plugin config", exc_info=True)


def _event_source_state(manager, name: str) -> bool | None:
    """Whether a loaded EventSource reports itself as running.

    ``None`` means "not answerable" - either the plugin is not an event source,
    or its ``is_running`` is unavailable.  The panel prints that as unknown
    rather than inventing a state it never observed.
    """
    sources = getattr(manager, "event_sources", None)
    if not isinstance(sources, Mapping):
        return None
    source = sources.get(name)
    if source is None:
        return None
    probe = getattr(source, "is_running", None)
    if not callable(probe):
        return None
    try:
        return bool(probe())
    except Exception:  # noqa: BLE001 - a broken probe must not break the panel
        return None


def _plugin_rows(manager, plugin_config, *, filter_name: str = DEFAULT_SETTINGS_FILTER) -> list[dict]:
    """Build the plugin inventory: what is loaded plus what could be loaded.

    ``list_all()`` answers "what is running"; the inventory answers "what is
    there and why is it not running", which is the question an operator has when
    an adapter they configured never shows up in the UI.

    Each row carries one effective ``state`` plus every fact behind it, so the
    panel can answer "is this plugin actually installed and working?" without
    the operator reading a log: loaded/active, whether an EventSource is really
    running, the config section the plugin reads, and - only for loaded rows -
    the ``enabled`` value found there.  A row also carries the plugin's declared
    settings count and how many of them differ from their defaults, which is what
    the ``?only=`` filter in the settings page narrows the panel down to.
    """
    loaded_by_name = {}
    try:
        for entry in manager.list_all():
            loaded_by_name[str(entry.get("name") or "")] = entry
    except Exception:
        logger.error("plugin list_all() failed", exc_info=True)

    available = getattr(manager, "available_plugins", None)
    inventory = []
    if callable(available):
        try:
            inventory = [item for item in available() or [] if isinstance(item, Mapping)]
        except Exception:
            logger.error("plugin inventory failed", exc_info=True)
    if not inventory:
        # Older managers only report what is already loaded; render that rather
        # than an empty panel.
        inventory = [
            {
                "name": name,
                "loaded": True,
                "installed": True,
                "in_builtin": True,
                "enabled": True,
                "version": entry.get("version"),
                "type": entry.get("type"),
                "events": entry.get("events") or [],
            }
            for name, entry in loaded_by_name.items()
        ]

    builtin_names = _builtin_list(plugin_config)
    system_enabled = bool(getattr(manager, "is_enabled", False))

    # Schema and change counts are computed once per section, from the same
    # resolver the configuration forms use, so a row's "N changed" and the form it
    # opens can never disagree.  The shipped template is read once for the whole
    # inventory: doing it per row would re-parse config.toml per plugin.
    try:
        config_path = Path(get_runtime().config.path)
    except Exception:  # noqa: BLE001 - counts degrade to zero, the panel still renders
        logger.debug("Plugin panel without a resolvable config path", exc_info=True)
        config_path = Path("config.toml")
    try:
        shipped_defaults, _ = _read_shipped_defaults(config_path)
        env_values = _read_env_values(config_path)
    except Exception:  # noqa: BLE001 - see above
        shipped_defaults, env_values = {}, {}
    change_map: dict[str, list[str]] = {}
    fields_by_section: dict[str, list] = {}
    for item in inventory:
        section = _plugin_section_name(str(item.get("name") or ""))
        if section in fields_by_section:
            continue
        live_section = plugin_config.get(section) if isinstance(plugin_config, Mapping) else None
        live_section = live_section if isinstance(live_section, Mapping) else {}
        template_section = {
            key.split(".", 1)[1]: value
            for key, value in shipped_defaults.items()
            if key.startswith(f"plugins.{section}.")
        }
        try:
            fields = _plugin_config_fields(
                manager, str(item.get("name") or ""), section, {**template_section, **live_section}
            )
        except Exception:  # noqa: BLE001 - one broken plugin must not blank the panel
            logger.debug("Plugin fields unavailable for %s", section, exc_info=True)
            fields = []
        fields_by_section[section] = fields
        changed = []
        for field in fields:
            effective = _plugin_effective_value(
                field,
                live=live_section,
                template=template_section,
                env_values=env_values,
            )
            if effective["differs_from_default"]:
                changed.append(field.name)
        if changed:
            change_map[section] = changed

    rows = []
    for item in inventory:
        name = str(item.get("name") or "")
        if not name:
            continue
        section = _plugin_section_name(name)
        loaded_entry = loaded_by_name.get(name) or loaded_by_name.get(section)
        loaded = bool(item.get("loaded")) or loaded_entry is not None
        installed = bool(item.get("installed", True))
        in_builtin = bool(item.get("in_builtin", name in builtin_names))
        enabled = bool(item.get("enabled", True))
        section_config = plugin_config.get(section) if isinstance(plugin_config, Mapping) else None
        enabled_declared = isinstance(section_config, Mapping) and "enabled" in section_config
        if enabled_declared:
            enabled = bool(section_config.get("enabled"))

        reasons = []
        if not loaded:
            # Each reason is a separate, actionable fact: do not collapse
            # "switched off" and "not listed" into one vague "not loaded".
            if not system_enabled:
                reasons.append("system_off")
            if not installed:
                reasons.append("not_installed")
            if not in_builtin:
                reasons.append("not_listed")
            if not enabled:
                reasons.append("disabled")
            if system_enabled and installed and in_builtin and enabled:
                reasons.append("not_registered")

        # A row that is not loaded keeps its first (most actionable) reason as
        # the state; a loaded row takes its state from the run check below.
        state = reasons[0] if reasons else "not_registered"
        registered_name = item.get("registered_name")
        if loaded and registered_name is None and loaded_entry is not None:
            registered_name = str(loaded_entry.get("name") or "")
        event_source = bool(item.get("event_source")) or (
            bool(registered_name) and registered_name in (getattr(manager, "event_sources", None) or {})
        )
        running = item.get("running")
        if loaded and event_source and running is None:
            running = _event_source_state(manager, str(registered_name or section))
        if loaded:
            if not event_source:
                state = "active"
            elif running is True:
                state = "active"
            elif running is False:
                state = "inactive"
            else:
                state = "unverified"
        else:
            running = None

        snippet_lines = []
        plugin_table = []
        if not system_enabled:
            plugin_table.append("enabled = true")
        if not in_builtin:
            plugin_table.append("builtin = " + json.dumps(builtin_names + [name]))
        if plugin_table:
            snippet_lines = ["[plugins]", *plugin_table]
        if not enabled:
            if snippet_lines:
                snippet_lines.append("")
            snippet_lines += [f"[plugins.{section}]", "enabled = true"]

        guard_reason = _runtime_critical_reason(section) or _runtime_critical_reason(name)
        changed = change_map.get(section) or change_map.get(name) or []
        rows.append(
            {
                "name": name,
                "section": section,
                "loaded": loaded,
                "installed": installed,
                "in_builtin": in_builtin,
                "enabled": enabled,
                "enabled_declared": enabled_declared,
                # Only a loaded row may claim an enabled value: a plugin that is
                # not running is not "enabled", it is not there.
                "show_enabled": loaded,
                "version": (loaded_entry or {}).get("version") or item.get("version"),
                "type": (loaded_entry or {}).get("type") or item.get("type"),
                "events": (loaded_entry or {}).get("events") or item.get("events") or [],
                "reasons": reasons,
                "state": state,
                "event_source": event_source,
                "running": running,
                "registered_name": registered_name,
                "guard_reason": guard_reason,
                "snippet": "\n".join(snippet_lines),
                # Configuration: the plugin's own section is now editable from this
                # row, so it carries the field and change counts the form is about.
                "field_count": len(fields_by_section.get(section, [])),
                "changed_count": len(changed),
                "changed_fields": list(changed),
                "configurable": bool(fields_by_section.get(section)),
                "config_url": f"/admin/settings/plugins/config?plugin={name}&only={filter_name}",
            }
        )
    # Loaded plugins first: the interesting rows are the ones that are not.
    rows.sort(key=lambda row: (not row["loaded"], row["name"]))
    return rows


def _plugin_panel_context(
    manager,
    plugin_config,
    *,
    notices=None,
    focus_plugin="",
    filter_name: str = DEFAULT_SETTINGS_FILTER,
) -> dict:
    """Everything ``admin/panels/plugin_status.html`` renders."""
    _sync_plugin_config(manager, plugin_config)
    plugins = (
        _plugin_rows(manager, plugin_config, filter_name=filter_name) if manager is not None else []
    )
    changed_rows = [row for row in plugins if row["changed_count"]]
    # The "only changed from shipped defaults" filter on the settings page asks the
    # panel to show just the plugins that have anything to show at all; with no
    # such plugin the panel must say so rather than look empty.
    filter_note = ""
    if filter_name == "changed":
        filter_note = gettext(
            "%(changed)s of %(total)s plugins have values that differ from their defaults.",
            changed=len(changed_rows),
            total=len(plugins),
        )
    elif filter_name == "shipped":
        filter_note = gettext(
            "%(changed)s of %(total)s plugins have values that differ from the shipped "
            "config.toml defaults.",
            changed=len(changed_rows),
            total=len(plugins),
        )
    return {
        "enabled": bool(getattr(manager, "is_enabled", False)) if manager is not None else False,
        "manager_present": manager is not None,
        "plugins": plugins,
        "plugin_count": len(plugins),
        "loaded_count": sum(1 for row in plugins if row["loaded"]),
        "active_count": sum(1 for row in plugins if row["state"] == "active"),
        "detector_count": len(manager.detectors) if manager is not None else 0,
        "notifier_count": len(manager.notifiers) if manager is not None else 0,
        "source_count": len(manager.event_sources) if manager is not None else 0,
        "notices": list(notices or []),
        "focus_plugin": focus_plugin,
        "filter_name": filter_name,
        "filter_note": filter_note,
        "changed_plugin_count": len(changed_rows),
        "configured_count": sum(1 for row in plugins if row["configurable"]),
    }


@settings_bp.route("/settings/plugin-status")
@require_auth
def settings_plugin_status():
    """Plugin inventory panel for Settings page.

    ``?only=`` narrows the inventory the same way the settings page does, so the
    panel keeps the readability filter when it is re-rendered on its own.
    """
    try:
        pm = _plugin_panel_manager()
        plugin_config = _plugin_config_table(get_runtime())
        return render_page(
            "admin/panels/plugin_status.html",
            **_plugin_panel_context(pm, plugin_config, filter_name=_settings_filter()),
        )
    except Exception as e:
        current_app.logger.error(f"[SETTINGS] plugin status failed: {e}", exc_info=True)
        return f'<div style="color:#ff4444;">Error: {e}</div>'


# -- Plugin control: enable/disable and [plugins] builtin membership ---------
#
# The panel used to be read-only, which left the last mile of plugin debugging to
# hand-edited TOML plus a restart.  These handlers close that loop through the
# SAME config path the CLI uses (load -> set_dotted_value -> write -> validate)
# and then apply the change to the running runtime, saying so honestly whenever
# they cannot.


def _runtime_critical_reason(name: str) -> str:
    """Refusal reason for a plugin the runtime cannot operate without.

    This is a guard rail, not a permission check.  Switching ``notifier_handler``
    off stops alert delivery with no other visible symptom: the monitor still
    emits ``alert_requested``, the live log still shows the detection, and
    nothing in the UI turns red - the mail simply never arrives.  That silence is
    exactly what an operator cannot debug from a settings page, so the change is
    refused with the reason attached.
    """
    known = {
        "notifier_handler": gettext(
            "Runtime alerting is delivered by this plugin; switching it off would "
            "silently drop every alert."
        ),
    }
    return known.get(name, "")


def _config_backup_path(config_path: Path) -> Path:
    """A free, timestamped sibling path for a config backup."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = config_path.with_name(f"{config_path.name}.{stamp}.bak")
    index = 1
    while candidate.exists():
        candidate = config_path.with_name(f"{config_path.name}.{stamp}-{index}.bak")
        index += 1
    return candidate


def _write_config_values(config_path: Path, updates: Mapping) -> tuple[bool, str, str]:
    """Apply dotted updates the way ``anteumbra config set`` does.

    Returns ``(ok, error, backup_name)``.  A timestamped copy of config.toml is
    kept before it is replaced - this file is the runtime's only source of truth
    and an operator editing plugins from the UI has no other undo.  The candidate
    file is validated with the same validator the CLI uses, and only errors this
    write newly introduces block it, so saving into a config that already warns
    keeps working.
    """
    data = load_toml_file(config_path)
    for key, value in updates.items():
        set_dotted_value(data, str(key), value)
    tmp_path = config_path.with_name(config_path.name + ".tmp")
    try:
        write_toml_file(tmp_path, data)
        baseline_errors, _ = validate_config_file(config_path)
        candidate_errors, _ = validate_config_file(tmp_path)
        new_errors = [error for error in candidate_errors if error not in baseline_errors]
        if new_errors:
            return False, "; ".join(new_errors[:3]), ""
        backup = _config_backup_path(config_path)
        shutil.copy2(config_path, backup)
        os.replace(tmp_path, config_path)
        return True, "", backup.name
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            logger.debug("Failed to remove the config write scratch file", exc_info=True)


def _reload_runtime_config(runtime) -> str:
    """Reload the runtime config; returns "" on success, else the reason."""
    try:
        runtime.config.reload()
    except Exception as exc:  # noqa: BLE001 - reported to the operator, not raised
        logger.error("Config reload failed after a plugin change", exc_info=True)
        return str(exc) or exc.__class__.__name__
    return ""


def _apply_plugin_change_live(manager, *, action: str, row: Mapping) -> tuple[str, str]:
    """Apply one plugin mutation to the running runtime.

    Returns ``(outcome, detail)`` where outcome is ``live`` (the runtime already
    reflects the new state), ``restart`` (it cannot be applied without one) or
    ``failed`` (the attempt did not take).  Nothing here pretends: a plugin that
    refuses to activate is reported as a failure instead of a success.
    """
    if manager is None:
        return "restart", ""
    if not getattr(manager, "is_enabled", False):
        return "restart", ""
    try:
        if action in ("disable", "builtin_remove"):
            if not row.get("loaded"):
                return "live", ""  # already not running: nothing to unload
            target = str(row.get("registered_name") or row.get("section") or row.get("name"))
            return ("live", "") if manager.unregister(target) else ("failed", "")
        if row.get("loaded"):
            return "live", ""  # already registered
        return ("live", "") if manager.load_plugin(str(row.get("name"))) else ("failed", "")
    except Exception as exc:  # noqa: BLE001 - the panel reports it inline
        logger.error("Plugin live apply failed for %s", row.get("name"), exc_info=True)
        return "failed", str(exc) or exc.__class__.__name__


def _notice(level: str, text: str) -> dict:
    return {"level": level, "text": text}


def _plugin_action_notices(
    action: str,
    row: Mapping,
    *,
    outcome: str,
    detail: str,
    builtin_after: list[str],
    backup_name: str,
) -> list[dict]:
    """The operator-facing result of one plugin mutation."""
    name = str(row.get("name"))
    notices: list[dict] = []
    if outcome == "live":
        notices.append(
            _notice(
                "success",
                {
                    "disable": gettext(
                        "Switched off %(name)s: config.toml written and the plugin was "
                        "unloaded from the running runtime.",
                        name=name,
                    ),
                    "enable": gettext(
                        "Switched on %(name)s: config.toml written and the plugin was "
                        "registered in the running runtime.",
                        name=name,
                    ),
                    "builtin_add": gettext(
                        "Added %(name)s to [plugins] builtin and loaded it in the running runtime.",
                        name=name,
                    ),
                    "builtin_remove": gettext(
                        "Removed %(name)s from [plugins] builtin and unloaded it from the "
                        "running runtime.",
                        name=name,
                    ),
                }[action],
            )
        )
    elif outcome == "restart":
        reason = gettext("the plugin system is switched off in this process")
        if _plugin_panel_manager() is None:
            reason = gettext("no plugin manager is attached to this runtime")
        notices.append(
            _notice(
                "warning",
                gettext(
                    "Config written, but %(name)s could not be applied to the running runtime "
                    "(%(reason)s). A restart is required.",
                    name=name,
                    reason=reason,
                ),
            )
        )
    else:
        notices.append(
            _notice(
                "warning",
                gettext(
                    "Config written, but applying %(name)s to the running runtime failed: "
                    "%(detail)s A restart is required to pick the configuration up.",
                    name=name,
                    detail=detail or gettext("the plugin did not activate"),
                ),
            )
        )

    listed = name in builtin_after
    if action == "disable" and listed:
        notices.append(
            _notice(
                "info",
                gettext(
                    "Note: %(name)s is still listed in [plugins] builtin, so a restart loads it "
                    "again from there.",
                    name=name,
                ),
            )
        )
    if action == "enable" and not listed:
        notices.append(
            _notice(
                "info",
                gettext(
                    "Note: %(name)s is not listed in [plugins] builtin, so a restart will not "
                    "load it.",
                    name=name,
                ),
            )
        )
    if action == "builtin_remove":
        notices.append(
            _notice(
                "info",
                gettext(
                    "Note: %(name)s is no longer listed in [plugins] builtin, so a restart will "
                    "not load it.",
                    name=name,
                ),
            )
        )
    if backup_name:
        notices.append(
            _notice(
                "info",
                gettext("Backup kept: %(file)s", file=backup_name),
            )
        )
    return notices


def _run_plugin_action(runtime, manager, plugin_config: Mapping, row: Mapping, action: str):
    """Write one plugin mutation and apply it; returns the notices to render."""
    name = str(row["name"])
    section = str(row["section"])
    if action not in ("enable", "disable", "builtin_add", "builtin_remove"):
        return [_notice("error", gettext("Unsupported plugin action: %(action)s", action=action))]
    if action in ("enable", "builtin_add") and not row["installed"]:
        return [
            _notice(
                "error",
                gettext(
                    "%(name)s is listed in config.toml, but this build has no implementation "
                    "for it.",
                    name=name,
                ),
            )
        ]
    guard = _runtime_critical_reason(section) or _runtime_critical_reason(name)
    if guard and action in ("disable", "builtin_remove"):
        return [
            _notice(
                "error",
                gettext(
                    "Refused: %(name)s must stay switched on and listed in builtin. %(reason)s",
                    name=name,
                    reason=guard,
                ),
            )
        ]

    builtin_before = _builtin_list(plugin_config)
    if action == "disable":
        updates = {f"plugins.{section}.enabled": False}
    elif action == "enable":
        updates = {f"plugins.{section}.enabled": True}
    elif action == "builtin_add":
        if name in builtin_before:
            return [
                _notice(
                    "info",
                    gettext("%(name)s is already listed in [plugins] builtin.", name=name),
                )
            ]
        updates = {"plugins.builtin": [*builtin_before, name]}
    else:
        remaining = [item for item in builtin_before if item not in (name, section)]
        if remaining == builtin_before:
            return [
                _notice(
                    "info",
                    gettext("%(name)s is not listed in [plugins] builtin.", name=name),
                )
            ]
        updates = {"plugins.builtin": remaining}

    try:
        config_path = Path(runtime.config.path)
    except Exception:
        logger.error("Plugin change without a resolvable config path", exc_info=True)
        return [_notice("error", gettext("Configuration path is unavailable; nothing was written."))]

    try:
        ok, error, backup_name = _write_config_values(config_path, updates)
    except Exception as exc:  # noqa: BLE001 - a bad config must not become a 500
        logger.error("Plugin config write failed", exc_info=True)
        return [
            _notice(
                "error",
                gettext(
                    "Config write failed for %(name)s: %(detail)s",
                    name=name,
                    detail=str(exc) or exc.__class__.__name__,
                ),
            )
        ]
    if not ok:
        return [
            _notice(
                "error",
                gettext(
                    "Config write refused for %(name)s: %(detail)s",
                    name=name,
                    detail=error or gettext("validation failed"),
                ),
            )
        ]

    reload_error = _reload_runtime_config(runtime)
    plugin_config_after = _plugin_config_table(runtime)
    builtin_after = _builtin_list(plugin_config_after)
    if reload_error:
        return [
            _notice(
                "warning",
                gettext(
                    "Config written and the runtime reload failed (%(detail)s); the running "
                    "plugin state was left untouched. A restart is required.",
                    detail=reload_error,
                ),
            ),
            _notice("info", gettext("Backup kept: %(file)s", file=backup_name)),
        ]

    if manager is not None:
        try:
            # The fresh instance must activate with what is on disk now.
            manager.apply_plugin_config(plugin_config_after)
        except Exception:  # noqa: BLE001 - older managers may not expose this
            logger.debug("Plugin manager refused the refreshed plugin config", exc_info=True)

    outcome, detail = _apply_plugin_change_live(manager, action=action, row=row)
    return _plugin_action_notices(
        action,
        row,
        outcome=outcome,
        detail=detail,
        builtin_after=builtin_after,
        backup_name=backup_name,
    )


@settings_bp.route("/settings/plugins/control", methods=["POST"])
@require_auth
def settings_plugin_control():
    """Switch one plugin on/off, or move it in/out of ``[plugins] builtin``.

    The response is the re-rendered inventory, so the row an operator just
    changed comes back with its resulting state.  Every failure - unknown
    plugin, guard rail, invalid config, failed live apply - renders as an inline
    notice inside that panel instead of a 500, because a plugin that will not
    start is a normal operational outcome, not a server fault.
    """
    notices: list[dict] = []
    focus = ""
    try:
        action = str(request.form.get("action") or "").strip()
        plugin_key = str(request.form.get("plugin") or "").strip()
        manager = _plugin_panel_manager()
        runtime = get_runtime()
        plugin_config = _plugin_config_table(runtime)
        rows = {row["name"]: row for row in _plugin_rows(manager, plugin_config)}
        row = rows.get(plugin_key)
        if row is None:
            notices.append(
                _notice(
                    "error",
                    gettext("Unknown plugin: %(name)s", name=plugin_key or "?"),
                )
            )
        else:
            focus = plugin_key
            notices = _run_plugin_action(runtime, manager, plugin_config, row, action)
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error(f"[SETTINGS] plugin control failed: {exc}", exc_info=True)
        notices = [
            _notice(
                "error",
                gettext("Plugin control failed: %(detail)s", detail=str(exc)),
            )
        ]
    try:
        manager = _plugin_panel_manager()
        plugin_config = _plugin_config_table(get_runtime())
        return render_page(
            "admin/panels/plugin_status.html",
            **_plugin_panel_context(manager, plugin_config, notices=notices, focus_plugin=focus),
        )
    except Exception as exc:  # noqa: BLE001 - the panel itself must still answer
        current_app.logger.error(f"[SETTINGS] plugin panel render failed: {exc}", exc_info=True)
        return f'<div style="color:#ff4444;">Error: {exc}</div>'


# -- Plugin configuration: write the plugin's own section ---------------------
#
# Saving goes through the pipeline the plugin-control endpoint already uses:
# timestamped backup -> load_toml_file -> mutate -> write_toml_file ->
# validate_config_file with delta validation -> live apply.  Secrets never enter
# that path: they go to .env through ``write_env_value`` and the plugin keeps
# reading them through the ``${VAR}`` placeholder in config.toml, so the
# credential is never written to a file that documents itself as safe to commit.


def _write_env_values(env_path: Path, values: Mapping[str, str]) -> tuple[list[str], str]:
    """Write ``.env`` values one by one; returns ``(written_keys, error)``.

    ``write_env_value`` is the CLI's writer, so the file keeps its comments and
    unrelated variables.  A failure part-way is reported rather than hidden: the
    caller names the keys that did land.
    """
    written: list[str] = []
    for key, value in values.items():
        try:
            write_env_value(env_path, key, value)
            os.environ[key] = value
        except Exception as exc:  # noqa: BLE001 - reported inline, never a 500
            logger.error("Plugin secret write failed for %s", key, exc_info=True)
            return written, str(exc) or exc.__class__.__name__
        written.append(key)
    return written, ""


def _apply_plugin_section_live(manager, name: str) -> tuple[str, str]:
    """Reload one plugin so it re-reads its section; returns ``(outcome, detail)``.

    Only a plugin that is already registered is reloaded: unregistering and
    re-registering a *running* one is how a settings save would otherwise stop a
    working adapter to change an unrelated field.  A plugin that is not loaded
    picks the new values up through the normal activation path, and one that
    cannot be reloaded is reported as restart-required instead of as a success.
    """
    if manager is None:
        return "restart", gettext("no plugin manager is attached to this runtime")
    if not getattr(manager, "is_enabled", False):
        return "restart", gettext("the plugin system is switched off in this process")
    try:
        target = manager.loaded_name(name) or manager.loaded_name(
            _plugin_section_name(name)
        )
    except Exception:  # noqa: BLE001 - an older manager may not expose it
        target = None
    if not target:
        return "inactive", ""
    try:
        if not manager.unregister(target):
            return "inactive", ""
        if not manager.load_plugin(name):
            return "failed", gettext("the plugin did not activate")
    except Exception as exc:  # noqa: BLE001 - reported inline, never a 500
        logger.error("Plugin live reload failed for %s", name, exc_info=True)
        return "failed", str(exc) or exc.__class__.__name__
    return "live", ""


def _plugin_config_notices(
    name: str,
    *,
    changed_keys: list[str],
    secret_keys: list[str],
    backup_name: str,
    outcome: str,
    detail: str,
) -> list[dict]:
    """What an operator is told after saving one plugin's settings."""
    notices: list[dict] = []
    if changed_keys or secret_keys:
        if outcome == "live":
            notices.append(
                _notice(
                    "success",
                    gettext(
                        "Saved %(count)s value(s) for %(name)s and reloaded the plugin, so "
                        "the running runtime uses them now.",
                        count=len(changed_keys) + len(secret_keys),
                        name=name,
                    ),
                )
            )
        elif outcome == "inactive":
            notices.append(
                _notice(
                    "success",
                    gettext(
                        "Saved %(count)s value(s) for %(name)s. The plugin is not loaded right "
                        "now, so they apply the next time it activates.",
                        count=len(changed_keys) + len(secret_keys),
                        name=name,
                    ),
                )
            )
        elif outcome == "failed":
            notices.append(
                _notice(
                    "warning",
                    gettext(
                        "Saved %(count)s value(s) for %(name)s, but reloading the plugin "
                        "failed (%(detail)s). A restart is required; the previous instance "
                        "may have been unloaded.",
                        count=len(changed_keys) + len(secret_keys),
                        name=name,
                        detail=detail or gettext("the plugin did not activate"),
                    ),
                )
            )
        else:
            notices.append(
                _notice(
                    "warning",
                    gettext(
                        "Saved %(count)s value(s) for %(name)s to disk, but they could not be "
                        "applied to the running runtime (%(detail)s). A restart is required.",
                        count=len(changed_keys) + len(secret_keys),
                        name=name,
                        detail=detail,
                    ),
                )
            )
    if secret_keys:
        notices.append(
            _notice(
                "info",
                gettext(
                    "%(count)s secret(s) written to .env. Their values are never shown or "
                    "logged; the field only reports whether one is set.",
                    count=len(secret_keys),
                ),
            )
        )
    if backup_name:
        notices.append(_notice("info", gettext("Backup kept: %(file)s", file=backup_name)))
    return notices


def _plugin_config_save(runtime, manager, plugin_config: Mapping, name: str):
    """Validate, write and apply one plugin's submitted settings."""
    section = _plugin_section_name(name)
    if not section or not _PLUGIN_FIELD_RE.fullmatch(section):
        return [], {
            "form": gettext("Unknown plugin: %(name)s", name=name or "?"),
        }

    config_path = Path(runtime.config.path)
    template_defaults, _ = _read_shipped_defaults(config_path)
    env_values = _read_env_values(config_path)
    section_config = plugin_config.get(section) if isinstance(plugin_config, Mapping) else None
    section_config = section_config if isinstance(section_config, Mapping) else {}
    template_section = {
        key.split(".", 1)[1]: value
        for key, value in template_defaults.items()
        if key.startswith(f"plugins.{section}.")
    }
    fields = _plugin_config_fields(
        manager, name, section, {**template_section, **section_config}
    )
    if not fields:
        return [], {
            "form": gettext("%(name)s declares no settings this build can write.", name=name)
        }

    errors: dict[str, str] = {}
    config_updates: dict[str, Any] = {}
    secret_values: dict[str, str] = {}

    for field in fields:
        if field.type == "secret":
            # A submitted secret is write-only: an empty field means "leave the
            # stored value alone", which is also how the .env section behaves.
            raw = request.form.get(f"secret__{field.name}")
            if raw is None or str(raw).strip() == "":
                continue
            effective = _plugin_effective_value(
                field, live=section_config, template=template_section, env_values=env_values
            )
            env_key = field.env_key or str(effective.get("env_var") or "")
            if not env_key or not _PLUGIN_FIELD_RE.fullmatch(env_key):
                errors[field.name] = gettext(
                    "No .env variable is declared for this secret, so it cannot be "
                    "written safely from here."
                )
                continue
            value, error = _coerce_plugin_field_value(field, raw)
            if error:
                errors[field.name] = error
                continue
            secret_values[env_key] = str(value)
            continue

        form_key = f"field__{field.name}"
        if field.type == "toggle":
            raw = "true" if request.form.get(form_key) in ("1", "true", "on", "yes") else "false"
        else:
            if form_key not in request.form:
                continue  # a field the form did not render is not a field to blank
            raw = request.form.get(form_key)
        value, error = _coerce_plugin_field_value(field, raw)
        if error:
            errors[field.name] = error
            continue
        if not field_values_equal(value, section_config.get(field.name, _MISSING)):
            config_updates[f"plugins.{section}.{field.name}"] = value

    if errors:
        return [], errors

    if not config_updates and not secret_values:
        return [_notice("info", gettext("Nothing to save: every value is unchanged."))], {}

    backup_name = ""
    if config_updates:
        try:
            ok, error, backup_name = _write_config_values(config_path, config_updates)
        except Exception as exc:  # noqa: BLE001 - a bad config must not become a 500
            logger.error("Plugin config write failed for %s", name, exc_info=True)
            return [
                _notice(
                    "error",
                    gettext(
                        "Config write failed for %(name)s: %(detail)s",
                        name=name,
                        detail=str(exc) or exc.__class__.__name__,
                    ),
                )
            ], {}
        if not ok:
            return [
                _notice(
                    "error",
                    gettext(
                        "Config write refused for %(name)s: %(detail)s",
                        name=name,
                        detail=error or gettext("validation failed"),
                    ),
                )
            ], {}

    secret_keys: list[str] = []
    if secret_values:
        env_path = config_path.parent / ".env"
        secret_keys, secret_error = _write_env_values(env_path, secret_values)
        if secret_error:
            # The config half may already be on disk; say exactly how far it got.
            notices = [
                _notice(
                    "error",
                    gettext(
                        ".env write failed after %(written)s of %(total)s secret(s) were "
                        "stored (%(detail)s). Nothing else was changed.",
                        written=len(secret_keys),
                        total=len(secret_values),
                        detail=secret_error,
                    ),
                )
            ]
            return notices, {}

    reload_error = _reload_runtime_config(runtime)
    if reload_error:
        return [
            _notice(
                "warning",
                gettext(
                    "Config written and the runtime reload failed (%(detail)s); the running "
                    "plugin state was left untouched. A restart is required.",
                    detail=reload_error,
                ),
            ),
            _notice("info", gettext("Backup kept: %(file)s", file=backup_name)),
        ], {}

    plugin_config_after = _plugin_config_table(runtime)
    if manager is not None:
        try:
            # A fresh instance must activate with what is on disk now.
            manager.apply_plugin_config(plugin_config_after)
        except Exception:  # noqa: BLE001 - older managers may not expose this
            logger.debug("Plugin manager refused the refreshed plugin config", exc_info=True)
    outcome, detail = _apply_plugin_section_live(manager, name)

    notices = _plugin_config_notices(
        name,
        changed_keys=sorted(config_updates),
        secret_keys=secret_keys,
        backup_name=backup_name,
        outcome=outcome,
        detail=detail,
    )
    return notices, {}


@settings_bp.route("/settings/plugins/config")
@require_auth
def settings_plugin_config_form():
    """Render one plugin's typed configuration form.

    The form is fetched per plugin rather than rendered with every row: the
    memory-shell probe alone declares seventeen settings, and a page that renders
    every plugin's form at once is the long, unreadable page this work exists to
    fix.  An unknown plugin is still answered - with an inline error inside the
    form target - so the panel never replaces itself with a 500.
    """
    name = str(request.args.get("plugin") or "").strip()
    try:
        manager = _plugin_panel_manager()
        plugin_config = _plugin_config_table(get_runtime())
        if not name:
            notice = [_notice("error", gettext("No plugin was named."))]
            return render_page(
                "admin/panels/plugin_config_form.html",
                plugin_name="",
                plugin_section="",
                fields=[],
                notices=notice,
                errors={},
                filter_name=_settings_filter(),
                form_url="/admin/settings/plugins/config",
                save_url="/admin/settings/plugins/config/save",
                panel_url="/admin/settings/plugin-status",
                field_count=0,
                changed_count=0,
                secret_count=0,
                has_schema=False,
                config_path="",
                template_path="",
            )
        return render_page(
            "admin/panels/plugin_config_form.html",
            **_plugin_form_context(
                name,
                manager=manager,
                plugin_config=plugin_config,
                filter_name=_settings_filter(),
            ),
        )
    except Exception as exc:  # noqa: BLE001 - the form must still answer
        current_app.logger.error(f"[SETTINGS] plugin config form failed: {exc}", exc_info=True)
        return f'<div style="color:#ff4444;">Error: {exc}</div>'


@settings_bp.route("/settings/plugins/config/save", methods=["POST"])
@require_auth
def settings_plugin_config_save():
    """Save one plugin's own ``[plugins.<name>]`` section.

    Validation errors render back into the form next to the field that caused
    them, and nothing is written when any field is rejected.  A successful save
    reports whether the running runtime picked the values up or whether a restart
    is required - never both, and never a bare "saved".
    """
    name = str(request.form.get("plugin") or "").strip()
    errors: dict[str, str] = {}
    notices: list[dict] = []
    try:
        manager = _plugin_panel_manager()
        runtime = get_runtime()
        plugin_config = _plugin_config_table(runtime)
        rows = {row["name"]: row for row in _plugin_rows(manager, plugin_config)}
        resolved = _plugin_key(rows, name)
        if not resolved:
            notices = [_notice("error", gettext("Unknown plugin: %(name)s", name=name or "?"))]
        else:
            name = resolved
            notices, errors = _plugin_config_save(runtime, manager, plugin_config, name)
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error(f"[SETTINGS] plugin config save failed: {exc}", exc_info=True)
        notices = [
            _notice("error", gettext("Plugin control failed: %(detail)s", detail=str(exc)))
        ]
    filter_name = _settings_filter()

    # A field error keeps the operator in the form they were editing; a save that
    # went through re-renders the whole inventory, so the row comes back with its
    # resulting state (and the count of values that now differ from defaults).
    if not errors and name:
        try:
            manager = _plugin_panel_manager()
            plugin_config = _plugin_config_table(get_runtime())
            return render_page(
                "admin/panels/plugin_status.html",
                **_plugin_panel_context(
                    manager,
                    plugin_config,
                    notices=notices,
                    focus_plugin=name,
                    filter_name=filter_name,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - still answer the request
            current_app.logger.error(
                "[SETTINGS] plugin panel re-render failed: %s", exc, exc_info=True
            )
            return f'<div style="color:#ff4444;">Error: {exc}</div>'
    try:
        manager = _plugin_panel_manager()
        plugin_config = _plugin_config_table(get_runtime())
        rows = {row["name"]: row for row in _plugin_rows(manager, plugin_config)}
        if _plugin_key(rows, name):
            return render_page(
                "admin/panels/plugin_config_form.html",
                **_plugin_form_context(
                    name,
                    manager=manager,
                    plugin_config=plugin_config,
                    notices=notices,
                    errors=errors,
                    filter_name=filter_name,
                ),
            )
        return render_page(
            "admin/panels/plugin_status.html",
            **_plugin_panel_context(
                manager, plugin_config, notices=notices, focus_plugin=name, filter_name=filter_name
            ),
        )
    except Exception as exc:  # noqa: BLE001 - the page must still answer
        current_app.logger.error(f"[SETTINGS] plugin form re-render failed: {exc}", exc_info=True)
        return f'<div style="color:#ff4444;">Error: {exc}</div>'
