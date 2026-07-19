"""Runtime capability assessment shared by CLI, launcher, and web health views."""

from __future__ import annotations

import importlib.util
from collections.abc import Callable, Mapping
from typing import Any


def assess_runtime_capabilities(config: Mapping[str, Any]) -> dict[str, Any]:
    scanner_config = config.get("scanner", {})
    yara_config = scanner_config.get("yara", {}) if isinstance(scanner_config, Mapping) else {}
    yara_enabled = bool(yara_config.get("enabled", False))
    try:
        yara_available = importlib.util.find_spec("yara") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        yara_available = False

    notifier_config = config.get("notifier", {})
    if not isinstance(notifier_config, Mapping):
        notifier_config = {}
    notifier_enabled = bool(notifier_config.get("enabled", False))

    configured_channels: list[str] = []
    incomplete_channels: list[str] = []
    if notifier_enabled:
        validators = {
            "wechat": _wechat_ready,
            "email": _email_ready,
            "webhook": _webhook_ready,
        }
        for name, validator in validators.items():
            channel = notifier_config.get(name, {})
            if not isinstance(channel, Mapping) or not channel.get("enabled", False):
                continue
            if validator(channel):
                configured_channels.append(name)
            else:
                incomplete_channels.append(name)

    warnings: list[dict[str, str]] = []
    if yara_enabled and not yara_available:
        warnings.append({
            "code": "yara_unavailable",
            "message": "YARA scanning is enabled but yara-python is not installed; emergency signatures only.",
        })
    if notifier_enabled and not configured_channels:
        warnings.append({
            "code": "notifier_local_only",
            "message": "No external notification channel is ready; alerts are recorded in local logs only.",
        })
    if incomplete_channels:
        warnings.append({
            "code": "notifier_incomplete",
            "message": "Enabled notification channels are missing required credentials: "
            + ", ".join(sorted(incomplete_channels)),
        })

    siem_config = config.get("siem", {})
    if not isinstance(siem_config, Mapping):
        siem_config = {}
    siem_enabled = bool(siem_config.get("enabled", False))
    plugins_config = config.get("plugins", {})
    if not isinstance(plugins_config, Mapping):
        plugins_config = {}
    builtin_plugins = plugins_config.get("builtin", [])
    if isinstance(builtin_plugins, str):
        builtin_plugins = [builtin_plugins]
    siem_handler_config = plugins_config.get("siem_handler", {})
    if not isinstance(siem_handler_config, Mapping):
        siem_handler_config = {}
    siem_bridge_ready = bool(
        plugins_config.get("enabled", False)
        and "siem_handler" in builtin_plugins
        and siem_handler_config.get("enabled", True)
    )
    if siem_enabled and not siem_bridge_ready:
        warnings.append({
            "code": "siem_event_bridge_missing",
            "message": "SIEM export is enabled but the siem_handler event bridge is disabled; file detections will stay local.",
        })

    return {
        "status": "degraded" if warnings else "healthy",
        "detection": {
            "yara_enabled": yara_enabled,
            "yara_available": yara_available,
            "mode": "yara_and_emergency" if yara_enabled and yara_available else "emergency_only",
        },
        "notifications": {
            "enabled": notifier_enabled,
            "mode": "external" if configured_channels else "local_only",
            "configured_channels": sorted(configured_channels),
            "incomplete_channels": sorted(incomplete_channels),
        },
        "siem": {
            "enabled": siem_enabled,
            "event_bridge_ready": siem_bridge_ready,
        },
        "warnings": warnings,
    }


def assess_system_health(
    *,
    config_loader: Callable[[], Mapping[str, Any]],
    wal_probe: Callable[[], Any],
    registry_probe: Callable[[], Any],
) -> dict[str, Any]:
    """Assess explicitly supplied runtime dependencies and capabilities."""
    checks: dict[str, str] = {}
    errors: dict[str, str] = {}
    capabilities: dict[str, Any] | None = None

    try:
        config = config_loader()
        capabilities = assess_runtime_capabilities(config)
        checks["config"] = "ok"
    except Exception as exc:
        checks["config"] = "error"
        errors["config"] = str(exc)

    for name, probe in (("wal", wal_probe), ("registry", registry_probe)):
        try:
            probe()
            checks[name] = "ok"
        except Exception as exc:
            checks[name] = "error"
            errors[name] = str(exc)

    critical_failure = bool(errors)
    optional_degraded = bool(
        capabilities and capabilities.get("status") == "degraded"
    )
    return {
        "status": "degraded" if critical_failure or optional_degraded else "healthy",
        "http_status": 503 if critical_failure else 200,
        "checks": checks,
        "errors": errors,
        "capabilities": capabilities,
    }


def _wechat_ready(config: Mapping[str, Any]) -> bool:
    return bool(str(config.get("send_key", "")).strip())


def _email_ready(config: Mapping[str, Any]) -> bool:
    recipients = config.get("to_addrs", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    return all((
        str(config.get("smtp_host", "")).strip(),
        str(config.get("username", "")).strip(),
        str(config.get("password", "")).strip(),
        str(config.get("from_addr", "")).strip(),
        any(str(address).strip() for address in recipients),
    ))


def _webhook_ready(config: Mapping[str, Any]) -> bool:
    return bool(str(config.get("url", "")).strip())
