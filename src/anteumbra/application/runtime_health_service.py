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
        "warnings": warnings,
    }


def assess_system_health(
    *,
    config_loader: Callable[[], Mapping[str, Any]] | None = None,
    wal_probe: Callable[[], Any] | None = None,
    registry_probe: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Assess critical runtime dependencies and optional capabilities."""
    if config_loader is None:
        from anteumbra.application.config_service import load_config

        config_loader = load_config
    if wal_probe is None:
        from anteumbra.application.wal_service import get_wal_info

        wal_probe = get_wal_info
    if registry_probe is None:
        from anteumbra.application.registry_service import get_all

        registry_probe = lambda: get_all(include_deleted=False)

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
