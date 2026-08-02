"""Runtime capability assessment tests."""

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 support
    import tomli as tomllib


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_missing_yara_and_incomplete_notifications_are_degraded(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: None,
    )
    result = runtime_health_service.assess_runtime_capabilities(
        {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {
                "enabled": True,
                "email": {
                    "enabled": True,
                    "smtp_host": "smtp.example.test",
                    "username": "",
                },
            },
        }
    )

    assert result["status"] == "degraded"
    assert result["detection"]["mode"] == "emergency_only"
    assert result["notifications"]["mode"] == "local_only"
    assert result["notifications"]["incomplete_channels"] == ["email"]
    assert {warning["code"] for warning in result["warnings"]} == {
        "yara_unavailable",
        "notifier_local_only",
        "notifier_incomplete",
    }


def test_yara_probe_import_error_is_optional_degradation(monkeypatch):
    from anteumbra.application import runtime_health_service

    def missing_module(_name):
        raise ModuleNotFoundError("No module named 'yara'")

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        missing_module,
    )
    result = runtime_health_service.assess_runtime_capabilities(
        {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {"enabled": False},
        }
    )

    assert result["status"] == "degraded"
    assert result["detection"]["mode"] == "emergency_only"
    assert {warning["code"] for warning in result["warnings"]} == {
        "yara_unavailable",
    }


def test_ready_external_channel_is_reported(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: object(),
    )
    result = runtime_health_service.assess_runtime_capabilities(
        {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {
                "enabled": True,
                "webhook": {"enabled": True, "url": "https://soc.example.test/hook"},
            },
        }
    )

    assert result["status"] == "healthy"
    assert result["detection"]["mode"] == "yara_and_emergency"
    assert result["notifications"]["configured_channels"] == ["webhook"]
    assert result["warnings"] == []


def test_disabled_notifications_are_an_explicit_local_mode(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: object(),
    )
    result = runtime_health_service.assess_runtime_capabilities(
        {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {"enabled": False},
        }
    )

    assert result["status"] == "healthy"
    assert result["notifications"] == {
        "enabled": False,
        "mode": "local_only",
        "configured_channels": [],
        "incomplete_channels": [],
    }


def test_enabled_siem_without_event_bridge_is_degraded(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: object(),
    )
    result = runtime_health_service.assess_runtime_capabilities(
        {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {"enabled": False},
            "siem": {"enabled": True},
            "plugins": {"enabled": False, "builtin": []},
        }
    )

    assert result["status"] == "degraded"
    assert result["siem"] == {"enabled": True, "event_bridge_ready": False}
    assert {warning["code"] for warning in result["warnings"]} == {
        "siem_event_bridge_missing",
    }


def test_enabled_siem_with_handler_is_healthy(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: object(),
    )
    result = runtime_health_service.assess_runtime_capabilities(
        {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {"enabled": False},
            "siem": {"enabled": True},
            "plugins": {
                "enabled": True,
                "builtin": ["siem_handler"],
                "siem_handler": {"enabled": True},
            },
        }
    )

    assert result["status"] == "healthy"
    assert result["siem"] == {"enabled": True, "event_bridge_ready": True}


def test_runtime_and_package_config_templates_stay_in_sync(monkeypatch):
    from anteumbra.application import runtime_health_service

    runtime_template = REPOSITORY_ROOT / "config.toml"
    package_template = REPOSITORY_ROOT / "src" / "anteumbra" / "config.toml"
    assert runtime_template.read_text(encoding="utf-8") == package_template.read_text(
        encoding="utf-8"
    )

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: object(),
    )
    config = tomllib.loads(package_template.read_text(encoding="utf-8"))
    result = runtime_health_service.assess_runtime_capabilities(config)

    assert result["status"] == "healthy"
    assert result["siem"] == {"enabled": True, "event_bridge_ready": True}


def test_system_health_keeps_optional_degradation_at_http_200(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: None,
    )
    result = runtime_health_service.assess_system_health(
        config_loader=lambda: {"scanner": {"yara": {"enabled": True}}},
        wal_probe=lambda: None,
        registry_probe=lambda: None,
    )

    assert result["status"] == "degraded"
    assert result["http_status"] == 200
    assert result["checks"] == {"config": "ok", "wal": "ok", "registry": "ok"}
    assert result["errors"] == {}


def test_system_health_reports_critical_probe_failure_as_503(monkeypatch):
    from anteumbra.application import runtime_health_service

    monkeypatch.setattr(
        runtime_health_service.importlib.util,
        "find_spec",
        lambda _name: object(),
    )

    def broken_registry():
        raise OSError("registry unavailable")

    result = runtime_health_service.assess_system_health(
        config_loader=lambda: {
            "scanner": {"yara": {"enabled": True}},
            "notifier": {"enabled": False},
        },
        wal_probe=lambda: None,
        registry_probe=broken_registry,
    )

    assert result["status"] == "degraded"
    assert result["http_status"] == 503
    assert result["checks"]["registry"] == "error"
    assert result["errors"] == {"registry": "registry unavailable"}
