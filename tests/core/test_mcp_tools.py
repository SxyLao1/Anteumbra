"""MCP tool surface: shape, the write gate, redaction, and mutations.

The suite talks to the tools in-process, so it needs neither the optional MCP
SDK nor a client, and it never touches a real Anteumbra instance: every test
builds a throwaway instance directory in ``tmp_path``.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any, get_args, get_origin

import pytest

CONFIG_TEMPLATE = """
[website]
name = "shop"
id = "shop"
path = "__SITE__"
port = 8080
enabled = true

[website.scan_options]
exclude_dirs = ["cache"]

[web_admin]
host = "127.0.0.1"
port = 18080
username = "admin"
password_hash = "${ANTEUMBRA_PASSWORD_HASH:-}"

[security]
secret_key = "${ANTEUMBRA_SECRET_KEY:-}"

[storage]
backend = "json"
db_path = "data/anteumbra.db"

[paths]
data_dir = "data"
log_base_dir = "logs"

[notifier]
enabled = false

[notifier.wechat]
enabled = false
send_key = "${ANTEUMBRA_WECHAT_API_KEY:-}"

[notifier.email]
enabled = false
username = "${ANTEUMBRA_EMAIL_USERNAME:-}"
password = "${ANTEUMBRA_EMAIL_PASSWORD:-}"

[plugins.cloudflare]
api_token = "${CLOUDFLARE_API_TOKEN:-}"

[quarantine]
auto_quarantine_enabled = false

[ip_blocker]
enabled = true
auto_block_enabled = false
"""

ENV_TEMPLATE = """# throwaway instance for tests
ANTEUMBRA_PASSWORD_HASH=pbkdf2:sha256:600000$saltsalt$deadbeefdeadbeef
ANTEUMBRA_SECRET_KEY=secret-key-value-that-must-not-leak
ANTEUMBRA_EMAIL_USERNAME=alerts@example.com
ANTEUMBRA_EMAIL_PASSWORD=mail-authorization-code-must-not-leak
ANTEUMBRA_WECHAT_API_KEY=SCT-send-key-must-not-leak
CLOUDFLARE_API_TOKEN=cloudflare-token-must-not-leak
"""

SECRET_VALUES = (
    "pbkdf2:sha256:600000$saltsalt$deadbeefdeadbeef",
    "secret-key-value-that-must-not-leak",
    "mail-authorization-code-must-not-leak",
    "SCT-send-key-must-not-leak",
    "cloudflare-token-must-not-leak",
)


@pytest.fixture
def instance_dir(tmp_path: Path) -> Path:
    """A throwaway instance with one enabled site whose path exists."""
    site = tmp_path / "www" / "shop"
    site.mkdir(parents=True)
    (site / "index.jsp").write_text("<%-- served by the container --%>\n", encoding="utf-8")
    (tmp_path / "config.toml").write_text(
        CONFIG_TEMPLATE.replace("__SITE__", site.as_posix()), encoding="utf-8"
    )
    (tmp_path / ".env").write_text(ENV_TEMPLATE, encoding="utf-8")
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    return tmp_path


@pytest.fixture
def instance(instance_dir: Path):
    from anteumbra.mcp.instance import Instance

    return Instance(instance_dir)


def _tools(instance, *, allow_write: bool):
    from anteumbra.mcp.tools import build_tools

    return {bound.name: bound for bound in build_tools(instance, allow_write=allow_write)}


def _call(instance, tool: str, *, allow_write: bool, **arguments: Any) -> dict[str, Any]:
    from anteumbra.mcp.tools import call_tool

    return call_tool(instance, tool, arguments, allow_write=allow_write)


def _json_type(annotation: object) -> str:
    origin = get_origin(annotation)
    if origin is not None and type(None) in get_args(annotation):
        inner = [item for item in get_args(annotation) if item is not type(None)]
        assert len(inner) == 1, annotation
        return _json_type(inner[0])
    return {
        str: "string",
        int: "integer",
        bool: "boolean",
        float: "number",
    }[annotation]


# ── registration and shape ───────────────────────────────────


def test_declared_parameters_match_every_handler_signature(instance):
    for allow_write in (False, True):
        for bound in _tools(instance, allow_write=allow_write).values():
            signature = inspect.signature(bound.function)
            parameters = list(signature.parameters.values())
            assert [item.name for item in parameters] == [
                item.name for item in bound.spec.parameters
            ], bound.name
            annotations = inspect.get_annotations(bound.function, eval_str=True)
            for declared, real in zip(bound.spec.parameters, parameters, strict=True):
                assert _json_type(annotations[real.name]) == declared.type, (
                    f"{bound.name}.{declared.name}"
                )
                assert (real.default is inspect.Parameter.empty) == declared.required, (
                    f"{bound.name}.{declared.name}"
                )


def test_read_only_mode_does_not_expose_a_single_mutating_tool(instance):
    from anteumbra.mcp.tools import READ_ONLY_TOOLS

    tools = _tools(instance, allow_write=False)

    assert set(tools) == {spec.name for spec in READ_ONLY_TOOLS}
    assert not any(bound.spec.write for bound in tools.values())
    for name in ("add_site", "update_site", "disable_site", "set_config_value", "set_env_value"):
        assert name not in tools


def test_write_mode_adds_the_mutating_tools(instance):
    read_only = set(_tools(instance, allow_write=False))
    write = _tools(instance, allow_write=True)

    assert read_only < set(write)
    assert {name for name, bound in write.items() if bound.spec.write} == {
        "add_site",
        "update_site",
        "disable_site",
        "set_config_value",
        "set_env_value",
        # Available because this fixture is stopped and the plugin is enabled.
        "run_memory_shell_probe",
    }


def test_memory_shell_probe_is_absent_in_read_only_mode(instance):
    assert "run_memory_shell_probe" not in _tools(instance, allow_write=False)
    # It is a write tool: with write access and a stopped instance it appears.
    assert "run_memory_shell_probe" in _tools(instance, allow_write=True)


def test_memory_shell_probe_is_absent_when_the_plugin_is_disabled(instance_dir, instance):
    config = (instance_dir / "config.toml").read_text(encoding="utf-8")
    (instance_dir / "config.toml").write_text(
        config + '\n[plugins.memory_shell_probe]\nenabled = false\n', encoding="utf-8"
    )

    assert "run_memory_shell_probe" not in _tools(instance, allow_write=True)


def test_unknown_tools_and_arguments_are_rejected(instance):
    from anteumbra.mcp.tools import ToolError, call_tool

    with pytest.raises(ToolError, match="Unknown tool"):
        call_tool(instance, "no_such_tool", {})
    with pytest.raises(ToolError, match="Unexpected argument"):
        call_tool(instance, "get_status", {"verbose": True})
    with pytest.raises(ToolError, match="Missing required argument"):
        call_tool(instance, "add_site", {"name": "x", "port": 80}, allow_write=True)


# ── secrets ──────────────────────────────────────────────────


def test_get_config_redacts_every_credential(instance):
    result = _call(instance, "get_config", allow_write=False)
    serialized = json.dumps(result)

    for secret in SECRET_VALUES:
        assert secret not in serialized, secret
    config = result["config"]
    assert config["web_admin"]["password_hash"] == "***REDACTED***"
    assert config["security"]["secret_key"] == "***REDACTED***"
    assert config["notifier"]["wechat"]["send_key"] == "***REDACTED***"
    assert config["notifier"]["email"]["password"] == "***REDACTED***"
    assert config["plugins"]["cloudflare"]["api_token"] == "***REDACTED***"
    # Non-secret settings stay readable, or the tool would be useless.
    assert config["web_admin"]["port"] == 18080
    assert config["quarantine"]["auto_quarantine_enabled"] is False


def test_get_config_never_returns_a_dotenv_value_anywhere(instance):
    """Sweep every read-only response for the instance's stored credentials."""
    from anteumbra.mcp.redaction import parse_env_secrets
    from anteumbra.mcp.tools import READ_ONLY_TOOLS, call_tool

    secrets = parse_env_secrets(instance.env_path.read_text(encoding="utf-8"))
    assert secrets, "the fixture must store credentials in .env"

    for spec in READ_ONLY_TOOLS:
        serialized = json.dumps(call_tool(instance, spec.name, {}, allow_write=False))
        for secret in secrets:
            assert secret not in serialized, f"{spec.name} leaked a credential"


def test_get_config_rejects_an_unknown_section(instance):
    from anteumbra.mcp.tools import ToolError

    with pytest.raises(ToolError, match="No such configuration section"):
        _call(instance, "get_config", allow_write=False, section="not_a_section")


def test_redaction_units_strip_url_credentials_and_short_secrets():
    from anteumbra.mcp.redaction import (
        REDACTED,
        is_secret_key,
        parse_env_secrets,
        redact_config,
        redact_secret_values,
    )

    assert is_secret_key("ANTEUMBRA_PASSWORD_HASH")
    assert is_secret_key("api_token")
    assert not is_secret_key("smtp_host")

    config = redact_config(
        {
            "notifier": {"webhook": {"url": "https://hooks.example.com/T00/B00/secretvalue"}},
            "waf_source": {"url": "http://127.0.0.1:8081", "type": "http"},
        }
    )
    assert config["notifier"]["webhook"]["url"] == REDACTED
    assert config["waf_source"]["url"] == "http://127.0.0.1:8081"

    assert redact_config({"a": "https://user:pw@example.com/x"})["a"] == REDACTED
    assert parse_env_secrets("ANTEUMBRA_EMAIL_PASSWORD=abc123\nPATH=/usr/bin\n") == ("abc123",)
    long_secret = "authorization-code-1234567890"
    assert (
        redact_secret_values(f"command {long_secret} here", (long_secret,))
        == f"command {REDACTED} here"
    )
    # A short secret is matched exactly, so it cannot blank out unrelated text.
    assert redact_secret_values("value 42 here", ("42",)) == "value 42 here"
    assert redact_secret_values("42", ("42",)) == REDACTED


# ── read-only tools ──────────────────────────────────────────


def test_get_status_reports_the_instance_without_leaking_secrets(instance):
    result = _call(instance, "get_status", allow_write=False)

    assert result["instance_root"] == str(instance.root)
    assert result["config_exists"] is True
    assert result["runtime"]["running"] is False
    assert result["monitored_sites"]["site_ids"] == ["shop"]
    assert result["admin_url"].endswith(":18080/admin")
    assert result["allow_write"] is False
    assert "secret-key-value-that-must-not-leak" not in json.dumps(result)


def test_list_sites_describes_reachability_and_jsp_support(instance):
    result = _call(instance, "list_sites", allow_write=False, probe_ports=False)

    assert result["count"] == 1
    site = result["sites"][0]
    assert site["site_id"] == "shop"
    assert site["port"] == 8080
    assert site["enabled"] is True
    assert site["serves_jsp"] is True
    assert "index.jsp" in site["serves_jsp_evidence"]
    assert site["reachable"] is None  # probing was not requested


def test_validate_config_matches_the_cli(instance):
    result = _call(instance, "validate_config", allow_write=False)
    cli = instance.cli("config", "validate")

    assert result["valid"] is True
    assert result["exit_code"] == 0
    assert result["errors"] == []
    assert cli.ok
    assert result["cli_output"] == cli.lines()


def test_list_detections_filters_by_site_and_status(instance):
    registry = instance.root / "data" / "suspicious_registry.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "file_path": "/var/www/shop/uploads/shell.php",
                    "detected_at": "2026-09-14T10:00:00",
                    "features": ["eval"],
                    "file_exists": True,
                    "site_id": "shop",
                    "site_name": "shop",
                },
                {
                    "file_path": "/var/www/shop/uploads/old.php",
                    "detected_at": "2026-09-13T10:00:00",
                    "features": ["base64_decode"],
                    "file_exists": False,
                    "missing_at": "2026-09-13T11:00:00",
                    "site_id": "shop",
                    "site_name": "shop",
                },
                {
                    "file_path": "/var/www/other/shell.jsp",
                    "detected_at": "2026-09-12T10:00:00",
                    "features": ["runtime_exec"],
                    "file_exists": True,
                    "site_id": "other",
                    "site_name": "other",
                },
            ]
        ),
        encoding="utf-8",
    )

    active = _call(instance, "list_detections", allow_write=False, site_id="shop")
    assert [row["file_path"] for row in active["detections"]] == [
        "/var/www/shop/uploads/shell.php"
    ]
    assert active["detections"][0]["status"] == "active"

    missing = _call(
        instance, "list_detections", allow_write=False, status="missing", site_id="shop"
    )
    assert [row["file_path"] for row in missing["detections"]] == [
        "/var/www/shop/uploads/old.php"
    ]

    other = _call(instance, "list_detections", allow_write=False, status="all", site_id="other")
    assert other["total_matching"] == 1

    from anteumbra.mcp.tools import ToolError

    with pytest.raises(ToolError, match="Unknown status"):
        _call(instance, "list_detections", allow_write=False, status="banana")


def test_list_quarantine_never_returns_file_content(instance_dir, instance):
    quarantine_dir = instance.root / "data" / "quarantine"
    quarantine_dir.mkdir(parents=True)
    original = instance_dir / "www" / "shop" / "uploads" / "shell.php"
    (quarantine_dir / "quarantine.json").write_text(
        json.dumps(
            [
                {
                    "quarantine_id": "Q-1",
                    "original_path": original.as_posix(),
                    "quarantine_path": "/opt/anteumbra/data/quarantine/2026-09-14/Q-1_shell.php",
                    "rule_name": "webshell_eval",
                    "features": ["eval"],
                    "file_size": 42,
                    "status": "quarantined",
                    "quarantine_time": "2026-09-14T10:00:00",
                }
            ]
        ),
        encoding="utf-8",
    )

    result = _call(instance, "list_quarantine", allow_write=False)

    assert result["total_matching"] == 1
    row = result["quarantine"][0]
    assert row["quarantine_id"] == "Q-1"
    assert row["site_id"] == "shop"  # resolved from the configured site root
    assert "content" not in json.dumps(result)


def test_list_sites_summary_aggregates_records_per_site(instance):
    registry = instance.root / "data" / "suspicious_registry.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "file_path": "/var/www/shop/uploads/a.php",
                    "detected_at": "2026-09-14T10:00:00",
                    "file_exists": True,
                    "site_id": "shop",
                    "site_name": "shop",
                },
                {
                    "file_path": "/var/www/shop/uploads/b.php",
                    "detected_at": "2026-09-14T11:00:00",
                    "file_exists": True,
                    "quarantine_id": "Q-9",
                    "site_id": "shop",
                    "site_name": "shop",
                },
            ]
        ),
        encoding="utf-8",
    )

    result = _call(instance, "list_sites_summary", allow_write=False)

    assert result["totals"]["detections"] == 2
    assert result["totals"]["active"] == 1
    assert result["totals"]["quarantined_files"] == 0  # no quarantine index was written
    site = result["sites"][0]
    assert site["watched"] is True
    assert site["detections"] == 2
    assert site["quarantined"] == 1
    assert site["last_detection_at"] == "2026-09-14T11:00:00"


def test_discovery_tools_are_read_only_and_bounded(instance):
    ports = _call(instance, "list_listening_ports", allow_write=False, max_results=5)
    assert ports["count"] <= 5
    assert isinstance(ports["ports"], list)
    assert ports["platform"]

    services = _call(instance, "discover_web_services", allow_write=False)
    assert services["http_probe_enabled"] is False
    assert services["count"] == len(services["services"])
    for service in services["services"]:
        assert "document_root" in service
        assert service["confidence"] in {"high", "medium"}


# ── mutations ────────────────────────────────────────────────


def test_add_site_writes_through_the_cli_config_path_and_revalidates(instance_dir, instance):
    new_site = instance_dir / "www" / "blog"
    new_site.mkdir(parents=True)
    (instance_dir / "logs" / "access.log").write_text("", encoding="utf-8")

    result = _call(
        instance,
        "add_site",
        allow_write=True,
        name="Blog",
        path=new_site.as_posix(),
        port=8081,
        log_monitor_enabled=True,
        access_log_path="logs/access.log",
    )

    assert result["written"] is True
    assert result["site"]["id"] == "blog"
    assert result["validation"]["config_path"] == str(instance_dir / "config.toml")
    # Validation runs the same code `anteumbra config validate` runs.
    assert result["validation"]["exit_code"] == 0
    assert result["valid"] is True, result["errors"]

    from anteumbra.cli import config_support
    from anteumbra.infrastructure.config.provider import TomlConfigProvider

    data = config_support.load_toml_file(instance_dir / "config.toml")
    assert isinstance(data["website"], list), "adding a second site must produce [[website]]"
    assert [entry["id"] for entry in data["website"]] == ["shop", "blog"]
    # The original single-table site kept its nested tables.
    assert data["website"][0]["scan_options"] == {"exclude_dirs": ["cache"]}
    assert data["website"][1]["log_config"]["log_monitor_enabled"] is True

    text = (instance_dir / "config.toml").read_text(encoding="utf-8")
    assert "[[website]]" in text

    provider = TomlConfigProvider(instance_dir / "config.toml")
    assert [site.site_id for site in provider.get_websites()] == ["shop", "blog"]
    assert provider.get_website("blog").port == 8081


def test_add_site_reports_validation_errors_instead_of_raising(instance_dir, instance):
    result = _call(
        instance,
        "add_site",
        allow_write=True,
        name="Ghost",
        path=(instance_dir / "does-not-exist").as_posix(),
        port=8082,
    )

    assert result["written"] is True
    assert result["valid"] is False
    assert any("does not exist" in error for error in result["errors"])
    assert result["validation"]["exit_code"] == 1


def test_add_site_rejects_a_duplicate_id_and_bad_input(instance):
    from anteumbra.mcp.tools import ToolError

    with pytest.raises(ToolError, match="already exists"):
        _call(instance, "add_site", allow_write=True, name="shop", path="/tmp", port=80)
    with pytest.raises(ToolError, match="port must be between"):
        _call(instance, "add_site", allow_write=True, name="bad", path="/tmp", port=99999)
    with pytest.raises(ToolError, match="must not contain path separators"):
        _call(instance, "add_site", allow_write=True, name="a/b", path="/tmp", port=80)


def test_update_and_disable_site_keep_the_stable_id(instance_dir, instance):
    from anteumbra.cli import config_support

    renamed = _call(
        instance, "update_site", allow_write=True, site_id="shop", name="Shop Front", port=9090
    )
    assert renamed["site"]["id"] == "shop"
    assert renamed["site"]["name"] == "Shop Front"
    assert renamed["valid"] is True

    disabled = _call(instance, "disable_site", allow_write=True, site_id="shop")
    assert disabled["site"]["enabled"] is False
    assert disabled["valid"] is False  # no enabled site left; the error is reported, not hidden
    assert any("At least one website must be enabled" in error for error in disabled["errors"])

    data = config_support.load_toml_file(instance_dir / "config.toml")
    assert data["website"]["id"] == "shop"
    assert data["website"]["enabled"] is False


def test_set_config_value_uses_the_cli_and_revalidates(instance_dir, instance):
    result = _call(
        instance, "set_config_value", allow_write=True, key="notifier.enabled", value="true"
    )

    assert result["exit_code"] == 0, result["stderr"]
    assert result["ok"] is True
    assert result["key"] == "notifier.enabled"
    assert result["validation"]["valid"] is True

    from anteumbra.cli import config_support

    data = config_support.load_toml_file(instance_dir / "config.toml")
    assert data["notifier"]["enabled"] is True


def test_set_env_value_writes_dotenv_and_never_echoes_the_secret(instance_dir, instance):
    result = _call(
        instance,
        "set_env_value",
        allow_write=True,
        key="ANTEUMBRA_EMAIL_PASSWORD",
        value="new-authorization-code-9999",
    )

    assert result["ok"] is True
    assert result["value_written"] is True
    assert result["value_returned"] is False
    assert result["restart_required"] is True
    assert "new-authorization-code-9999" not in json.dumps(result)
    assert "new-authorization-code-9999" in (instance_dir / ".env").read_text(encoding="utf-8")
    # config.toml is never the destination for a secret.
    assert "new-authorization-code-9999" not in (instance_dir / "config.toml").read_text(
        encoding="utf-8"
    )


def test_set_env_value_refuses_foreign_and_empty_values(instance):
    from anteumbra.mcp.tools import ToolError

    with pytest.raises(ToolError, match="Only ANTEUMBRA_"):
        _call(instance, "set_env_value", allow_write=True, key="PATH", value="/evil")
    with pytest.raises(ToolError, match="never invent one"):
        _call(instance, "set_env_value", allow_write=True, key="ANTEUMBRA_SECRET_KEY", value="")


def test_mutations_refuse_to_run_without_a_config(tmp_path):
    from anteumbra.mcp.instance import Instance
    from anteumbra.mcp.tools import ToolError

    bare = Instance(tmp_path / "empty", allow_write=True)

    with pytest.raises(ToolError, match="No config.toml"):
        _call(bare, "add_site", allow_write=True, name="x", path=str(tmp_path), port=80)
