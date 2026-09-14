"""MCP server behaviour: the missing-extra error, registration, and the write gate."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

CONFIG_TEMPLATE = """
[website]
name = "shop"
id = "shop"
path = "__SITE__"
port = 8080
enabled = true

[web_admin]
host = "127.0.0.1"
port = 18080
password_hash = "not-a-real-hash"

[security]
secret_key = "not-a-real-secret"

[storage]
backend = "json"

[paths]
data_dir = "data"
"""


@pytest.fixture
def instance_dir(tmp_path: Path) -> Path:
    site = tmp_path / "www" / "shop"
    site.mkdir(parents=True)
    (tmp_path / "config.toml").write_text(
        CONFIG_TEMPLATE.replace("__SITE__", site.as_posix()), encoding="utf-8"
    )
    (tmp_path / ".env").write_text("ANTEUMBRA_SECRET_KEY=not-a-real-secret\n", encoding="utf-8")
    (tmp_path / "data").mkdir(exist_ok=True)
    return tmp_path


@pytest.fixture
def instance(instance_dir: Path):
    from anteumbra.mcp.instance import Instance

    return Instance(instance_dir)


def _hide_mcp_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import mcp`` fail for the duration of one test."""
    for name in [key for key in sys.modules if key == "mcp" or key.startswith("mcp.")]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "mcp", None)


def _combined(result) -> str:
    text = result.output or ""
    try:
        text += result.stderr or ""
    except (AttributeError, ValueError):  # pragma: no cover - older click
        pass
    return text


# ── the missing optional dependency ──────────────────────────


def test_serve_without_the_sdk_reports_one_install_line(monkeypatch, instance_dir):
    _hide_mcp_sdk(monkeypatch)
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["--home", str(instance_dir), "mcp", "serve"])

    assert result.exit_code == 1, _combined(result)
    text = _combined(result)
    assert 'pip install "anteumbra[mcp]"' in text
    assert "Error:" in text
    assert "Traceback" not in text
    assert "ImportError" not in text


def test_missing_sdk_message_is_a_single_actionable_line(monkeypatch):
    _hide_mcp_sdk(monkeypatch)
    from anteumbra.mcp.server import MCP_EXTRA_ERROR, McpSdkMissing, load_sdk

    with pytest.raises(McpSdkMissing) as excinfo:
        load_sdk()

    assert str(excinfo.value) == MCP_EXTRA_ERROR
    assert MCP_EXTRA_ERROR.count("\n") == 0
    assert MCP_EXTRA_ERROR.count("pip install") == 1
    assert "anteumbra mcp serve" in MCP_EXTRA_ERROR


def test_mcp_tools_listing_never_needs_the_sdk(monkeypatch, instance_dir):
    _hide_mcp_sdk(monkeypatch)
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["--home", str(instance_dir), "mcp", "tools"])

    assert result.exit_code == 0, _combined(result)
    assert "get_status" in result.output
    assert "add_site" not in result.output
    assert "Mutating tools are absent" in result.output

    write_result = CliRunner().invoke(
        cli, ["--home", str(instance_dir), "mcp", "tools", "--allow-write"]
    )
    assert write_result.exit_code == 0, _combined(write_result)
    assert "add_site" in write_result.output
    assert "set_env_value" in write_result.output


def test_serve_help_documents_transport_home_and_the_extra(instance_dir):
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["mcp", "serve", "--help"])

    assert result.exit_code == 0, _combined(result)
    assert "--allow-write" in result.output
    assert "stdio" in result.output
    assert "--home" in result.output
    assert 'pip install "anteumbra[mcp]"' in " ".join(result.output.split())


def test_top_level_help_lists_the_new_command_groups():
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0, _combined(result)
    assert "mcp" in result.output
    assert "skill" in result.output


# ── registration through the real SDK, when it is installed ──


def test_server_registers_exactly_the_declared_read_only_tools(instance):
    pytest.importorskip("mcp")
    from anteumbra.mcp.server import build_server
    from anteumbra.mcp.tools import READ_ONLY_TOOLS

    tools = asyncio.run(build_server(instance, allow_write=False).list_tools())

    assert [tool.name for tool in tools] == [spec.name for spec in READ_ONLY_TOOLS]
    schemas = {tool.name: tool.inputSchema for tool in tools}
    assert schemas["list_detections"]["properties"]["limit"]["type"] == "integer"
    assert schemas["list_detections"]["properties"]["site_id"]["anyOf"][0] == {"type": "string"}
    assert schemas["get_status"]["properties"] == {}
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True


def test_server_registers_mutating_tools_only_in_write_mode(instance):
    pytest.importorskip("mcp")
    from anteumbra.mcp.server import build_server
    from anteumbra.mcp.tools import WRITE_TOOLS

    read_only_names = {
        tool.name for tool in asyncio.run(build_server(instance, allow_write=False).list_tools())
    }
    write_tools = asyncio.run(build_server(instance, allow_write=True).list_tools())
    write_names = {tool.name for tool in write_tools}

    assert read_only_names.isdisjoint({spec.name for spec in WRITE_TOOLS})
    assert {"add_site", "update_site", "disable_site", "set_config_value", "set_env_value"} <= (
        write_names
    )
    schemas = {tool.name: tool.inputSchema for tool in write_tools}
    assert schemas["add_site"]["required"] == ["name", "path", "port"]
    annotations = {tool.name: tool.annotations for tool in write_tools}
    assert annotations["add_site"].readOnlyHint is False
    assert annotations["add_site"].destructiveHint is True


def test_server_reports_anteumbra_version_not_the_sdk_version(instance):
    pytest.importorskip("mcp")
    import anteumbra
    from anteumbra.mcp.server import build_server

    server = build_server(instance, allow_write=False)

    assert server._mcp_server.version == anteumbra.__version__


def test_server_instructions_state_the_safety_defaults(instance):
    pytest.importorskip("mcp")
    from anteumbra.mcp.server import build_server

    server = build_server(instance, allow_write=False)
    instructions = server.instructions or ""

    assert "get_status" in instructions
    assert "validate_config" in instructions
    assert "--allow-write" in instructions
    assert "never print a secret" in instructions.lower()
