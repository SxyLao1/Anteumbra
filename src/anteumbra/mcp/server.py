"""Start the Anteumbra MCP server on stdio.

The optional ``mcp`` SDK is imported here and nowhere else, so the rest of the
package - and every other CLI command - keeps working on a base install.
"""

from __future__ import annotations

import sys

from anteumbra.mcp.instance import Instance
from anteumbra.mcp.tools import BoundTool, build_tools

SERVER_NAME = "anteumbra"
MCP_EXTRA_NAME = "mcp"
MCP_EXTRA_INSTALL_HINT = 'pip install "anteumbra[mcp]"'
MCP_EXTRA_ERROR = (
    'The MCP server needs the optional "mcp" Python SDK. '
    f"Install it with: {MCP_EXTRA_INSTALL_HINT} - then run \"anteumbra mcp serve\" again."
)

INSTRUCTIONS = """\
You are operating a local Anteumbra instance (a passive web-perimeter security
observatory) through this server. Anteumbra ships no agent of its own: you are
the agent, and every write is the user's decision.

Work in this order:
1. get_status - is the service running, which version, which instance directory.
2. discover_web_services (and list_listening_ports) - find web servers on this
   machine and name their document roots.
3. Ask the user which of them to monitor. Never guess, and stop if a discovered
   service does not look like it belongs to them.
4. list_sites / get_config - see what is already configured.
5. add_site / update_site / disable_site - configure (write access only).
6. validate_config - no site is monitored while validation reports errors.
7. set_env_value - store secrets (mail authorization code, WeChat send key, WAF
   token) in .env. Never put a secret in config.toml and never repeat one back.
8. Ask the user to start or restart the service with the CLI:
   anteumbra --home <instance> start | stop | run
9. Verify: validate_config returns valid, list_sites shows the site enabled, and
   a test file in the web root produces a row in list_detections.
10. Report back: admin URL, monitored sites, where data and logs live, and how
   to stop or restart.

Safety defaults you must keep: writes only exist if the server was started with
--allow-write; ask before every mutating call; never enable IP blocking or
auto-quarantine without explicit confirmation; never print a secret; and say
plainly when something could not be verified on this platform.
"""


class McpSdkMissing(RuntimeError):
    """Raised when the optional ``mcp`` SDK is not importable."""


def load_sdk():
    """Import the optional MCP SDK, or explain exactly how to install it."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised by a CLI test
        raise McpSdkMissing(MCP_EXTRA_ERROR) from exc
    return FastMCP


def sdk_is_installed() -> bool:
    """Return whether the optional SDK is importable, without raising."""
    try:
        import importlib.util

        return importlib.util.find_spec("mcp") is not None
    except (ImportError, ValueError):  # pragma: no cover - defensive
        return False


def tool_annotations(bound: BoundTool):
    """Describe a tool's side effects to the client."""
    from mcp.types import ToolAnnotations

    return ToolAnnotations(
        readOnlyHint=not bound.spec.write,
        destructiveHint=bound.spec.write,
        idempotentHint=not bound.spec.write,
        openWorldHint=False,
    )


def label_version(server) -> None:
    """Report Anteumbra's version - not the SDK's - in the initialize handshake.

    FastMCP leaves the low-level server version unset, so a client would be told
    the ``mcp`` package version (for example ``1.27.1``) as if it were Anteumbra's.
    """
    low_level = getattr(server, "_mcp_server", None)
    if low_level is None or getattr(low_level, "version", None) is not None:
        return
    try:
        from anteumbra import __version__

        low_level.version = __version__
    except Exception:  # pragma: no cover - version reporting is not critical
        pass


def build_server(instance: Instance, *, allow_write: bool = False):
    """Build the FastMCP server for one instance and one write mode."""
    fast_mcp = load_sdk()
    server = fast_mcp(SERVER_NAME, instructions=INSTRUCTIONS)
    for bound in build_tools(instance, allow_write=allow_write):
        server.add_tool(
            bound.function,
            name=bound.spec.name,
            description=bound.spec.summary,
            annotations=tool_annotations(bound),
            structured_output=False,
        )
    label_version(server)
    return server


def serve_stdio(instance: Instance, *, allow_write: bool = False) -> None:
    """Serve the tool surface to a local agent over stdio.

    Nothing may be written to stdout here: stdout carries the protocol.
    """
    if not instance.has_config:
        print(
            f"Warning: no config.toml at {instance.config_path}. Discovery tools work; "
            f'create the runtime with `anteumbra install "{instance.root}"` before configuring.',
            file=sys.stderr,
        )
    server = build_server(instance, allow_write=allow_write)
    server.run("stdio")


__all__ = [
    "INSTRUCTIONS",
    "MCP_EXTRA_ERROR",
    "MCP_EXTRA_INSTALL_HINT",
    "MCP_EXTRA_NAME",
    "SERVER_NAME",
    "McpSdkMissing",
    "build_server",
    "label_version",
    "load_sdk",
    "sdk_is_installed",
    "serve_stdio",
]
