"""Click commands exposing the Anteumbra MCP server."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import click


def register_mcp_commands(
    root: click.Group,
    *,
    find_project_root: Callable[[], Path],
) -> click.Group:
    """Register the ``mcp`` command group and return it."""

    @root.group(
        "mcp",
        invoke_without_command=True,
        epilog=(
            "\b\nExamples:\n"
            "  anteumbra --home E:\\Software\\Anteumbra mcp serve\n"
            "  anteumbra --home E:\\Software\\Anteumbra mcp serve --allow-write\n"
            "  anteumbra mcp tools"
        ),
    )
    @click.pass_context
    def mcp(ctx):
        """Serve Anteumbra's tools to a local AI agent over MCP.

        Anteumbra ships no AI agent of its own. It exposes the same operations
        the CLI performs, so the agent you already run can discover, configure
        and verify this instance.
        """
        if ctx.invoked_subcommand is None:
            click.echo(ctx.get_help())

    @mcp.command("serve")
    @click.option(
        "--allow-write/--read-only",
        default=False,
        help="Expose mutating tools (add/update/disable site, config and .env writes).",
    )
    def mcp_serve(allow_write):
        """Serve this instance over MCP on stdio for a local agent.

        The transport is stdio: the client starts this command and speaks the
        protocol on its stdin/stdout. Use `--home` before `mcp` to choose the
        instance. Read-only by default; mutating tools do not exist in the tool
        list unless --allow-write is given.

        \b
        Requires the optional SDK:
            pip install "anteumbra[mcp]"
        """
        from anteumbra.mcp.instance import Instance
        from anteumbra.mcp.server import McpSdkMissing, serve_stdio

        instance = Instance(find_project_root(), allow_write=bool(allow_write))
        try:
            serve_stdio(instance, allow_write=bool(allow_write))
        except McpSdkMissing as exc:
            raise click.ClickException(str(exc)) from exc

    @mcp.command("tools")
    @click.option(
        "--allow-write",
        is_flag=True,
        help="List the tool surface this instance would expose in write mode.",
    )
    def mcp_tools(allow_write):
        """List the MCP tools a client would see for this instance.

        This reads the same declarations the server registers, so it works
        without the optional SDK and is the quickest way to confirm that the
        mutating tools are absent in read-only mode.
        """
        from anteumbra.mcp.instance import Instance
        from anteumbra.mcp.tools import build_tools

        instance = Instance(find_project_root(), allow_write=bool(allow_write))
        tools = build_tools(instance, allow_write=bool(allow_write))
        for bound in tools:
            gate = "write" if bound.spec.write else "read-only"
            click.echo(f"{bound.spec.name:<26} {gate:<9} {bound.spec.summary}")
        click.echo(f"\n{len(tools)} tools for instance {instance.root}")
        if not allow_write:
            click.echo(
                "Mutating tools are absent by design; add --allow-write to "
                "`anteumbra mcp serve` to expose them."
            )

    return mcp
