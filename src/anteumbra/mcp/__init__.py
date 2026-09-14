"""MCP surface for Anteumbra: a local agent's read/write window on one instance.

This package contains no AI agent of its own. It exposes the operations an
operator already performs with the CLI - inspect status, configure sites,
validate, verify - as Model Context Protocol tools, so the user's own agent can
drive them. The package is import-safe without the optional ``mcp`` SDK: the SDK
is imported lazily, and only when a server is actually started.
"""

from __future__ import annotations
