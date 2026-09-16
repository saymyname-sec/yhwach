"""Yhwach MCP server — exposes the engine to Claude Code on Kali as tools.

Thin wrapper over mcp_tools (which carry the logic and no SDK dependency). The
`mcp` package is an optional extra: `pip install yhwach[mcp]`. Supports the
mcp<2 FastMCP API (what Kali's OSAI stack pins) and the mcp>=2 rename.

Each tool resolves the engagement DB from $YHWACH_DB (or the default lab path),
so the operator sets the lab once via the environment. Yhwach never calls a
model here — `yhwach_next` returns the persona-framed context for the host to
reason over.
"""
from __future__ import annotations

import os
from pathlib import Path

from yhwach.mcp_tools import TOOL_SPECS

DEFAULT_DB = "~/osai/current/state/yhwach.db"


def _db_path() -> str:
    return os.path.expanduser(os.environ.get("YHWACH_DB", DEFAULT_DB))


def _load_fastmcp():
    """Import FastMCP across mcp v1/v2. Raises a helpful error if mcp is absent."""
    try:
        from mcp.server.fastmcp import FastMCP  # mcp < 2
        return FastMCP
    except ModuleNotFoundError:
        try:
            from mcp.server.mcpserver import MCPServer  # mcp >= 2 (renamed)
            return MCPServer
        except ModuleNotFoundError as e:
            raise SystemExit(
                "The 'mcp' package is required for the Yhwach MCP server. "
                "Install it with:  pip install 'yhwach[mcp]'"
            ) from e


def build_server():
    FastMCP = _load_fastmcp()
    server = FastMCP("yhwach")

    def _make(fn):
        # Bind the db path at call time; pass through the tool's own args.
        def wrapper(**kwargs) -> str:
            try:
                return str(fn(_db_path(), **kwargs))
            except Exception as e:  # noqa: BLE001 — surface errors as tool output
                return f"[yhwach error] {e}"
        return wrapper

    for name, fn, desc in TOOL_SPECS:
        wrapper = _make(fn)
        wrapper.__name__ = name
        wrapper.__doc__ = desc
        # FastMCP infers the schema from the wrapped signature; we keep args as
        # explicit kwargs via functools.partial-style binding below.
        server.tool(name=name, description=desc)(_bind_signature(fn, wrapper))

    return server


def _bind_signature(fn, wrapper):
    """Give the wrapper fn the tool's parameter signature (minus db_path) so the
    MCP SDK generates the right input schema."""
    import inspect

    sig = inspect.signature(fn)
    params = [p for n, p in sig.parameters.items() if n != "db_path"]
    wrapper.__signature__ = inspect.Signature(params)
    return wrapper


def run() -> None:
    build_server().run()


if __name__ == "__main__":
    run()
