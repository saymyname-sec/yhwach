"""Tests for the MCP server glue (SDK-facing). The `mcp` package is optional,
so the build tests skip when it isn't installed."""
from __future__ import annotations

import inspect

import pytest

from yhwach import mcp_server
from yhwach.mcp_tools import TOOL_SPECS


def test_bind_signature_strips_db_path() -> None:
    def fn(db_path, lab, limit=4):  # noqa: ANN001, ANN202
        return None

    def wrapper(**kwargs):  # noqa: ANN003, ANN202
        return None

    bound = mcp_server._bind_signature(fn, wrapper)
    params = list(inspect.signature(bound).parameters)
    assert params == ["lab", "limit"]           # db_path dropped, rest preserved


def test_load_fastmcp_returns_a_class() -> None:
    pytest.importorskip("mcp")
    cls = mcp_server._load_fastmcp()
    assert cls is not None and callable(cls)


def test_build_server_registers_all_tools() -> None:
    pytest.importorskip("mcp")
    # Building exercises _bind_signature + schema inference for every TOOL_SPEC;
    # a bad annotation or signature would raise here.
    server = mcp_server.build_server()
    assert server is not None
    assert len(TOOL_SPECS) >= 15            # full CLI-parity surface
