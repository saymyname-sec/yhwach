"""Tests for the MCP tool logic (no SDK dependency)."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import (
    TOOL_SPECS,
    tool_add_cred,
    tool_advance,
    tool_findings,
    tool_next,
    tool_plan,
    tool_report,
    tool_spray,
    tool_status,
)


def _seed(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="m", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')", (eng,))
        hid = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')", (hid,))
        yhdb.upsert_surface(conn, hid, int(cur.lastrowid), "ollama", "none", "{}")


def test_status(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_status(tmp_db, "m")
    assert "Engagement 'm'" in out
    assert "scanned: 1" in out


def test_plan_and_next(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "rules matched" in tool_plan(tmp_db, "m")
    ctx = tool_next(tmp_db, "m")
    assert "## FRAME" in ctx
    assert "ollama_unauth_api" in ctx


def test_add_cred_then_spray_needs_surface(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "added" in tool_add_cred(tmp_db, "m", "admin", "P@ss")
    # ollama isn't a sprayable surface -> nothing to spray
    assert "nothing to spray" in tool_spray(tmp_db, "m")


def test_advance(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "foothold" in tool_advance(tmp_db, "m", "10.0.0.5", "foothold")


def test_report_and_findings(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "# Yhwach Engagement Report" in tool_report(tmp_db, "m")
    assert tool_findings(tmp_db, "m") == "no findings"


def test_unknown_lab_raises(tmp_db: Path) -> None:
    import pytest
    with pytest.raises(ValueError):
        tool_status(tmp_db, "nope")


def test_tool_specs_shape() -> None:
    names = {t[0] for t in TOOL_SPECS}
    assert {"yhwach_status", "yhwach_next", "yhwach_report"}.issubset(names)
    for name, fn, desc in TOOL_SPECS:
        assert name.startswith("yhwach_") and callable(fn) and desc
