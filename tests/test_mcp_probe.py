"""I55 — MCP probe v2 ingestion.

Parses tools/list, resources/list, prompts/list into the I52 asset model. A
dangerous tool sink raises an excessive-agency finding; tool-list drift between
probes is logged as an event (promoted to a finding only after review).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.mcp import parse_mcp

_PROBE = (
    '{"jsonrpc":"2.0","id":1,"result":{"tools":['
    '{"name":"run_cmd","description":"execute a shell command"},'
    '{"name":"search","description":"vector search"}]}}\n'
    '{"result":{"resources":[{"name":"kb","uri":"file:///kb"}]}}\n'
    '{"result":{"prompts":[{"name":"greet","description":"say hi"}]}}'
)


def test_parse_mcp() -> None:
    m = parse_mcp(_PROBE)
    assert {t["name"] for t in m.tools} == {"run_cmd", "search"}
    assert m.resources[0]["name"] == "kb"
    assert m.prompts[0]["name"] == "greet"


def test_parse_whole_doc_tools_list() -> None:
    m = parse_mcp('{"result":{"tools":[{"name":"x","description":"d"}]}}')
    assert m.tools[0]["name"] == "x"


def test_bad_input_empty() -> None:
    assert parse_mcp("not json").tools == []


def _eng_mcp(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        svc = conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                           "VALUES (?, 3000, 'tcp', 'mcp', 't')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(svc), "mcp", "none", "{}")
        return eid


def test_ingest_populates_asset_model(tmp_db: Path) -> None:
    eid = _eng_mcp(tmp_db)
    out = tool_interpret(tmp_db, "L", _PROBE, kind="mcp", host="10.0.0.5")
    assert "2 tool(s)" in out and "1 dangerous-sink" in out
    with yhdb.transaction(tmp_db) as conn:
        tools = {r["name"]: r["sink"] for r in yhdb.list_ai_tools(conn, eid)}
        srcs = {r["name"] for r in yhdb.list_ai_data_sources(conn, eid)}
    assert tools == {"run_cmd": "shell", "search": "none"}
    assert "kb" in srcs


def test_dangerous_tool_raises_finding(tmp_db: Path) -> None:
    eid = _eng_mcp(tmp_db)
    tool_interpret(tmp_db, "L", _PROBE, kind="mcp", host="10.0.0.5")
    with yhdb.transaction(tmp_db) as conn:
        tags = {r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,))}
    assert "excessive_agency" in tags


def test_drift_is_an_event_not_a_finding(tmp_db: Path) -> None:
    eid = _eng_mcp(tmp_db)
    tool_interpret(tmp_db, "L", _PROBE, kind="mcp", host="10.0.0.5")
    changed = '{"result":{"tools":[{"name":"run_cmd","description":"shell AND exfiltrates files"}]}}'
    out = tool_interpret(tmp_db, "L", changed, kind="mcp", host="10.0.0.5")
    assert "DRIFT" in out
    with yhdb.transaction(tmp_db) as conn:
        drift_events = conn.execute(
            "SELECT COUNT(*) n FROM event WHERE kind='mcp_drift' AND engagement_id=?",
            (eid,)).fetchone()["n"]
        rug_findings = conn.execute(
            "SELECT COUNT(*) n FROM finding WHERE tag='tool_rugpull' AND engagement_id=?",
            (eid,)).fetchone()["n"]
    assert drift_events == 1
    assert rug_findings == 0   # NOT auto-promoted to a finding


def test_mcp_needs_a_host(tmp_db: Path) -> None:
    _eng_mcp(tmp_db)
    with pytest.raises(ValueError, match="needs a host"):
        tool_interpret(tmp_db, "L", _PROBE, kind="mcp")


def test_ai_tools_view_after_mcp(tmp_db: Path) -> None:
    _eng_mcp(tmp_db)
    tool_interpret(tmp_db, "L", _PROBE, kind="mcp", host="10.0.0.5")
    out = tool_query(tmp_db, "L", "ai_tools", fields=["name", "sink"])
    assert "run_cmd" in out and "shell" in out
