"""I52 — AI-surface asset model: agent tools + data sources.

Tools are classified to a sink (the excessive-agency signal); a changed tool
description is a rug-pull; a writable data source is the indirect-injection
vector. The tool_sink / source_writable when-keys gate the exploit rules.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import knowledge as kn
from yhwach.aisurface import classify_sink
from yhwach.mcp_tools import tool_ai_source, tool_ai_tool, tool_query

# --- sink lexicon -----------------------------------------------------------


def test_classify_sink() -> None:
    assert classify_sink("run_shell") == "shell"
    assert classify_sink("exec", "execute a command") == "shell"
    assert classify_sink("notify", "sends an email") == "email"
    assert classify_sink("run_sql", "runs a SQL query") == "sql"
    assert classify_sink("get_weather", "returns the forecast") == "none"


def test_explicit_sink_override(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        _id, _created, _rug = yhdb.add_ai_tool(conn, eid, "mystery", description="opaque",
                                               sink="code")
        row = conn.execute("SELECT sink FROM ai_tool WHERE name='mystery'").fetchone()
    assert row["sink"] == "code"


# --- rug-pull ---------------------------------------------------------------


def test_rug_pull_on_description_change(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        _i, created, rug = yhdb.add_ai_tool(conn, eid, "t", description="reads files")
        assert created and not rug
        _i, created2, rug2 = yhdb.add_ai_tool(conn, eid, "t", description="reads files")
        assert not created2 and not rug2    # unchanged -> no rug-pull
        _i, _c, rug3 = yhdb.add_ai_tool(conn, eid, "t", description="now also exfiltrates")
        assert rug3 is True                  # changed -> rug-pull


# --- findings on ingest -----------------------------------------------------


def _eng_surface(path: Path, kind: str = "mcp") -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        svc = conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                           "VALUES (?, 3000, 'tcp', ?, 't')", (hid, kind)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(svc), kind, "none", "{}")
        return eid


def test_dangerous_sink_raises_finding(tmp_db: Path) -> None:
    _eng_surface(tmp_db)
    out = tool_ai_tool(tmp_db, "L", name="exec_command", description="run a shell command",
                       host="10.0.0.5")
    assert "excessive-agency" in out
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        tags = {r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,))}
    assert "excessive_agency" in tags


def test_benign_tool_no_finding(tmp_db: Path) -> None:
    _eng_surface(tmp_db)
    tool_ai_tool(tmp_db, "L", name="get_weather", description="forecast", host="10.0.0.5")
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) n FROM finding").fetchone()["n"]
    assert n == 0


def test_writable_source_raises_finding(tmp_db: Path) -> None:
    eid = _eng_surface(tmp_db, kind="chatbot")
    tool_ai_source(tmp_db, "L", name="customer-kb", kind="rag", host="10.0.0.5", writable=True)
    with yhdb.transaction(tmp_db) as conn:
        tags = {r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,))}
    assert "rag_poisoning" in tags


# --- the when-keys gate recall ----------------------------------------------


def _cands(path: Path, eid: int) -> set[str]:
    with yhdb.transaction(path) as conn:
        return {c.technique_id for c in kn.candidates_for(conn, eid)}


def test_tool_sink_when_key_gates_rule(tmp_db: Path) -> None:
    eid = _eng_surface(tmp_db, kind="mcp")
    assert "agent_tool_shell_sink" not in _cands(tmp_db, eid)   # no shell tool yet
    tool_ai_tool(tmp_db, "L", name="exec", description="run shell", host="10.0.0.5")
    assert "agent_tool_shell_sink" in _cands(tmp_db, eid)       # now it fires


def test_source_writable_when_key_gates_rule(tmp_db: Path) -> None:
    eid = _eng_surface(tmp_db, kind="chatbot")
    assert "writable_source_indirect_injection" not in _cands(tmp_db, eid)
    tool_ai_source(tmp_db, "L", name="kb", kind="rag", host="10.0.0.5", writable=True)
    assert "writable_source_indirect_injection" in _cands(tmp_db, eid)


def test_views(tmp_db: Path) -> None:
    _eng_surface(tmp_db)
    tool_ai_tool(tmp_db, "L", name="exec", description="run shell", host="10.0.0.5")
    out = tool_query(tmp_db, "L", "ai_tools", fields=["name", "sink"])
    assert "exec" in out and "shell" in out
