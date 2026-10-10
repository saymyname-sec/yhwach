"""yhwach next — the fused recall-menu + "about to miss" view.

The recall menu was invisible: consumed only by the runtime, collapsed to an
integer in the UI, with no CLI/MCP surface. These tests lock the surfacing:
the applicable-technique menu is returned (read-only vs gated), successes are
filtered, and the three "about to miss" fusions (coverage gaps, untried creds,
uncaptured objectives) come through in the data, the text and the JSON.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import nextmoves as nm_
from yhwach.cli import main


def _seed(tmp_db: Path) -> tuple[int, int]:
    """One scanned host with an unauth chatbot surface (yields AI candidates),
    one untried cred, one uncaptured objective. Returns (engagement_id, host_id)."""
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="nexttest", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'ai01', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng,),
        )
        hid = int(cur.lastrowid)
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 3000, 'tcp', 'gradio', '2026-01-01T00:00:00Z')",
            (hid,),
        )
        yhdb.upsert_surface(conn, hid, int(svc.lastrowid), "chatbot", "none", "{}")
        yhdb.add_credential(conn, eng, "svc_ai", "P@ss1", "password", "dump")
        yhdb.add_objective(conn, eng, "proof.txt", host_id=hid, points=10)
        return eng, hid


def test_next_moves_returns_recall_menu(tmp_db: Path) -> None:
    eng, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = nm_.next_moves(conn, eng)
    # The chatbot surface lights up applicable techniques — that is the menu.
    assert nm.auto or nm.gated
    assert all(c.autonomy == "proceed" for c in nm.auto)
    assert all(c.autonomy != "proceed" for c in nm.gated)


def test_next_moves_fuses_the_about_to_miss_signals(tmp_db: Path) -> None:
    eng, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = nm_.next_moves(conn, eng)
    # untried cred (never validated) surfaces
    assert any(c["identifier"] == "svc_ai" for c in nm.untried_creds)
    # uncaptured objective surfaces
    assert any(o["label"] == "proof.txt" for o in nm.objectives)
    # the scanned host is under-enumerated (no coverage rows recorded)
    assert nm.coverage
    assert not nm.empty


def test_next_moves_filters_succeeded(tmp_db: Path) -> None:
    eng, hid = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        before = nm_.next_moves(conn, eng)
        target = (before.auto + before.gated)[0]
        conn.execute(
            "INSERT INTO attempt (engagement_id, host_id, playbook_rule_id, result, "
            "attempted_at) VALUES (?, ?, ?, 'success', '2026-01-02T00:00:00Z')",
            (eng, hid, target.technique_id),
        )
        after = nm_.next_moves(conn, eng)
    pairs_before = {(c.technique_id, c.host_ip) for c in before.auto + before.gated}
    pairs_after = {(c.technique_id, c.host_ip) for c in after.auto + after.gated}
    assert (target.technique_id, target.host_ip) in pairs_before
    assert (target.technique_id, target.host_ip) not in pairs_after


def test_next_moves_host_scope(tmp_db: Path) -> None:
    eng, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        scoped = nm_.next_moves(conn, eng, host_ip="10.0.0.5")
        empty = nm_.next_moves(conn, eng, host_ip="10.0.0.99")
    assert all(c.host_ip == "10.0.0.5" for c in scoped.auto + scoped.gated)
    assert not (empty.auto or empty.gated)


def test_render_and_json_shapes(tmp_db: Path) -> None:
    eng, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = nm_.next_moves(conn, eng)
    text = "\n".join(nm_.render_next(nm))
    assert "svc_ai" in text
    assert "proof.txt" in text
    assert "UNDER-ENUMERATION" in text
    doc = nm_.next_as_dict(nm)
    for key in ("auto", "gated", "coverage_gaps", "untried_creds", "objectives", "pending_scan"):
        assert key in doc
    # JSON-serialisable end to end
    assert json.loads(json.dumps(doc))


def test_cli_next(tmp_db: Path) -> None:
    _seed(tmp_db)
    res = CliRunner().invoke(main, ["next", "--lab", "nexttest", "--db", str(tmp_db)])
    assert res.exit_code == 0, res.output
    assert "Next moves for 'nexttest'" in res.output
    assert "svc_ai" in res.output


def test_cli_next_json(tmp_db: Path) -> None:
    _seed(tmp_db)
    res = CliRunner().invoke(
        main, ["next", "--lab", "nexttest", "--json", "--db", str(tmp_db)]
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(res.output)
    assert "auto" in doc and "coverage_gaps" in doc


def test_cli_next_unknown_lab(tmp_db: Path) -> None:
    res = CliRunner().invoke(main, ["next", "--lab", "nope", "--db", str(tmp_db)])
    assert res.exit_code == 2


def test_cli_coverage(tmp_db: Path) -> None:
    _seed(tmp_db)
    res = CliRunner().invoke(main, ["coverage", "--lab", "nexttest", "--db", str(tmp_db)])
    assert res.exit_code == 0, res.output
    assert "honesty" in res.output
    js = CliRunner().invoke(
        main, ["coverage", "--lab", "nexttest", "--json", "--db", str(tmp_db)]
    )
    assert js.exit_code == 0, js.output
    doc = json.loads(js.output)
    assert "honesty_pct" in doc and "gaps" in doc


def test_mcp_tool_next(tmp_db: Path) -> None:
    from yhwach import mcp_tools

    _seed(tmp_db)
    out = mcp_tools.tool_next(tmp_db, "nexttest")
    assert "Next moves for 'nexttest'" in out
    assert "svc_ai" in out
    # registered in the MCP tool surface
    names = {name for name, _fn, _desc in mcp_tools.TOOL_SPECS}
    assert "yhwach_next" in names


def test_mcp_tool_coverage(tmp_db: Path) -> None:
    from yhwach import mcp_tools

    _seed(tmp_db)
    out = mcp_tools.tool_coverage(tmp_db, "nexttest")
    assert "Enumeration coverage for 'nexttest'" in out
    assert "honesty" in out
    names = {name for name, _fn, _desc in mcp_tools.TOOL_SPECS}
    assert "yhwach_coverage" in names
