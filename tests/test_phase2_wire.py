"""Phase 2 — the advisor wire: brief governor, attempt ledger, query views,
and the interpret entry point."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import (
    tool_attempt,
    tool_brief,
    tool_engage,
    tool_interpret,
    tool_query,
)


def _lab(tmp_db: Path, scope: str = "10.0.0.0/24", kind: str = "lab") -> int:
    tool_engage(tmp_db, "L", scope, kind=kind)
    with yhdb.transaction(tmp_db) as conn:
        return yhdb.engagement_id_for(conn, "L")


# --- brief governor ---------------------------------------------------------

def test_brief_caps_reach_and_hides_placeholders(tmp_db: Path) -> None:
    # /24 engage materialises 254 undiscovered placeholders.
    tool_engage(tmp_db, "big", "10.50.0.0/24", kind="internal")
    out = tool_brief(tmp_db, "big", section="reach", limit=20)
    # Undiscovered placeholders are counted, never dumped into the REACH table.
    assert out.count("| 10.50.0.") == 0
    assert "undiscovered scope placeholders not shown" in out


def test_brief_stage_filter(tmp_db: Path) -> None:
    tool_engage(tmp_db, "big", "10.50.0.0/24", kind="internal")
    out = tool_brief(tmp_db, "big", section="reach", stage="undiscovered", limit=5)
    assert "## REACH" in out


# --- attempt ledger ---------------------------------------------------------

def _seed_host_with_rule(tmp_db: Path):
    """An engagement + scanned host + a surface that yields >=1 candidate."""
    eid = _lab(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute(
            "SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.5'", (eid,)
        ).fetchone()["id"]
        conn.execute("UPDATE host SET stage='scanned' WHERE id=?", (hid,))
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', 't')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), "ollama", "none", "{}")
    return eid


def test_attempt_rejects_unknown_rule(tmp_db: Path) -> None:
    _lab(tmp_db)
    import pytest

    with pytest.raises(ValueError, match="unknown technique"):
        tool_attempt(tmp_db, "L", rule="definitely_not_a_rule", result="fail")


def test_attempt_accepts_free_technique(tmp_db: Path) -> None:
    _lab(tmp_db)
    out = tool_attempt(tmp_db, "L", rule="", result="partial",
                       technique="custom web auth bypass", host="10.0.0.5")
    assert "recorded" in out


def test_fail_attempt_retires_candidate_from_next(tmp_db: Path) -> None:
    from yhwach import knowledge as kn
    from yhwach.nextmoves import next_moves

    eid = _seed_host_with_rule(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = next_moves(conn, eid, host_ip="10.0.0.5")
        cand_ids = [c.technique_id for c in (nm.auto + nm.gated)]
    assert cand_ids, "fixture should yield at least one candidate"
    rule = cand_ids[0]
    # Confirm it IS a real catalog id, then burn it.
    assert rule in {t.id for t in kn.load_techniques()}
    tool_attempt(tmp_db, "L", rule=rule, result="fail", host="10.0.0.5", reason="SOC blocked")
    with yhdb.transaction(tmp_db) as conn:
        nm2 = next_moves(conn, eid, host_ip="10.0.0.5")
        still = [c.technique_id for c in (nm2.auto + nm2.gated)]
        burned = [b["rule"] for b in nm2.burned]
    assert rule not in still
    assert rule in burned


# --- query views ------------------------------------------------------------

def test_query_hosts_and_filter(tmp_db: Path) -> None:
    _lab(tmp_db)
    out = tool_query(tmp_db, "L", "hosts", where={"ip": "10.0.0.5"})
    assert "10.0.0.5" in out


def test_query_unknown_view_and_column(tmp_db: Path) -> None:
    import pytest

    _lab(tmp_db)
    with pytest.raises(ValueError, match="unknown view"):
        tool_query(tmp_db, "L", "nonsense")
    with pytest.raises(ValueError, match="unknown column"):
        tool_query(tmp_db, "L", "hosts", where={"nope": "x"})


def test_query_creds_masked_by_default(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_add_cred

    _lab(tmp_db)
    tool_add_cred(tmp_db, "L", "svc", "SuperSecretValue123", kind="password")
    masked = tool_query(tmp_db, "L", "creds")
    assert "SuperSecretValue123" not in masked
    revealed = tool_query(tmp_db, "L", "creds", reveal=True)
    assert "SuperSecretValue123" in revealed


# --- interpret --------------------------------------------------------------

def test_interpret_sniffs_nmap(tmp_db: Path) -> None:
    _lab(tmp_db)
    xml = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
           '<address addr="10.0.0.5" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="22"><state state="open"/>'
           '<service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>')
    out = tool_interpret(tmp_db, "L", xml)
    assert "nmap ingested" in out


def test_interpret_dry_run_does_not_write(tmp_db: Path) -> None:
    eid = _lab(tmp_db)
    out = tool_interpret(tmp_db, "L", "some unrecognised blob of output", dry_run=True)
    assert "dry_run" in out
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM finding WHERE engagement_id=?", (eid,)).fetchone()[0]
    assert n == 0


def test_interpret_unparsed_falls_back_to_loot_finding(tmp_db: Path) -> None:
    eid = _lab(tmp_db)
    out = tool_interpret(tmp_db, "L", "weird custom tool output nobody parses", title="weird tool")
    assert "unparsed" in out and "INFO finding" in out
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute(
            "SELECT severity, class FROM finding WHERE engagement_id=? AND title='weird tool'",
            (eid,)).fetchone()
    assert row is not None and row["class"] == "INFO"
