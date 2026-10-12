"""Phase 3 — the memory an operator pulls from: finding lifecycle (status,
per-instance, curated freeze) and evidence binding. No report generation."""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach.mcp_tools import (
    tool_add_evidence,
    tool_add_finding,
    tool_brief,
    tool_engage,
    tool_finding_set,
    tool_query,
)


def _lab(tmp_db: Path) -> int:
    tool_engage(tmp_db, "L", "10.0.0.0/24", kind="internal")
    with yhdb.transaction(tmp_db) as conn:
        return yhdb.engagement_id_for(conn, "L")


# --- finding lifecycle ------------------------------------------------------

def test_close_finding_drops_from_live_but_stays_queryable(tmp_db: Path) -> None:
    _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "Reflected XSS", "medium", "payload reflected",
                     cls="CWE-79", host="10.0.0.5")
    # It is live in the register.
    assert "Reflected XSS" in tool_query(tmp_db, "L", "findings",
                                         where={"status in": list(yhdb.LIVE_FINDING_STATUSES)})
    fid = _only_finding_id(tmp_db)
    tool_finding_set(tmp_db, "L", fid, status="false_positive", reason="dev console, not exploitable")
    # Gone from the live/open set…
    live = tool_query(tmp_db, "L", "findings",
                      where={"status in": list(yhdb.LIVE_FINDING_STATUSES)})
    assert "Reflected XSS" not in live
    # …but still a row (closed, not deleted).
    allrows = tool_query(tmp_db, "L", "findings", where={"id": fid})
    assert "false_positive" in allrows


def test_confirmed_finding_stays_live_in_brief(tmp_db: Path) -> None:
    _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "SMB signing off", "high", "signing:False",
                     cls="CWE-287", host="10.0.0.5", tag="smb_signing_off")
    fid = _only_finding_id(tmp_db)
    tool_finding_set(tmp_db, "L", fid, status="confirmed")
    # 'confirmed' is a LIVE status, so the lead still shows in the brief UNLOCKS.
    out = tool_brief(tmp_db, "L", section="unlocks")
    assert "smb_signing_off" in out


def test_curated_finding_frozen_against_reingest(tmp_db: Path) -> None:
    eid = _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "Weak cipher", "low", "original evidence",
                     cls="CWE-327", host="10.0.0.5")
    fid = _only_finding_id(tmp_db)
    tool_finding_set(tmp_db, "L", fid, severity="high", evidence="operator-curated evidence")
    # A parser re-ingest of the same (class,title,host) must NOT clobber it.
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.5'",
                           (eid,)).fetchone()["id"]
        yhdb.add_finding(conn, hid, None, "CWE-327", "Weak cipher", "low",
                         "parser re-ingest evidence", engagement_id=eid)
        row = conn.execute("SELECT severity, evidence FROM finding WHERE id=?", (fid,)).fetchone()
    assert row["severity"] == "high"
    assert row["evidence"] == "operator-curated evidence"


def test_per_instance_rows_by_location(tmp_db: Path) -> None:
    eid = _lab(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.5'",
                           (eid,)).fetchone()["id"]
        for loc in ("/a?id=1", "/b?id=2", "/c?id=3"):
            yhdb.add_finding(conn, hid, None, "CWE-639", "IDOR", "medium",
                             f"idor at {loc}", engagement_id=eid, location=loc)
        n = conn.execute("SELECT COUNT(*) FROM finding WHERE engagement_id=? AND title='IDOR'",
                         (eid,)).fetchone()[0]
        gk = conn.execute("SELECT DISTINCT group_key FROM finding WHERE title='IDOR'").fetchall()
    assert n == 3                      # one row per affected instance
    assert len(gk) == 1                # all roll up to one register entry


# --- evidence binding -------------------------------------------------------

def test_add_evidence_binds_and_is_queryable(tmp_db: Path) -> None:
    _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "RCE via upload", "critical", "webshell", host="10.0.0.5")
    fid = _only_finding_id(tmp_db)
    out = tool_add_evidence(tmp_db, "L", kind="output", text="id\nuid=0(root)",
                            finding=fid, caption="proof as root")
    assert "evidence #" in out
    q = tool_query(tmp_db, "L", "evidence", where={"finding_id": fid})
    assert "output" in q


def test_add_evidence_refuses_missing_file(tmp_db: Path) -> None:
    _lab(tmp_db)
    with pytest.raises(ValueError, match="missing or empty"):
        tool_add_evidence(tmp_db, "L", kind="screenshot", path="/no/such/file.png")


def test_evidence_dedup_one_artefact_many_findings(tmp_db: Path) -> None:
    eid = _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "Finding A", "low", "a", host="10.0.0.5")
    tool_add_finding(tmp_db, "L", "Finding B", "low", "b", host="10.0.0.6")
    with yhdb.transaction(tmp_db) as conn:
        ids = [r["id"] for r in conn.execute(
            "SELECT id FROM finding WHERE engagement_id=? ORDER BY id", (eid,)).fetchall()]
    tool_add_evidence(tmp_db, "L", kind="output", text="shared dump", finding=ids[0])
    tool_add_evidence(tmp_db, "L", kind="output", text="shared dump", finding=ids[1])
    with yhdb.transaction(tmp_db) as conn:
        n_ev = conn.execute("SELECT COUNT(*) FROM evidence WHERE engagement_id=?", (eid,)).fetchone()[0]
        n_link = conn.execute("SELECT COUNT(*) FROM evidence_link").fetchone()[0]
    assert n_ev == 1       # deduped by sha256
    assert n_link == 2     # but bound to both findings


def test_finding_set_rejects_bad_severity(tmp_db: Path) -> None:
    _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "x", "low", "e", host="10.0.0.5")
    fid = _only_finding_id(tmp_db)
    with pytest.raises(ValueError, match="invalid severity"):
        tool_finding_set(tmp_db, "L", fid, severity="hgih")


def test_evidence_rebind_same_finding_is_idempotent(tmp_db: Path) -> None:
    _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "F", "low", "e", host="10.0.0.5")
    fid = _only_finding_id(tmp_db)
    tool_add_evidence(tmp_db, "L", kind="screenshot", text="same proof", finding=fid)
    tool_add_evidence(tmp_db, "L", kind="screenshot", text="same proof", finding=fid)
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM evidence_link WHERE finding_id=?", (fid,)).fetchone()[0]
    assert n == 1  # NULL objective must not defeat dedup


def test_closed_finding_tag_leaves_brief_lessons(tmp_db: Path) -> None:
    # A closed finding's tag must not drive the brief (LESSONS included).
    _lab(tmp_db)
    tool_add_finding(tmp_db, "L", "AS-REP roastable", "high", "ev",
                     cls="T1558.004", host="10.0.0.5", tag="asreproastable")
    fid = _only_finding_id(tmp_db)
    tool_finding_set(tmp_db, "L", fid, status="false_positive")
    out = tool_brief(tmp_db, "L")  # full brief, includes LESSONS
    assert "asreproastable" not in out


def _only_finding_id(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        return conn.execute("SELECT id FROM finding ORDER BY id DESC LIMIT 1").fetchone()["id"]
