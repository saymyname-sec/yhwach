"""I66 — bulk add_findings / add_creds.

One call, one transaction, same dedupe as the singular tools. The spray default
comes from the engagement mode (armed or not) — never forced on.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_add_creds, tool_add_findings


def _eng(path: Path, kind: str = "internal") -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24", kind=kind)
        conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                     "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,))
        return eid


def test_bulk_findings_insert_and_tag(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    out = tool_add_findings(tmp_db, "L", [
        {"title": "Anon SMB", "severity": "high", "host": "10.0.0.5", "tag": "writable_share"},
        {"title": "Info leak", "severity": "low"},
    ])
    assert "2 new" in out
    assert "writable_share" in out
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) n FROM finding WHERE engagement_id=?", (eid,)).fetchone()["n"]
    assert n == 2


def test_bulk_findings_dedupe_on_reinsert(tmp_db: Path) -> None:
    _eng(tmp_db)
    items = [{"title": "Anon SMB", "severity": "high", "host": "10.0.0.5"}]
    tool_add_findings(tmp_db, "L", items)
    out = tool_add_findings(tmp_db, "L", items)
    assert "0 new" in out and "1 updated" in out


def test_bulk_findings_requires_title_and_severity(tmp_db: Path) -> None:
    import pytest

    _eng(tmp_db)
    with pytest.raises(ValueError, match="title and severity"):
        tool_add_findings(tmp_db, "L", [{"title": "no severity"}])


def test_bulk_creds_insert_and_manual_policy(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    tool_add_creds(tmp_db, "L", [
        {"identifier": "svc", "secret": "P@ss", "kind": "password"},
        {"identifier": "adm", "secret": "deadbeef", "kind": "ntlm", "spray_policy": "manual"},
    ])
    with yhdb.transaction(tmp_db) as conn:
        rows = {r["identifier"]: r["spray_policy"] for r in conn.execute(
            "SELECT identifier, spray_policy FROM credential WHERE engagement_id=?", (eid,))}
    assert rows == {"svc": None, "adm": "manual"}


def test_bulk_creds_does_not_spray_when_not_armed(tmp_db: Path) -> None:
    _eng(tmp_db, kind="internal")   # record_only by default
    out = tool_add_creds(tmp_db, "L", [{"identifier": "svc", "secret": "x"}])
    assert "autospray off: not armed" in out


def test_bulk_creds_provided_flag(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_add_creds(tmp_db, "L", [{"identifier": "svc", "secret": "x", "provided": True}])
    with yhdb.transaction(tmp_db) as conn:
        prov = conn.execute("SELECT provenance FROM credential WHERE identifier='svc'").fetchone()["provenance"]
    assert prov == "provided"


def test_empty_lists_are_a_no_op(tmp_db: Path) -> None:
    _eng(tmp_db)
    assert "non-empty list" in tool_add_findings(tmp_db, "L", [])
    assert "non-empty list" in tool_add_creds(tmp_db, "L", [])


def test_lab_engagement_sprays_bulk_creds(tmp_db: Path) -> None:
    # a lab engagement is armed by default -> the single autospray pass runs.
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24", kind="lab")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                     "VALUES (?, 22, 'tcp', 'ssh', 't')", (hid,))
    out = tool_add_creds(tmp_db, "L", [{"identifier": "root", "secret": "toor"}])
    assert "autospray:" in out   # ran (hit count may be 0 without nxc)
