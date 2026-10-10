"""Tests for credential_access + validation tracking (Phase 1: Creds Vault)."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb


def _host(conn, eid: int, ip: str) -> int:
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, first_seen) VALUES (?, ?, ?)",
        (eid, ip, "2026-01-01T00:00:00Z"),
    )
    return int(cur.lastrowid)


def test_credential_access_table_exists(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    assert "credential_access" in {r["name"] for r in rows}


def test_list_credentials_exposes_id(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="ca1", scope="10.0.0.0/24")
        cid, _ = yhdb.add_credential(conn, eid, "u", "p", "password", "s")
        rows = yhdb.list_credentials(conn, eid)
    assert rows[0]["id"] == cid


def test_record_cred_access_dedups_and_upgrades(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="ca2", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.5")
        cid, _ = yhdb.add_credential(conn, eid, "admin", "pw", "password", "s")
        a = yhdb.record_cred_access(conn, eid, cid, hid, port=445, proto="smb")
        b = yhdb.record_cred_access(conn, eid, cid, hid, port=445, proto="smb", result="admin")
        assert a == b  # same (cred, host, proto, port) → one row
        row = conn.execute("SELECT result FROM credential_access WHERE id=?", (a,)).fetchone()
        assert row["result"] == "admin"  # success upgraded to admin
        # admin is never downgraded back to success
        yhdb.record_cred_access(conn, eid, cid, hid, port=445, proto="smb", result="success")
        row = conn.execute("SELECT result FROM credential_access WHERE id=?", (a,)).fetchone()
        assert row["result"] == "admin"


def test_mark_credential_validated_sets_host_and_access(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="ca3", scope="10.0.0.0/24")
        h1 = _host(conn, eid, "10.0.0.5")
        h2 = _host(conn, eid, "10.0.0.6")
        cid, _ = yhdb.add_credential(conn, eid, "svc", "pw", "password", "s")
        yhdb.mark_credential_validated(conn, eid, cid, h1, port=5985, proto="winrm")
        row = conn.execute(
            "SELECT validated_on_host_id FROM credential WHERE id=?", (cid,)).fetchone()
        assert row["validated_on_host_id"] == h1  # first proof wins
        # a non-admin proof on another host does NOT move the slot
        yhdb.mark_credential_validated(conn, eid, cid, h2, port=445, proto="smb")
        row = conn.execute(
            "SELECT validated_on_host_id FROM credential WHERE id=?", (cid,)).fetchone()
        assert row["validated_on_host_id"] == h1
        # an admin proof always takes the slot
        yhdb.mark_credential_validated(conn, eid, cid, h2, port=445, proto="smb", result="admin")
        row = conn.execute(
            "SELECT validated_on_host_id FROM credential WHERE id=?", (cid,)).fetchone()
        assert row["validated_on_host_id"] == h2


def test_list_credential_access_groups_by_cred(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="ca4", scope="10.0.0.0/24")
        h1 = _host(conn, eid, "10.0.0.5")
        h2 = _host(conn, eid, "10.0.0.6")
        cid, _ = yhdb.add_credential(conn, eid, "admin", "pw", "password", "s")
        yhdb.mark_credential_validated(conn, eid, cid, h1, port=5985, proto="winrm")
        yhdb.mark_credential_validated(conn, eid, cid, h2, port=445, proto="smb", result="admin")
        grouped = yhdb.list_credential_access(conn, eid)
    assert set(grouped) == {cid}
    targets = {(r["host_ip"], r["proto"], r["result"]) for r in grouped[cid]}
    assert ("10.0.0.5", "winrm", "success") in targets
    assert ("10.0.0.6", "smb", "admin") in targets


def test_parse_validated_on() -> None:
    from yhwach.mcp_tools import _parse_validated_on

    assert _parse_validated_on("10.1.1.1") == ("10.1.1.1", None, None)
    assert _parse_validated_on("10.1.1.1:445") == ("10.1.1.1", 445, None)
    assert _parse_validated_on("10.1.1.1:5985/winrm") == ("10.1.1.1", 5985, "winrm")
    assert _parse_validated_on("10.1.1.1/ssh") == ("10.1.1.1", None, "ssh")
