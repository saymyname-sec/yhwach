"""Phase 1 — engagement profile (kind + record_only gate), typed scope, and
credential provenance."""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach import scope as yhscope
from yhwach.mcp_tools import tool_add_cred, tool_engage, tool_scan, tool_scope

# --- active_mode / arming ---------------------------------------------------

def test_default_active_mode() -> None:
    assert yhdb.default_active_mode(None) == "armed"
    assert yhdb.default_active_mode("lab") == "armed"
    assert yhdb.default_active_mode("ctf") == "armed"
    assert yhdb.default_active_mode("internal") == "record_only"
    assert yhdb.default_active_mode("bounty") == "record_only"


def test_non_lab_engagement_starts_record_only(tmp_db: Path) -> None:
    tool_engage(tmp_db, "corp", "10.0.0.0/24", kind="internal")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        assert yhdb.engagement_armed(conn, eid) is False


def test_lab_engagement_starts_armed(tmp_db: Path) -> None:
    tool_engage(tmp_db, "lab1", "10.0.0.0/24", kind="lab")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "lab1")
        assert yhdb.engagement_armed(conn, eid) is True


def test_scan_refused_in_record_only(tmp_db: Path) -> None:
    tool_engage(tmp_db, "corp", "10.0.0.0/24", kind="internal")
    with pytest.raises(ValueError, match="record_only"):
        tool_scan(tmp_db, "corp", host="10.0.0.5")


def test_arm_enables_active_tools(tmp_db: Path) -> None:
    tool_engage(tmp_db, "corp", "10.0.0.0/24", kind="internal")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        yhdb.set_active_mode(conn, eid, "armed")
        assert yhdb.engagement_armed(conn, eid) is True


# --- credential provenance --------------------------------------------------

def test_provided_credential_is_not_sprayed(tmp_db: Path) -> None:
    tool_engage(tmp_db, "corp", "10.0.0.0/24", kind="lab")  # armed, so spray would run
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        # The /24 is auto-materialised; promote an existing host and give it SMB
        # so there IS a spray target.
        hid = conn.execute(
            "SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.5'", (eid,)
        ).fetchone()["id"]
        conn.execute("UPDATE host SET stage='scanned' WHERE id=?", (hid,))
        conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                     "VALUES (?, 445, 'tcp', 'Samba', 't')", (hid,))
    # A provided cred must not become a spray candidate.
    tool_add_cred(tmp_db, "corp", "svc", "Winter2026", kind="password", provided=True)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        from yhwach import sprayer as yhspray
        creds = yhspray._candidate_creds(conn, eid)
    assert creds == []


def test_discovered_credential_is_a_spray_candidate(tmp_db: Path) -> None:
    tool_engage(tmp_db, "corp", "10.0.0.0/24", kind="lab")
    tool_add_cred(tmp_db, "corp", "svc", "Winter2026", kind="password")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        from yhwach import sprayer as yhspray
        creds = yhspray._candidate_creds(conn, eid)
    assert len(creds) == 1


# --- typed scope ------------------------------------------------------------

def test_scope_classify() -> None:
    assert yhscope.classify_token("10.0.0.0/24") == "cidr"
    assert yhscope.classify_token("10.0.0.5") == "ip"
    assert yhscope.classify_token("*.example.com") == "wildcard"
    assert yhscope.classify_token("app.example.com") == "hostname"
    assert yhscope.classify_token("10.0.0.0/99") is None
    assert yhscope.classify_token("bad token!") is None


def test_assert_target_cidr_and_exclude(tmp_db: Path) -> None:
    tool_engage(tmp_db, "corp", "10.20.0.0/16", kind="internal")
    tool_scope(tmp_db, "corp", action="exclude", target="10.20.5.0/24")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        assert yhscope.assert_target(conn, eid, "10.20.1.10")[0] is True
        # Exclude wins over the broader include.
        assert yhscope.assert_target(conn, eid, "10.20.5.10")[0] is False
        # Outside every include.
        assert yhscope.assert_target(conn, eid, "10.99.0.1")[0] is False


def test_assert_target_wildcard(tmp_db: Path) -> None:
    tool_engage(tmp_db, "bb", "*.example.com", kind="bounty")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "bb")
        assert yhscope.assert_target(conn, eid, "api.example.com")[0] is True
        assert yhscope.assert_target(conn, eid, "evil.com")[0] is False
        # *.example.com must NOT match the apex (review finding #3).
        assert yhscope.assert_target(conn, eid, "example.com")[0] is False
        assert yhscope.assert_target(conn, eid, "notexample.com")[0] is False


def test_exclude_wins_through_sprayer_candidates(tmp_db: Path) -> None:
    """An excluded host must not be a spray candidate even though it is inside a
    broader include (review finding #2)."""
    from yhwach import sprayer as yhspray

    tool_engage(tmp_db, "corp", "10.20.0.0/16", kind="lab")  # armed
    tool_scope(tmp_db, "corp", action="exclude", target="10.20.5.0/24")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "corp")
        for ip in ("10.20.1.10", "10.20.5.10"):
            hid = conn.execute(
                "INSERT INTO host (engagement_id, ip, stage, first_seen) "
                "VALUES (?, ?, 'scanned', 't')", (eid, ip)).lastrowid
            conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                         "VALUES (?, 445, 'tcp', 'Samba', 't')", (hid,))
        ips = {s["ip"] for s in yhspray._candidate_services(conn, eid)}
    assert "10.20.1.10" in ips
    assert "10.20.5.10" not in ips  # excluded


def test_legacy_engagement_keeps_includes_when_exclude_added(tmp_db: Path) -> None:
    """Adding an exclude to a legacy (string-only) engagement must not drop the
    legacy include scope (review findings #4/#8)."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="legacy", scope="10.0.0.0/24")
    tool_scope(tmp_db, "legacy", action="exclude", target="10.0.0.9")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "legacy")
        assert yhscope.assert_target(conn, eid, "10.0.0.20")[0] is True   # still in scope
        assert yhscope.assert_target(conn, eid, "10.0.0.9")[0] is False   # excluded


def test_empty_scope_refuses_traffic(tmp_db: Path) -> None:
    # An engagement row with no scope_entry rows and no legacy string refuses.
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="empty", scope="")
        ok, reason = yhscope.assert_target(conn, eid, "10.0.0.5")
    assert ok is False and "no scope" in reason


def test_legacy_scope_string_still_gates(tmp_db: Path) -> None:
    # A DB seeded straight through upsert_engagement (no scope_entry rows) still
    # gates on the engagement.scope string via the matcher fallback.
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="legacy", scope="10.0.0.0/24")
        assert yhscope.assert_target(conn, eid, "10.0.0.9")[0] is True
        assert yhscope.assert_target(conn, eid, "10.9.9.9")[0] is False


# --- schema parity ----------------------------------------------------------

def test_fresh_init_has_every_migrated_column_and_table(tmp_path: Path) -> None:
    """schema.sql ALONE (no self-heal migration) must already define every column
    and table the migration would add — otherwise a fresh DB and an upgraded DB
    diverge. Must inspect through a RAW sqlite3 connection: yhdb.connect() runs
    _migrate() on open, which would ALTER-add the very columns under test and
    make the assertion tautological."""
    import sqlite3

    from yhwach import schema_sql_path

    raw = sqlite3.connect(str(tmp_path / "raw.db"))
    try:
        raw.executescript(schema_sql_path().read_text(encoding="utf-8"))
        tables = {r[0] for r in
                  raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for tname in yhdb._ADDED_TABLES:
            assert tname in tables, f"schema.sql missing table {tname}"
        for tname, col, _decl in yhdb._ADDED_COLUMNS:
            cols = {r[1] for r in raw.execute(f"PRAGMA table_info({tname})")}
            assert col in cols, f"schema.sql missing {tname}.{col}"
    finally:
        raw.close()
