"""Tests for the SQLite bootstrap and engagement upsert."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from yhwach import db as yhdb

EXPECTED_TABLES = {
    "engagement",
    "host",
    "service",
    "surface",
    "finding",
    "credential",
    "task",
    "technique_state",
    "lore_denylist_hit",
    "event",
}


def test_init_creates_all_tables(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    names = {r["name"] for r in rows}
    missing = EXPECTED_TABLES - names
    assert not missing, f"missing tables: {missing}"


def test_init_is_idempotent(tmp_db: Path) -> None:
    # Second init on the same file should not error and should preserve data.
    with yhdb.transaction(tmp_db) as conn:
        yhdb.upsert_engagement(conn, lab="lab-x", scope="10.0.0.0/24")

    yhdb.init(tmp_db)  # keep-mode is default

    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute("SELECT lab FROM engagement WHERE lab = ?", ("lab-x",)).fetchone()
    assert row is not None
    assert row["lab"] == "lab-x"


def test_engagement_upsert_is_idempotent(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        id1 = yhdb.upsert_engagement(conn, lab="lab-a", scope="10.0.0.0/24")
        id2 = yhdb.upsert_engagement(conn, lab="lab-a", scope="10.0.0.0/24,10.0.1.0/24")
    assert id1 == id2


def test_engagement_upsert_updates_scope(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        yhdb.upsert_engagement(conn, lab="lab-b", scope="10.0.0.0/24")
        yhdb.upsert_engagement(conn, lab="lab-b", scope="10.0.0.0/24,10.0.1.0/24")
        row = conn.execute("SELECT scope FROM engagement WHERE lab = ?", ("lab-b",)).fetchone()
    assert row["scope"] == "10.0.0.0/24,10.0.1.0/24"


def test_foreign_keys_enforced(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO host (engagement_id, ip, first_seen) VALUES (?, ?, ?)",
            (9999, "10.0.0.1", "2026-01-01T00:00:00Z"),
        )


def test_engagement_id_for_returns_none_for_missing(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        assert yhdb.engagement_id_for(conn, "does-not-exist") is None


# ---- credential vault ---------------------------------------------------


def test_add_credential_appends_source_on_update(tmp_db: Path) -> None:
    """A cred rediscovered via a new channel keeps its full provenance chain,
    not just the latest source (the old code clobbered it)."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="cv", scope="10.0.0.0/24")
        yhdb.add_credential(conn, eid, "svc_app", "@ppS3rv!", "password", "sqli")
        yhdb.add_credential(conn, eid, "svc_app", "@ppS3rv!", "password", "jenkins_xml")
        row = conn.execute(
            "SELECT secret, source FROM credential WHERE identifier=?",
            ("svc_app",)).fetchone()
    assert row["secret"] == "@ppS3rv!"
    assert row["source"] == "sqli,jenkins_xml"


def test_add_credential_dedupes_repeated_source(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="cv2", scope="10.0.0.0/24")
        yhdb.add_credential(conn, eid, "admin", "admin", "password", "dump")
        yhdb.add_credential(conn, eid, "admin", "admin", "password", "dump")
        row = conn.execute(
            "SELECT source FROM credential WHERE identifier=?", ("admin",)).fetchone()
    assert row["source"] == "dump"


def test_list_credentials_joins_source_host_ip(tmp_db: Path) -> None:
    """`list_credentials` must expose `source_host_ip` so downstream (CLI,
    MCP, context) can annotate where a cred came from."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="cv3", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, first_seen) VALUES (?, ?, ?)",
            (eid, "10.0.0.10", "2026-01-01T00:00:00Z"))
        hid = int(cur.lastrowid)
        yhdb.add_credential(conn, eid, "root", "toor", "password", "dump",
                            source_host_id=hid)
        rows = yhdb.list_credentials(conn, eid)
    assert rows[0]["source_host_ip"] == "10.0.0.10"


def test_list_credentials_filters_by_kind(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="cv4", scope="10.0.0.0/24")
        yhdb.add_credential(conn, eid, "u1", "p", "password", "s")
        yhdb.add_credential(conn, eid, "u2", "----BEGIN----\nkey\n", "ssh_key", "s")
        assert [r["identifier"] for r in yhdb.list_credentials(conn, eid, kind="ssh_key")] == ["u2"]
        assert [r["identifier"] for r in yhdb.list_credentials(conn, eid, kind="password")] == ["u1"]


# ── tunnel: soft-enum kinds + agent_path (arsenal wiring) ────────────────────

def _host(conn: sqlite3.Connection, eid: int, ip: str) -> int:
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, first_seen) VALUES (?, ?, ?)",
        (eid, ip, "2026-01-01T00:00:00Z"),
    )
    return int(cur.lastrowid)


def test_add_tunnel_accepts_chisel_kind(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="tun1", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.13")
        tid, created = yhdb.add_tunnel(
            conn, eid, hid, "172.16.10.0/24", kind="chisel"
        )
        assert created is True
        row = conn.execute("SELECT kind FROM tunnel WHERE id = ?", (tid,)).fetchone()
        assert row["kind"] == "chisel"


def test_add_tunnel_records_agent_path(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="tun2", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.14")
        tid, _ = yhdb.add_tunnel(
            conn, eid, hid, "10.0.0.0/24",
            kind="ligolo", agent_path="SVCMON_WIN",
        )
        row = conn.execute(
            "SELECT agent_path FROM tunnel WHERE id = ?", (tid,)
        ).fetchone()
        assert row["agent_path"] == "SVCMON_WIN"


def test_add_tunnel_rejects_unknown_kind_when_strict(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="tun3", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.15")
        with pytest.raises(ValueError, match="unknown tunnel kind"):
            yhdb.add_tunnel(
                conn, eid, hid, "10.0.1.0/24", kind="wireguard", strict=True
            )


def test_add_tunnel_unknown_kind_accepted_by_default(tmp_db: Path) -> None:
    # strict=False (default) keeps legacy/ingest paths working. Rows with
    # unusual kinds appear in the report as-is rather than silently dropped.
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="tun4", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.16")
        tid, created = yhdb.add_tunnel(
            conn, eid, hid, "10.0.2.0/24", kind="something_new"
        )
        assert created is True
        row = conn.execute("SELECT kind FROM tunnel WHERE id = ?", (tid,)).fetchone()
        assert row["kind"] == "something_new"


def test_add_tunnel_dedupes_on_engagement_via_subnet(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="tun5", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.17")
        tid1, c1 = yhdb.add_tunnel(conn, eid, hid, "10.0.3.0/24", kind="chisel")
        tid2, c2 = yhdb.add_tunnel(conn, eid, hid, "10.0.3.0/24", kind="ligolo")
        assert c1 is True and c2 is False
        assert tid1 == tid2
        # First writer wins on kind — the dedup key doesn't include kind, so
        # a re-record with a different kind must NOT clobber the historical
        # record (that would erase the operator's original choice).
        row = conn.execute("SELECT kind FROM tunnel WHERE id = ?", (tid1,)).fetchone()
        assert row["kind"] == "chisel"


def test_tunnel_kinds_registry_is_stable():
    # If this fails, the CLI/MCP surface docstrings + CLAUDE.md need updating
    # in the same commit that adds the new kind — hence the pin.
    assert yhdb.TUNNEL_KINDS == ("ligolo", "chisel", "ssh_dyn", "socat")


def test_log_event_stamps_persona_and_rules_hash(tmp_db: Path) -> None:
    """Every event carries the persona + rule-set fingerprints (replay evidence)."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="ev", scope="10.0.0.0/24")
        yhdb.log_event(conn, eid, "enum", {"a": 1})
        yhdb.log_event(conn, eid, "enum", {"a": 2})
        rows = conn.execute(
            "SELECT persona_hash, rules_hash FROM event WHERE engagement_id = ?", (eid,)
        ).fetchall()
    assert len(rows) == 2
    for r in rows:
        assert r["persona_hash"] and r["rules_hash"]      # non-null / non-empty
    # stable across events, and the two axes are distinct fingerprints
    assert rows[0]["persona_hash"] == rows[1]["persona_hash"]
    assert rows[0]["rules_hash"] == rows[1]["rules_hash"]
    assert rows[0]["persona_hash"] != rows[0]["rules_hash"]


def test_stage_transition_records_why(tmp_db) -> None:
    """The `note` column existed from the start with no writer, so "what evidence
    moved this host to this stage" was answerable only by timestamp inference."""
    from yhwach import db as _db

    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                     "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,))
        hid = conn.execute("SELECT id FROM host WHERE ip='10.0.0.5'").fetchone()["id"]
        _db.set_host_stage(conn, eid, "10.0.0.5", "enumerated", note="probe found 3 surfaces")
        rows = _db.stage_history(conn, int(hid))
    assert len(rows) == 1
    assert rows[0]["to_stage"] == "enumerated"
    assert rows[0]["note"] == "probe found 3 surfaces"


def test_stage_transition_note_is_optional(tmp_db) -> None:
    from yhwach import db as _db

    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                     "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,))
        hid = conn.execute("SELECT id FROM host WHERE ip='10.0.0.5'").fetchone()["id"]
        _db.set_host_stage(conn, eid, "10.0.0.5", "enumerated")
        assert _db.stage_history(conn, int(hid))[0]["note"] == ""


# --- DB file permissions (Theme G minimal: 0600/0700, POSIX only) -----------


def test_init_hardens_db_perms_on_posix(tmp_path: Path) -> None:
    import os
    import stat

    db = tmp_path / "perm.db"
    yhdb.init(db)
    assert yhdb.perms_insecure(db) == []
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(db.parent).st_mode) & 0o077 == 0


def test_perms_insecure_flags_group_world_access(tmp_path: Path) -> None:
    import os

    db = tmp_path / "perm.db"
    yhdb.init(db)
    if os.name != "posix":
        # The bits do not apply on Windows; the check is a documented no-op.
        assert yhdb.perms_insecure(db) == []
        return
    os.chmod(db, 0o644)
    assert str(db) in yhdb.perms_insecure(db)
    yhdb.harden_perms(db)
    assert yhdb.perms_insecure(db) == []
