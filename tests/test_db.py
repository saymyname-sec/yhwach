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
    "proof",
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
        yhdb.add_credential(conn, eid, "svc_portal", "P0rt@l!", "password", "sqli")
        yhdb.add_credential(conn, eid, "svc_portal", "P0rt@l!", "password", "jenkins_xml")
        row = conn.execute(
            "SELECT secret, source FROM credential WHERE identifier=?",
            ("svc_portal",)).fetchone()
    assert row["secret"] == "P0rt@l!"
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
