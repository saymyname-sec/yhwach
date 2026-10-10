"""Tests for `upsert_surface` and the scanned-hosts-with-ports lookup."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb


def _seed_engagement_and_host(tmp_db: Path) -> tuple[int, int, int]:
    """Helper: create an engagement + one linux host + one service on 11434.

    Returns (engagement_id, host_id, service_id).
    """
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="fixt", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng_id, "10.0.0.5"),
        )
        host_id = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 11434, 'tcp', 'ollama', '2026-01-01T00:00:00Z')",
            (host_id,),
        )
        service_id = int(cur.lastrowid)
    return eng_id, host_id, service_id


def test_upsert_surface_creates_row(tmp_db: Path) -> None:
    _, host_id, svc_id = _seed_engagement_and_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        sid, created = yhdb.upsert_surface(
            conn, host_id=host_id, service_id=svc_id,
            kind="ollama", auth="none", meta_json='{"endpoint":"/api/tags"}',
        )
        assert created is True
        row = conn.execute("SELECT kind, auth FROM surface WHERE id = ?", (sid,)).fetchone()
    assert row["kind"] == "ollama"
    assert row["auth"] == "none"


def test_upsert_surface_updates_existing(tmp_db: Path) -> None:
    _, host_id, svc_id = _seed_engagement_and_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        sid1, created1 = yhdb.upsert_surface(
            conn, host_id, svc_id, "ollama", "none", '{"endpoint":"/api/tags"}',
        )
        sid2, created2 = yhdb.upsert_surface(
            conn, host_id, svc_id, "ollama", "bearer", '{"endpoint":"/api/tags","note":"auth added"}',
        )
        rows = conn.execute("SELECT COUNT(*) AS n FROM surface").fetchone()

    assert sid1 == sid2
    assert created1 is True and created2 is False
    assert rows["n"] == 1


def test_upsert_surface_with_null_service_id(tmp_db: Path) -> None:
    """A host-general surface (service_id NULL) should dedupe by (host, kind)."""
    _, host_id, _ = _seed_engagement_and_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        sid1, c1 = yhdb.upsert_surface(conn, host_id, None, "mcp", "none", "{}")
        sid2, c2 = yhdb.upsert_surface(conn, host_id, None, "mcp", "none", "{}")
        n = conn.execute("SELECT COUNT(*) AS n FROM surface").fetchone()["n"]
    assert sid1 == sid2
    assert c1 is True and c2 is False
    assert n == 1


def test_upsert_surface_different_kinds_coexist(tmp_db: Path) -> None:
    _, host_id, svc_id = _seed_engagement_and_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.upsert_surface(conn, host_id, svc_id, "ollama", "none", "{}")
        yhdb.upsert_surface(conn, host_id, svc_id, "openai_compat", "none", "{}")
        rows = conn.execute("SELECT kind FROM surface ORDER BY kind").fetchall()
    assert [r["kind"] for r in rows] == ["ollama", "openai_compat"]


def test_scanned_hosts_with_ports_returns_expected(tmp_db: Path) -> None:
    eng_id, host_id, svc_id = _seed_engagement_and_host(tmp_db)
    # add a second host with a non-AI port; should be excluded
    with yhdb.transaction(tmp_db) as conn:
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng_id, "10.0.0.6"),
        )
        host2_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 22, 'tcp', '2026-01-01T00:00:00Z')",
            (host2_id,),
        )

    with yhdb.transaction(tmp_db) as conn:
        targets = yhdb.scanned_hosts_with_ports(conn, eng_id, [11434, 7860, 8000])

    assert len(targets) == 1
    assert targets[0]["ip"] == "10.0.0.5"
    assert targets[0]["port"] == 11434
    assert targets[0]["host_id"] == host_id
    assert targets[0]["service_id"] == svc_id


def test_scanned_hosts_with_ports_empty_returns_empty(tmp_db: Path) -> None:
    eng_id, _, _ = _seed_engagement_and_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        assert yhdb.scanned_hosts_with_ports(conn, eng_id, []) == []
