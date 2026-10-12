"""Tests for worker_state heartbeats (Phase 2: gaze panel)."""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb


def test_worker_state_table_exists(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    assert "worker_state" in {r["name"] for r in rows}


def test_heartbeat_upserts_one_row_per_host(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="w1", scope="10.0.0.0/24")
        yhdb.heartbeat_worker(conn, eid, "10.0.0.5", "watching", focus="esc1", cmd="certipy req")
        yhdb.heartbeat_worker(conn, eid, "10.0.0.5", "done")  # focus/cmd preserved on omit
        rows = yhdb.list_worker_state(conn, eid)
    assert len(rows) == 1
    assert rows[0]["status"] == "done"
    assert rows[0]["focus"] == "esc1" and rows[0]["cmd"] == "certipy req"


def test_run_status_running_on_fresh_heartbeat(tmp_db: Path) -> None:
    pytest.importorskip("fastapi")  # ui panel needs the [ui] extra; skip like test_ui.py
    from yhwach import ui

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="w2", scope="10.0.0.0/24")
        yhdb.heartbeat_worker(conn, eid, "10.0.0.5", "watching")
        assert ui._run_status(conn, eid) == "RUNNING"


def test_run_status_idle_on_stale_heartbeat(tmp_db: Path) -> None:
    pytest.importorskip("fastapi")  # ui panel needs the [ui] extra; skip like test_ui.py
    from yhwach import ui

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="w3", scope="10.0.0.0/24")
        conn.execute(
            "INSERT INTO worker_state (engagement_id, host_ip, status, updated_at) "
            "VALUES (?, '10.0.0.5', 'watching', '2000-01-01T00:00:00Z')",
            (eid,),
        )
        assert ui._run_status(conn, eid) == "idle"


