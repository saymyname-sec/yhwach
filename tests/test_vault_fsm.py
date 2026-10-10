"""Tests for the credential vault, host FSM transitions, and event log."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb


def _seed_host(tmp_db: Path, stage: str = "scanned", ip: str = "10.0.0.5") -> tuple[int, int]:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="v", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) VALUES (?, ?, ?, ?)",
            (eng, ip, stage, "2026-01-01T00:00:00Z"))
        return eng, int(cur.lastrowid)


def test_set_host_stage_advances(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db, "scanned")
    with yhdb.transaction(tmp_db) as conn:
        changed, msg = yhdb.set_host_stage(conn, eng, "10.0.0.5", "foothold")
        stage = conn.execute("SELECT stage FROM host WHERE ip='10.0.0.5'").fetchone()["stage"]
    assert changed is True and msg is None
    assert stage == "foothold"


def test_set_host_stage_refuses_backward(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db, "looted")
    with yhdb.transaction(tmp_db) as conn:
        changed, msg = yhdb.set_host_stage(conn, eng, "10.0.0.5", "scanned")
    assert changed is False
    assert "refusing" in msg


def test_set_host_stage_backward_with_force(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db, "looted")
    with yhdb.transaction(tmp_db) as conn:
        changed, _ = yhdb.set_host_stage(conn, eng, "10.0.0.5", "scanned", monotonic=False)
    assert changed is True


def test_blocked_always_allowed(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db, "foothold")
    with yhdb.transaction(tmp_db) as conn:
        changed, _ = yhdb.set_host_stage(conn, eng, "10.0.0.5", "blocked")
    assert changed is True


def test_add_and_list_credentials(tmp_db: Path) -> None:
    eng, hid = _seed_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        _, c1 = yhdb.add_credential(conn, eng, "svc_admin", "P@ss", "password", "dump", hid)
        _, c2 = yhdb.add_credential(conn, eng, "svc_admin", "P@ss2", "password", "spray", hid)  # update
        rows = yhdb.list_credentials(conn, eng)
    assert c1 is True and c2 is False
    assert len(rows) == 1
    assert rows[0]["identifier"] == "svc_admin"
    assert rows[0]["secret"] == "P@ss2"  # updated


def test_credentials_deduped_by_kind(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "admin", "hash", "ntlm", "dump")
        yhdb.add_credential(conn, eng, "admin", "plain", "password", "crack")
        rows = yhdb.list_credentials(conn, eng)
    assert len(rows) == 2  # same identifier, different kind -> two entries


def test_log_event_appends(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.log_event(conn, eng, "stage", {"host": "10.0.0.5", "stage": "foothold"})
        yhdb.log_event(conn, eng, "credential", {"id": "admin"})
        n = conn.execute("SELECT COUNT(*) AS n FROM event WHERE engagement_id=?", (eng,)).fetchone()["n"]
    assert n == 2
