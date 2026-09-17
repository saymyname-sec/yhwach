"""Tests for proof binding + the foothold -> looted screenshot gate."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb


def _seed_host(tmp_db: Path, stage: str = "foothold", ip: str = "10.0.0.5") -> tuple[int, int]:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="p", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) VALUES (?, ?, ?, ?)",
            (eng, ip, stage, "2026-01-01T00:00:00Z"))
        return eng, int(cur.lastrowid)


def test_add_proof_inserts_row(tmp_db: Path) -> None:
    _, hid = _seed_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        pid = yhdb.add_proof(conn, hid, "/root/proof.txt", "/root/shots/flag.png",
                             flag_content="OSAI{demo}")
        row = conn.execute("SELECT * FROM proof WHERE id = ?", (pid,)).fetchone()
    assert pid > 0
    assert row["screenshot_path"] == "/root/shots/flag.png"
    assert row["flag_content"] == "OSAI{demo}"
    assert row["scored"] == 0


def test_looted_refused_without_proof(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db, "foothold")
    with yhdb.transaction(tmp_db) as conn:
        changed, msg = yhdb.set_host_stage(conn, eng, "10.0.0.5", "looted")
    assert changed is False
    assert "proof" in msg


def test_looted_allowed_with_proof(tmp_db: Path) -> None:
    eng, hid = _seed_host(tmp_db, "foothold")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_proof(conn, hid, "-", "/root/shots/flag.png")
        changed, msg = yhdb.set_host_stage(conn, eng, "10.0.0.5", "looted")
        stage = conn.execute("SELECT stage FROM host WHERE ip='10.0.0.5'").fetchone()["stage"]
    assert changed is True and msg is None
    assert stage == "looted"


def test_looted_gate_bypassed_with_force(tmp_db: Path) -> None:
    eng, _ = _seed_host(tmp_db, "foothold")
    with yhdb.transaction(tmp_db) as conn:
        changed, _ = yhdb.set_host_stage(conn, eng, "10.0.0.5", "looted", monotonic=False)
    assert changed is True


def test_empty_screenshot_does_not_satisfy_gate(tmp_db: Path) -> None:
    eng, hid = _seed_host(tmp_db, "foothold")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_proof(conn, hid, "-", "")  # no real screenshot path
        changed, msg = yhdb.set_host_stage(conn, eng, "10.0.0.5", "looted")
    assert changed is False
    assert "proof" in msg
