"""Phase 5: host tags + stage-transition history."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb


def _host(conn, eid: int, ip: str) -> int:
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, stage, first_seen) VALUES (?, ?, 'scanned', 't')",
        (eid, ip))
    return int(cur.lastrowid)


def test_host_tag_add_dedup_remove(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t1", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5")
        ok, _ = yhdb.add_host_tag(conn, eid, "10.0.0.5", "AI-Target")  # normalises case
        assert ok
        yhdb.add_host_tag(conn, eid, "10.0.0.5", "ai-target")  # dedup
        yhdb.add_host_tag(conn, eid, "10.0.0.5", "dual-homed")
        hid = conn.execute("SELECT id FROM host WHERE ip='10.0.0.5'").fetchone()["id"]
        assert sorted(yhdb.tags_for_hosts(conn, eid)[hid]) == ["ai-target", "dual-homed"]
        assert yhdb.remove_host_tag(conn, eid, "10.0.0.5", "ai-target") is True
        assert yhdb.tags_for_hosts(conn, eid)[hid] == ["dual-homed"]


def test_tag_missing_host(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t2", scope="10.0.0.0/24")
        ok, msg = yhdb.add_host_tag(conn, eid, "10.9.9.9", "dc")
        assert ok is False and "not found" in msg


def test_stage_transition_recorded_on_advance(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t3", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.5")
        yhdb.set_host_stage(conn, eid, "10.0.0.5", "enumerated")
        yhdb.set_host_stage(conn, eid, "10.0.0.5", "foothold")
        yhdb.set_host_stage(conn, eid, "10.0.0.5", "foothold")  # no-op, no new row
        hist = yhdb.stage_history(conn, hid)
    trail = [(r["from_stage"], r["to_stage"]) for r in hist]
    assert trail == [("scanned", "enumerated"), ("enumerated", "foothold")]


def test_stage_transition_not_recorded_when_refused(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t4", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.5")
        yhdb.set_host_stage(conn, eid, "10.0.0.5", "looted")
        changed, _ = yhdb.set_host_stage(conn, eid, "10.0.0.5", "scanned")  # backwards → refused
        assert changed is False
        # only the forward transition is on record
        assert [r["to_stage"] for r in yhdb.stage_history(conn, hid)] == ["looted"]
