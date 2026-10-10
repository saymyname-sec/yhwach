"""Tests for the phase-completion judge: evidence gathering + verdict mapping."""

from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import judge as jg
from yhwach.brain import Action


class FakeBrain:
    """Returns a canned Action and records the prompt it was given."""

    def __init__(self, action: Action):
        self._action = action
        self.last_prompt: str | None = None

    def decide(self, context: str, *, history=None) -> Action:
        self.last_prompt = context
        return self._action


def _host(conn, eid, ip, stage):
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, ?, 'linux', ?, '2026-01-01T00:00:00Z')",
        (eid, ip, stage),
    )
    return int(cur.lastrowid)


# --- evidence ---------------------------------------------------------------


def test_evidence_counts_stages_and_gaps(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5", "scanned")
        _host(conn, eid, "10.0.0.6", "enumerated")
        ev = jg.gather_evidence(conn, eid)

    assert ev.stage_counts == {"scanned": 1, "enumerated": 1}
    assert ev.unenumerated_hosts == ["10.0.0.5"]
    # both non-undiscovered hosts lack a full-port scan record
    assert set(ev.hosts_missing_full_scan) == {"10.0.0.5", "10.0.0.6"}
    assert ev.obvious_incomplete() is not None


def test_evidence_clean_when_all_enumerated_and_scanned(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.6", "enumerated")
        yhdb.record_coverage(conn, hid, proto="tcp", ports="1-65535", full_range=True)
        ev = jg.gather_evidence(conn, eid)

    assert ev.unenumerated_hosts == []
    assert ev.hosts_missing_full_scan == []
    assert ev.obvious_incomplete() is None


def test_evidence_renders_deterministic_read(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5", "scanned")
        text = jg.gather_evidence(conn, eid).render()
    assert "DETERMINISTIC EVIDENCE" in text
    assert "not yet enumerated" in text


# --- verdict ----------------------------------------------------------------


def test_judge_maps_mark_phase_done_to_done(tmp_db: Path) -> None:
    brain = FakeBrain(Action(action="mark_phase_done", rationale="all clear"))
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.6", "enumerated")
        verdict = jg.judge_phase(conn, eid, brain=brain)

    assert verdict.done is True
    assert verdict.reasoning == "all clear"
    # the judge saw the brief + evidence
    assert "DETERMINISTIC EVIDENCE" in brain.last_prompt


def test_judge_maps_note_to_not_done_with_whats_left(tmp_db: Path) -> None:
    brain = FakeBrain(
        Action(
            action="note",
            rationale="two hosts unscanned",
            args={"whats_left": ["scan 10.0.0.5", "probe 10.0.0.6"]},
        )
    )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5", "scanned")
        verdict = jg.judge_phase(conn, eid, brain=brain)

    assert verdict.done is False
    assert verdict.whats_left == ["scan 10.0.0.5", "probe 10.0.0.6"]
    assert verdict.evidence is not None
