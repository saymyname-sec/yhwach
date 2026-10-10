"""Tests for the control channel: kill + approvals, and their wiring."""

from __future__ import annotations

from pathlib import Path

from yhwach import actions as act
from yhwach import control
from yhwach import db as yhdb
from yhwach import orchestrator as orch
from yhwach.brain import Action
from yhwach.knowledge import Candidate


def _candidate(**kw) -> Candidate:
    base = dict(
        technique_id="x_exploit",
        technique="x_exploit",
        host_id=1,
        host_ip="10.0.0.5",
        surface_id=None,
        surface_kind="ollama",
        risk="exploit",
        autonomy="propose",
        technique_class="ai",
        points=15,
        maps=[],
        routes=None,
        source=None,
        chained_from=None,
        rationale="applies",
    )
    base.update(kw)
    return Candidate(**base)


def _engagement(conn):
    eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
        (eid,),
    )
    return eid, int(cur.lastrowid)


# --- kill -------------------------------------------------------------------


def test_kill_scoped_to_run(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        start = control.mark_run_started(conn, eid, phase="enumeration")
        assert not control.is_killed(conn, eid, since_event_id=start)
        control.request_kill(conn, eid)
        assert control.is_killed(conn, eid, since_event_id=start)


def test_kill_before_run_does_not_leak(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        control.request_kill(conn, eid)  # stale kill from a previous run
        start = control.mark_run_started(conn, eid, phase="x")
        assert not control.is_killed(conn, eid, since_event_id=start)


# --- approvals --------------------------------------------------------------


def test_approval_grant_and_check(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        assert not control.is_approved(conn, eid, technique="x", host="10.0.0.5")
        control.grant_approval(conn, eid, technique="x", host="10.0.0.5")
        assert control.is_approved(conn, eid, technique="x", host="10.0.0.5")
        # wrong host not approved
        assert not control.is_approved(conn, eid, technique="x", host="10.0.0.9")


def test_host_agnostic_approval(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        control.grant_approval(conn, eid, technique="x", host=None)
        assert control.is_approved(conn, eid, technique="x", host="10.0.0.5")


def test_pending_approvals_inbox(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        yhdb.log_event(
            conn,
            eid,
            "approval_requested",
            {"technique": "x_exploit", "host": "10.0.0.5", "risk": "exploit"},
        )
        pend = control.pending_approvals(conn, eid)
        assert pend == [{"technique": "x_exploit", "host": "10.0.0.5", "risk": "exploit"}]
        control.grant_approval(conn, eid, technique="x_exploit", host="10.0.0.5")
        assert control.pending_approvals(conn, eid) == []


# --- wiring -----------------------------------------------------------------


def test_approved_gated_move_executes(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        control.grant_approval(conn, eid, technique="x_exploit", host="10.0.0.5")
        ex = act.ActionExecutor(conn, eid)  # allow_gated=False
        res = ex.execute(
            Action(
                action="run_technique",
                technique_id="x_exploit",
                host_ip="10.0.0.5",
                rationale="approved",
            ),
            candidates=[_candidate(host_id=hid)],
        )
    assert res.outcome is act.Outcome.EXECUTED


def test_kill_halts_the_loop(tmp_db: Path) -> None:
    # An external kill arriving mid-run stops the loop at the next iteration.
    class DoneJudge:
        def decide(self, context, *, history=None):
            return Action(action="mark_phase_done", rationale="ok")

    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        yhdb.upsert_surface(conn, hid, None, "ollama", "none", "{}")

        class KillingDoer:
            def decide(self, context, *, history=None):
                # simulate the UI killing the run after the first turn
                control.request_kill(conn, eid)
                return Action(action="note", rationale="one step then killed")

        report = orch.Orchestrator(conn, eid, doer=KillingDoer(), judge_brain=DoneJudge()).run()

    assert report.halt_reason == "killed"
    assert len(report.iterations) == 1  # one turn ran before the kill was seen
