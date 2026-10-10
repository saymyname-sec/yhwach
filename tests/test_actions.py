"""Tests for the action executor: validation, gating, execution, recording."""

from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import actions as act
from yhwach import db as yhdb
from yhwach.brain import Action
from yhwach.knowledge import Candidate


def _candidate(**kw) -> Candidate:
    base = dict(
        technique_id="ollama_unauth_api",
        technique="ollama_unauth_api",
        host_id=1,
        host_ip="10.0.0.5",
        surface_id=1,
        surface_kind="ollama",
        risk="read_only",
        autonomy="proceed",
        technique_class="ai",
        points=15,
        maps=["LLM06"],
        routes=None,
        source=None,
        chained_from=None,
        rationale="applies",
    )
    base.update(kw)
    return Candidate(**base)


def _engagement(conn) -> tuple[int, int]:
    eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
        (eid,),
    )
    host_id = int(cur.lastrowid)
    # A real surface so findings tied to surface_id=1 satisfy the FK.
    yhdb.upsert_surface(conn, host_id, None, "ollama", "none", "{}")
    return eid, host_id


# --- validation -------------------------------------------------------------


def test_unknown_action_rejected(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        with pytest.raises(act.ActionError, match="unknown action"):
            ex.execute(Action(action="frobnicate", rationale="?"), candidates=[])


def test_run_technique_not_in_menu_is_rejected(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        # brain names a technique that is not an applicable candidate
        with pytest.raises(act.ActionError, match="not an applicable candidate"):
            ex.execute(
                Action(action="run_technique", technique_id="made_up", rationale="x"),
                candidates=[_candidate(host_id=hid)],
            )


def test_run_technique_requires_id(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        with pytest.raises(act.ActionError, match="requires a technique_id"):
            ex.execute(Action(action="run_technique", rationale="x"), candidates=[])


# --- gating -----------------------------------------------------------------


def test_read_only_proceeds_and_records_attempt(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        res = ex.execute(
            Action(
                action="run_technique",
                technique_id="ollama_unauth_api",
                host_ip="10.0.0.5",
                rationale="free recon",
            ),
            candidates=[_candidate(host_id=hid)],
        )
        assert res.outcome is act.Outcome.EXECUTED
        attempts = yhdb.list_attempts(conn, eid)
    assert len(attempts) == 1
    assert attempts[0]["playbook_rule_id"] == "ollama_unauth_api"


def test_exploit_is_gated_by_default(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        res = ex.execute(
            Action(action="run_technique", technique_id="x_exploit", rationale="pop it"),
            candidates=[
                _candidate(
                    technique_id="x_exploit", autonomy="propose", risk="exploit", host_id=hid
                )
            ],
        )
        assert res.outcome is act.Outcome.QUEUED
        # no attempt recorded — it's waiting on a human
        assert yhdb.list_attempts(conn, eid) == []


def test_exploit_proceeds_when_gated_allowed(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid, allow_gated=True)
        res = ex.execute(
            Action(action="run_technique", technique_id="x_exploit", rationale="pop it"),
            candidates=[
                _candidate(
                    technique_id="x_exploit", autonomy="propose", risk="exploit", host_id=hid
                )
            ],
        )
        assert res.outcome is act.Outcome.EXECUTED


def test_destructive_never_proceeds_even_when_allowed(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid, allow_gated=True)
        res = ex.execute(
            Action(action="run_technique", technique_id="x_wipe", rationale="nuke"),
            candidates=[
                _candidate(technique_id="x_wipe", autonomy="ask", risk="destructive", host_id=hid)
            ],
        )
        assert res.outcome is act.Outcome.QUEUED


# --- runner + findings ------------------------------------------------------


def test_runner_output_becomes_findings(tmp_db: Path) -> None:
    def runner(cand: Candidate) -> act.RunResult:
        return act.RunResult(
            result="success",
            evidence="3 models exposed",
            findings=[{"title": "ollama unauth", "tag": "ollama_models", "severity": "high"}],
        )

    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid, runner=runner)
        res = ex.execute(
            Action(
                action="run_technique",
                technique_id="ollama_unauth_api",
                host_ip="10.0.0.5",
                rationale="recon",
            ),
            candidates=[_candidate(host_id=hid)],
        )
        assert res.outcome is act.Outcome.EXECUTED
        assert len(res.finding_ids) == 1
        rows = conn.execute(
            "SELECT tag, status FROM finding WHERE engagement_id=?", (eid,)
        ).fetchall()
    assert rows[0]["tag"] == "ollama_models"
    assert rows[0]["status"] == "open"


# --- signals ----------------------------------------------------------------


def test_mark_phase_done_records_event(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        res = ex.execute(
            Action(action="mark_phase_done", rationale="all enumerated"), candidates=[]
        )
        assert res.outcome is act.Outcome.RECORDED
        row = conn.execute("SELECT kind FROM event WHERE id=?", (res.event_id,)).fetchone()
    assert row["kind"] == "phase_done_requested"


def test_note_records_event(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        res = ex.execute(Action(action="note", rationale="DC looks juicy"), candidates=[])
        assert res.outcome is act.Outcome.RECORDED


def test_out_of_scope_host_is_denied(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)  # scope 10.0.0.0/24
        ex = act.ActionExecutor(conn, eid)
        res = ex.execute(
            Action(action="run_technique", technique_id="ollama_unauth_api",
                   host_ip="10.9.9.9", rationale="oob"),
            candidates=[_candidate(host_id=hid, host_ip="10.9.9.9")],
        )
        assert res.outcome is act.Outcome.DENIED
        assert "out of scope" in res.detail
        assert yhdb.list_attempts(conn, eid) == []  # nothing ran


# --- action-class guardrail (policy.class_gate wiring) ----------------------


def _run(ex, hid, **cand_kw):
    return ex.execute(
        Action(action="run_technique", technique_id="ollama_unauth_api", rationale="x"),
        candidates=[_candidate(host_id=hid, **cand_kw)],
    )


def test_dangerous_class_queued_without_grant(tmp_db: Path) -> None:
    # A read-only-autonomy candidate that is tagged high-consequence must still
    # queue for approval when no --allow grant covers its class.
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)  # no grants
        res = _run(ex, hid, action_class="listener")
        assert res.outcome is act.Outcome.QUEUED
        assert "listener" in res.detail
        assert yhdb.list_attempts(conn, eid) == []  # nothing ran
        row = conn.execute(
            "SELECT payload_json FROM event WHERE engagement_id=? AND kind='approval_requested'",
            (eid,),
        ).fetchone()
        assert row is not None and "listener" in row["payload_json"]


def test_dangerous_class_runs_with_grant(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid, grants={"listener"})
        res = _run(ex, hid, action_class="listener")
        assert res.outcome is act.Outcome.EXECUTED


def test_allow_gated_does_not_grant_class(tmp_db: Path) -> None:
    # Full exploit autonomy (allow_gated) must NOT cover a dangerous class.
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid, allow_gated=True)  # no class grant
        res = _run(ex, hid, action_class="push", risk="exploit", autonomy="propose")
        assert res.outcome is act.Outcome.QUEUED
        assert "push" in res.detail


def test_standing_approval_clears_class_gate(tmp_db: Path) -> None:
    from yhwach import control

    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        control.grant_approval(conn, eid, technique="ollama_unauth_api", host="10.0.0.5")
        ex = act.ActionExecutor(conn, eid)  # no --allow grant, but human approved
        res = _run(ex, hid, action_class="push")
        assert res.outcome is act.Outcome.EXECUTED


def test_untagged_candidate_unaffected(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        ex = act.ActionExecutor(conn, eid)
        res = _run(ex, hid)  # action_class defaults to None
        assert res.outcome is act.Outcome.EXECUTED
