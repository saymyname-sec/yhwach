"""Tests for the orchestrator loop, driven by scripted fake brains."""

from __future__ import annotations

from pathlib import Path

from yhwach import actions as act
from yhwach import db as yhdb
from yhwach import orchestrator as orch
from yhwach import policy as pol
from yhwach.brain import Action


class ScriptedBrain:
    """Returns queued Actions in order; repeats the last once exhausted."""

    def __init__(self, actions: list[Action]):
        self._actions = list(actions)
        self.calls = 0

    def decide(self, context: str, *, history=None) -> Action:
        self.calls += 1
        if self._actions:
            return self._actions.pop(0)
        return Action(action="mark_phase_done", rationale="nothing left")


def _engagement_with_ollama(conn) -> int:
    eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
        (eid,),
    )
    yhdb.upsert_surface(conn, int(cur.lastrowid), None, "ollama", "none", "{}")
    return eid


def test_loop_runs_a_technique_then_judges_done(tmp_db: Path) -> None:
    doer = ScriptedBrain(
        [
            Action(
                action="run_technique",
                technique_id="ollama_unauth_api",
                host_ip="10.0.0.5",
                rationale="free recon",
            ),
            Action(action="mark_phase_done", rationale="done"),
        ]
    )
    judge = ScriptedBrain([Action(action="mark_phase_done", rationale="all enumerated")])

    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        report = orch.Orchestrator(conn, eid, doer=doer, judge_brain=judge).run()
        attempts = yhdb.list_attempts(conn, eid)

    assert report.executed == 1
    # Post-arsenal-wiring: the linux host also carries generate_linux_revshell
    # (gated, os-only). The scripted doer explicitly marks the phase done
    # after the ollama run, so the loop halts on 'brain_signaled_done' rather
    # than 'no_candidates'. Both are valid convergence signals here.
    assert report.halt_reason in ("no_candidates", "brain_signaled_done", "awaiting_approval")
    assert report.verdict.done is True
    assert len(attempts) == 1


def test_loop_terminates_when_candidates_exhausted(tmp_db: Path) -> None:
    # Doer keeps proposing the same technique; once consumed, subsequent
    # proposals raise ActionError and the loop must terminate cleanly.
    # Post-arsenal-wiring: os=linux hosts also carry generate_linux_revshell
    # (os-only, gated) so `candidates_left` never hits zero. The loop
    # terminates via the ActionError iteration counter (see the fix in
    # orchestrator.run) OR via awaiting_approval on the gated candidate.
    class AlwaysRunSame:
        def decide(self, context, *, history=None):
            return Action(
                action="run_technique",
                technique_id="ollama_unauth_api",
                host_ip="10.0.0.5",
                rationale="again",
            )

    judge = ScriptedBrain([Action(action="note", rationale="not done")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        # max_iterations=8 keeps the test fast — the fix under test is the
        # backstop that counts invalid re-proposals against the iteration
        # budget (previously an infinite `continue` loop when the doer
        # kept naming a consumed technique).
        report = orch.Orchestrator(
            conn, eid, doer=AlwaysRunSame(), judge_brain=judge, max_iterations=8,
        ).run()

    # ran once, consumed it — the rest is either invalid re-proposals
    # (max_iterations backstop) or a gated candidate parked for approval.
    assert report.halt_reason in (
        "no_candidates", "max_iterations", "awaiting_approval",
    )
    assert report.executed == 1


def test_budget_halts_the_loop(tmp_db: Path) -> None:
    class AlwaysNote:
        def decide(self, context, *, history=None):
            return Action(action="note", rationale="thinking")

    judge = ScriptedBrain([Action(action="note", rationale="not done")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        report = orch.Orchestrator(
            conn,
            eid,
            doer=AlwaysNote(),
            judge_brain=judge,
            budget=pol.Budget(max_actions=3),
        ).run()

    assert report.halt_reason == "budget:max_actions"
    # notes don't consume candidates, so 3 actions were spent
    assert len(report.iterations) == 3


def test_gated_technique_is_queued_not_run(tmp_db: Path) -> None:
    # A findings_include chain that is exploit-tier: needs approval, not run.
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        # light up the probllama chain (exploit-tier) with an open finding
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=?", (eid,)).fetchone()["id"]
        yhdb.add_finding(
            conn,
            host_id=hid,
            surface_id=None,
            cls="LLM01",
            title="probllama",
            severity="high",
            evidence="probllama detected",
            tag="ollama_probllama",
            engagement_id=eid,
        )

        doer = ScriptedBrain(
            [
                Action(
                    action="run_technique",
                    technique_id="ollama_probllama_rce",
                    host_ip="10.0.0.5",
                    rationale="pop it",
                ),
            ]
        )
        judge = ScriptedBrain([Action(action="mark_phase_done", rationale="ok")])
        report = orch.Orchestrator(conn, eid, doer=doer, judge_brain=judge).run()
        events = conn.execute(
            "SELECT kind FROM event WHERE engagement_id=? AND kind='approval_requested'",
            (eid,),
        ).fetchall()

    assert report.queued == 1
    assert len(events) == 1


def test_halt_event_is_logged(tmp_db: Path) -> None:
    doer = ScriptedBrain([Action(action="mark_phase_done", rationale="done")])
    judge = ScriptedBrain([Action(action="mark_phase_done", rationale="clean")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        orch.Orchestrator(conn, eid, doer=doer, judge_brain=judge).run()
        row = conn.execute(
            "SELECT kind FROM event WHERE engagement_id=? AND kind='orchestrator_halt'",
            (eid,),
        ).fetchone()
    assert row is not None


# --- robustness: error handling + stage advancement -------------------------

from yhwach.brain import BrainRefusalError  # noqa: E402


def test_brain_refusal_halts_cleanly(tmp_db: Path) -> None:
    class RefusingDoer:
        def decide(self, context, *, history=None):
            raise BrainRefusalError("cyber", "nope")

    judge = ScriptedBrain([Action(action="note", rationale="x")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        report = orch.Orchestrator(conn, eid, doer=RefusingDoer(), judge_brain=judge).run()
        ev = conn.execute(
            "SELECT 1 FROM event WHERE engagement_id=? AND kind='brain_error'", (eid,)
        ).fetchone()
    assert report.halt_reason == "brain_error"
    assert ev is not None  # recorded, not crashed


def test_runner_exception_is_recorded_and_loop_continues(tmp_db: Path) -> None:
    def boom(cand):
        raise RuntimeError("hexstrike down")

    doer = ScriptedBrain([
        Action(action="run_technique", technique_id="ollama_unauth_api",
               host_ip="10.0.0.5", rationale="try"),
        Action(action="mark_phase_done", rationale="stop"),
    ])
    judge = ScriptedBrain([Action(action="mark_phase_done", rationale="ok")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        ex = act.ActionExecutor(conn, eid, runner=boom)
        report = orch.Orchestrator(conn, eid, doer=doer, judge_brain=judge, executor=ex).run()
        err = conn.execute(
            "SELECT 1 FROM event WHERE engagement_id=? AND kind='execution_error'", (eid,)
        ).fetchone()
        fails = yhdb.list_attempts(conn, eid, result="fail")
    # did not crash; recorded the error + a fail attempt; the burned move is
    # dropped from the menu. Post-arsenal-wiring the linux host still carries
    # generate_linux_revshell (gated), so the doer's next step
    # (mark_phase_done) is the terminal signal — either that or a clean
    # halt on no_candidates satisfies the invariant.
    assert err is not None
    assert len(fails) == 1
    assert report.halt_reason in ("no_candidates", "brain_signaled_done", "awaiting_approval")


def test_host_advances_to_enumerated_after_recon(tmp_db: Path) -> None:
    doer = ScriptedBrain([
        Action(action="run_technique", technique_id="ollama_unauth_api",
               host_ip="10.0.0.5", rationale="recon"),
    ])
    judge = ScriptedBrain([Action(action="note", rationale="x")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)  # host at 'scanned'
        orch.Orchestrator(conn, eid, doer=doer, judge_brain=judge).run()
        stage = conn.execute(
            "SELECT stage FROM host WHERE engagement_id=? AND ip='10.0.0.5'", (eid,)
        ).fetchone()["stage"]
    assert stage == "enumerated"  # worked + no read-only candidate left -> advanced


def test_untouched_host_stays_scanned(tmp_db: Path) -> None:
    # brain immediately says done; nothing attempted -> host must NOT advance
    doer = ScriptedBrain([Action(action="mark_phase_done", rationale="skip")])
    judge = ScriptedBrain([Action(action="note", rationale="x")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        orch.Orchestrator(conn, eid, doer=doer, judge_brain=judge).run()
        stage = conn.execute(
            "SELECT stage FROM host WHERE engagement_id=? AND ip='10.0.0.5'", (eid,)
        ).fetchone()["stage"]
    assert stage == "scanned"


def test_token_budget_halts_the_loop(tmp_db: Path) -> None:
    class UsageDoer:
        last_usage = {"input": 200, "output": 300, "total": 500}

        def decide(self, context, *, history=None):
            return Action(action="note", rationale="think")

    judge = ScriptedBrain([Action(action="note", rationale="x")])
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement_with_ollama(conn)
        report = orch.Orchestrator(
            conn, eid, doer=UsageDoer(), judge_brain=judge,
            budget=pol.Budget(max_tokens=1000),
        ).run()
    # 500 tokens/turn -> exhausted after 2 turns
    assert report.halt_reason == "budget:max_tokens"
    assert report.budget["tokens_spent"] >= 1000
