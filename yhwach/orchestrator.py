"""Orchestrator: the control loop (wire 0 — the part that was the human).

Ties the pieces together per AGENT.md § "The loop":

    build context (brief + candidates)
      -> doer brain decides one action
      -> executor validates + runs it, writes results to memory
      -> budget / halt check
    ... until the phase is done or budget/candidates run out
      -> JUDGE rules on phase completeness

Everything the orchestrator decides is deterministic (budgets, halting, what to
offer the brain). The only judgment is the brain's. Brains and executor are
injectable so the whole loop is testable with fakes — no key, no network.

Convergence: each (technique, host) is offered at most once per run. A success
consumes the technique (matcher drops it); a queued/denied/tried move is filtered
out. So the candidate set strictly shrinks and the loop always terminates.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from yhwach import actions as act
from yhwach import db as yhdb
from yhwach import judge as jg
from yhwach import knowledge as kn
from yhwach import policy as pol
from yhwach.brain import BrainError
from yhwach.brief import build_brief
from yhwach.judge import DecidingBrain, Verdict


@dataclass(frozen=True)
class IterationRecord:
    n: int
    action: str
    technique_id: str | None
    host_ip: str | None
    outcome: str
    detail: str


@dataclass(frozen=True)
class RunReport:
    phase: str
    iterations: list[IterationRecord]
    halt_reason: str
    verdict: Verdict | None
    budget: dict = field(default_factory=dict)
    halt_detail: str | None = None  # human-readable why, when halt_reason is coarse

    @property
    def executed(self) -> int:
        return sum(1 for it in self.iterations if it.outcome == act.Outcome.EXECUTED)

    @property
    def queued(self) -> int:
        return sum(1 for it in self.iterations if it.outcome == act.Outcome.QUEUED)


def render_candidates(candidates: list[kn.Candidate]) -> str:
    """The applicable-technique menu the doer picks from. No ordering implied —
    the brain ranks; the list is the complete recall set."""
    if not candidates:
        return "## CANDIDATES\n(none applicable)"
    lines = ["## CANDIDATES — applicable techniques (you choose which, and the order)"]
    for c in candidates:
        chain = f" chains<-{c.chained_from}" if c.chained_from else ""
        star = " ★AI" if c.technique_class == "ai" else ""
        lines.append(
            f"- `{c.technique_id}` @ {c.host_ip} "
            f"[{c.surface_kind or 'host'} · {c.risk}{star}{chain} · hint:{c.points}pts]"
        )
    return "\n".join(lines)


def build_context(conn: sqlite3.Connection, engagement_id: int, candidates: list) -> str:
    """What the doer reads each turn: the engagement brief + the candidate menu +
    how to respond."""
    brief = build_brief(conn, engagement_id)
    return (
        f"{brief}\n\n{render_candidates(candidates)}\n\n"
        "## YOUR TASK\n"
        "Choose the single best next move and call emit_action once:\n"
        "  - action='run_technique' with technique_id + host_ip to run a candidate "
        "(read-only runs immediately; exploit/destructive is queued for approval);\n"
        "  - action='craft_and_run' with technique_id + host_ip and a payload you "
        "write in args.payload (plus args.method/path/param/content_type) to deliver "
        "a prompt injection / SSTI / tool-abuse probe to the surface;\n"
        "  - action='note' to record a lead or reasoning without acting;\n"
        "  - action='mark_phase_done' when nothing useful remains this phase.\n"
        "Put a one-line why in `rationale`. Pick only from the candidate list."
    )


class Orchestrator:
    """Runs one phase of the engagement loop for a single engagement."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        engagement_id: int,
        *,
        doer: DecidingBrain,
        judge_brain: DecidingBrain,
        executor: act.ActionExecutor | None = None,
        runner: act.Runner | None = None,
        budget: pol.Budget | None = None,
        allow_gated: bool = False,
        allow_grants: frozenset[str] | set[str] | None = None,
        phase: str = "enumeration",
        max_iterations: int = 200,
        host_ip: str | None = None,
        judge_at_end: bool = True,
    ) -> None:
        self.conn = conn
        self.engagement_id = engagement_id
        self.doer = doer
        self.judge_brain = judge_brain
        self.executor = executor or act.ActionExecutor(
            conn, engagement_id, allow_gated=allow_gated, grants=allow_grants, runner=runner
        )
        self.budget = budget or pol.Budget()
        self.phase = phase
        self.max_iterations = max_iterations
        self.host_ip = host_ip
        self.judge_at_end = judge_at_end

    def _candidates(self, tried: set[tuple[str | None, str | None]]) -> list[kn.Candidate]:
        cands = kn.candidates_for(self.conn, self.engagement_id, host_ip=self.host_ip)
        return [c for c in cands if (c.technique_id, c.host_ip) not in tried]

    def _seed_tried(self) -> set[tuple[str | None, str | None]]:
        """(technique, host) pairs already succeeded in an earlier run/worker —
        never re-offer them. This is the cross-run half of convergence, at the
        right granularity: a technique that landed on host A can still run on
        host B (unlike engagement-wide exhaustion, which is reserved for true
        non-recurring infra flaws via `technique_state`)."""
        from yhwach import db as yhdb

        return {
            (a["playbook_rule_id"], a["host_ip"])
            for a in yhdb.list_attempts(self.conn, self.engagement_id, result="success")
            if a["playbook_rule_id"]
        }

    def _advance_enumerated_hosts(self) -> None:
        """Advance scanned -> enumerated for hosts we actually worked: at least one
        attempt recorded and no read-only candidate left. This is what lets the
        judge/brief see phase progress (the FSM never advanced from the loop
        before). Scoped to host_ip when the run is a single-host worker."""
        clause = "AND ip=?" if self.host_ip else ""
        params = [self.engagement_id] + ([self.host_ip] if self.host_ip else [])
        scanned = [
            r["ip"]
            for r in self.conn.execute(
                f"SELECT ip FROM host WHERE engagement_id=? AND stage='scanned' {clause}",
                params,
            ).fetchall()
        ]
        attempted = {a["host_ip"] for a in yhdb.list_attempts(self.conn, self.engagement_id)}
        succeeded = self._seed_tried()
        for ip in scanned:
            if ip not in attempted:
                continue  # never worked -> leave it 'scanned'
            cands = kn.candidates_for(self.conn, self.engagement_id, host_ip=ip)
            outstanding = [
                c
                for c in cands
                if c.autonomy == "proceed" and (c.technique_id, c.host_ip) not in succeeded
            ]
            if outstanding:
                continue  # read-only recon still outstanding
            changed, _ = yhdb.set_host_stage(
                self.conn, self.engagement_id, ip, "enumerated",
                note="probe/triage complete")
            if changed:
                yhdb.log_event(
                    self.conn,
                    self.engagement_id,
                    "stage",
                    {"host": ip, "stage": "enumerated", "by": "agent"},
                )

    def run(self) -> RunReport:
        from yhwach import control

        iterations: list[IterationRecord] = []
        tried: set[tuple[str | None, str | None]] = self._seed_tried()
        awaiting_approval = False
        halt_reason = "max_iterations"
        halt_detail: str | None = None
        start_event = control.mark_run_started(self.conn, self.engagement_id, phase=self.phase)

        while len(iterations) < self.max_iterations:
            if control.is_killed(self.conn, self.engagement_id, since_event_id=start_event):
                halt_reason = "killed"
                break
            candidates = self._candidates(tried)
            decision = pol.should_halt(
                self.budget,
                phase_done=False,
                candidates_left=len(candidates),
                awaiting_approval=awaiting_approval,
            )
            if decision.should_halt:
                halt_reason = decision.reason or "halt"
                break

            self.budget.spend(actions=1)
            try:
                action = self.doer.decide(build_context(self.conn, self.engagement_id, candidates))
                self.budget.spend(tokens=getattr(self.doer, "last_usage", {}).get("total", 0))
            except BrainError as exc:
                # A refusal / no-action won't self-correct by retrying — record and stop.
                halt_detail = str(exc)
                yhdb.log_event(
                    self.conn,
                    self.engagement_id,
                    "brain_error",
                    {"error": type(exc).__name__, "detail": halt_detail[:200]},
                )
                halt_reason = "brain_error"
                break

            if action.action == "mark_phase_done":
                halt_reason = "brain_signaled_done"
                break

            # Offer each technique at most once per run -> strict shrink -> halt,
            # recorded before execute so a raising move is never re-proposed.
            if action.action == "run_technique" and action.technique_id:
                tried.add((action.technique_id, action.host_ip))

            try:
                result = self.executor.execute(action, candidates=candidates)
            except act.ActionError as exc:
                # The brain proposed something invalid (e.g. a hallucinated
                # technique). Drop it and give the brain another turn — but
                # count the decision against max_iterations so a brain that
                # keeps proposing the same invalid action cannot spin the
                # loop forever. (Pre-arsenal-wiring this only terminated by
                # exhausting `candidates`; once os-only rules always keep
                # the candidate list non-empty, the loop needed its own
                # backstop.)
                yhdb.log_event(
                    self.conn,
                    self.engagement_id,
                    "action_error",
                    {
                        "action": action.action,
                        "technique": action.technique_id,
                        "detail": str(exc)[:200],
                    },
                )
                iterations.append(
                    IterationRecord(
                        n=len(iterations) + 1,
                        action=action.action,
                        technique_id=action.technique_id,
                        host_ip=action.host_ip,
                        outcome="action_error",
                        detail=str(exc)[:200],
                    )
                )
                continue
            except Exception as exc:  # runner / HexStrike / network failure
                yhdb.log_event(
                    self.conn,
                    self.engagement_id,
                    "execution_error",
                    {
                        "technique": action.technique_id,
                        "host": action.host_ip,
                        "error": type(exc).__name__,
                        "detail": str(exc)[:200],
                    },
                )
                if action.technique_id:
                    yhdb.add_attempt(
                        self.conn,
                        self.engagement_id,
                        result="fail",
                        playbook_rule_id=action.technique_id,
                        reason=f"{type(exc).__name__}: {str(exc)[:120]}",
                    )
                iterations.append(
                    IterationRecord(
                        n=len(iterations) + 1,
                        action=action.action,
                        technique_id=action.technique_id,
                        host_ip=action.host_ip,
                        outcome="execution_error",
                        detail=f"{type(exc).__name__}: {str(exc)[:120]}",
                    )
                )
                continue

            iterations.append(
                IterationRecord(
                    n=len(iterations) + 1,
                    action=action.action,
                    technique_id=action.technique_id,
                    host_ip=action.host_ip,
                    outcome=str(result.outcome),
                    detail=result.detail,
                )
            )
            if result.outcome is act.Outcome.QUEUED:
                awaiting_approval = True

        self._advance_enumerated_hosts()
        verdict = (
            jg.judge_phase(self.conn, self.engagement_id, brain=self.judge_brain, phase=self.phase)
            if self.judge_at_end
            else None
        )
        self._log_halt(halt_reason, verdict)
        return RunReport(
            phase=self.phase,
            iterations=iterations,
            halt_reason=halt_reason,
            verdict=verdict,
            budget=self.budget.snapshot(),
            halt_detail=halt_detail,
        )

    def _log_halt(self, reason: str, verdict: Verdict | None) -> None:
        from yhwach import db as yhdb

        yhdb.log_event(
            self.conn,
            self.engagement_id,
            "orchestrator_halt",
            {
                "phase": self.phase,
                "reason": reason,
                "phase_done": verdict.done if verdict else None,
                "budget": self.budget.snapshot(),
            },
        )
