"""Actions: validate a brain decision, then execute it against memory.

The brain emits an `Action` (yhwach.brain.Action); this module is the bridge
between that decision and the world model. It does three jobs, all deterministic:

  1. **Validate** the action — most importantly, a `run_technique` must name a
     technique that is actually in the candidate menu the matcher produced. The
     brain can only act on what knowledge.py offered; a hallucinated technique is
     rejected here, never run. This is the anti-drift guard AGENT.md relies on.
  2. **Gate** it through policy (read-only proceeds; exploit/destructive need
     approval unless the run is explicitly allowed to proceed).
  3. **Execute** — for a proceed, invoke an injectable runner (which actually
     drives the tool and parses output), then record the attempt, any findings,
     and an event to memory. No runner => a dry "planned" record.

The executor never calls a model and never picks the move — it carries out the
one the brain already chose.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from yhwach import control, scope
from yhwach import db as yhdb
from yhwach import policy as pol
from yhwach.brain import Action
from yhwach.knowledge import Candidate

# Action verbs the executor understands. Anything else is rejected.
VALID_ACTIONS = frozenset(
    {"run_technique", "craft_and_run", "request_approval", "mark_phase_done", "note"}
)


class ActionError(ValueError):
    """The brain emitted an action the executor cannot carry out."""


class Outcome(StrEnum):
    EXECUTED = "executed"  # ran and recorded
    QUEUED = "queued_for_approval"  # gated — awaiting a human
    DENIED = "denied"  # out of policy
    RECORDED = "recorded"  # a signal/note written to memory
    NOOP = "noop"


@dataclass(frozen=True)
class RunResult:
    """What an injected runner returns after driving one read-only technique.
    `result` is an attempt-ledger verdict; `findings` are add_finding kwargs."""

    result: str = "success"  # one of db.ATTEMPT_RESULTS
    reason: str | None = None
    evidence: str | None = None
    findings: list[dict] = field(default_factory=list)
    # What was actually delivered and what came back. The payload used to survive
    # ONLY in the dry-run stub — i.e. it was recorded when it was not sent — and
    # the response was kept only when there were no findings. On a timed engagement the
    # phrasing that worked, and the guardrail text that refused, are the two most
    # reusable facts in the engagement.
    payload: str | None = None
    response: str | None = None
    verdict: str | None = None   # signal | refused | silent


# A runner turns a chosen candidate into a RunResult (drives the tool + parses).
Runner = Callable[[Candidate], RunResult]


@dataclass(frozen=True)
class ExecutionResult:
    outcome: Outcome
    detail: str
    attempt_id: int | None = None
    event_id: int | None = None
    finding_ids: list[int] = field(default_factory=list)


class ActionExecutor:
    """Carries out validated brain actions against one engagement's memory."""

    def __init__(
        self,
        conn,
        engagement_id: int,
        *,
        allow_gated: bool = False,
        grants: frozenset[str] | set[str] | None = None,
        runner: Runner | None = None,
    ) -> None:
        self.conn = conn
        self.engagement_id = engagement_id
        self.allow_gated = allow_gated
        # High-consequence action-class grants (push/listener/…). These are gated
        # INDEPENDENTLY of `allow_gated` — exploit autonomy never grants them.
        self.grants = frozenset(grants) if grants else frozenset()
        self.runner = runner
        row = conn.execute("SELECT scope FROM engagement WHERE id=?", (engagement_id,)).fetchone()
        self._scope = row["scope"] if row else None

    def execute(self, action: Action, *, candidates: list[Candidate]) -> ExecutionResult:
        if action.action not in VALID_ACTIONS:
            raise ActionError(f"unknown action '{action.action}'")

        if action.action == "run_technique":
            return self._run_technique(action, candidates)
        if action.action == "craft_and_run":
            return self._craft_and_run(action, candidates)
        if action.action == "mark_phase_done":
            return self._signal("phase_done_requested", action)
        if action.action == "request_approval":
            return self._signal("approval_requested", action)
        # note
        return self._signal("note", action)

    # -- run_technique ------------------------------------------------------

    def _run_technique(self, action: Action, candidates: list[Candidate]) -> ExecutionResult:
        if not action.technique_id:
            raise ActionError("run_technique requires a technique_id")

        cand = self._resolve_candidate(action, candidates)
        blocked = self._scope_and_gate(cand, action.rationale)
        if blocked is not None:
            return blocked

        # PROCEED — run (or dry-record) and write the outcome to the ledger.
        run = self.runner(cand) if self.runner else RunResult(result="success", reason="planned")
        attempt_id = yhdb.add_attempt(
            self.conn,
            self.engagement_id,
            result=run.result,
            host_id=cand.host_id,
            playbook_rule_id=cand.technique_id,
            technique_id=cand.technique,
            reason=run.reason or action.rationale,
            evidence=run.evidence,
        )
        finding_ids = self._record_findings(cand, run)
        eid = yhdb.log_event(
            self.conn,
            self.engagement_id,
            "action_executed",
            {
                "technique": cand.technique_id,
                "host": cand.host_ip,
                "result": run.result,
                "findings": len(finding_ids),
            },
        )
        return ExecutionResult(
            Outcome.EXECUTED,
            f"ran {cand.technique_id} on {cand.host_ip} -> {run.result}",
            attempt_id=attempt_id,
            event_id=eid,
            finding_ids=finding_ids,
        )

    # -- craft_and_run (the CRAFT path) -------------------------------------

    def _craft_and_run(self, action: Action, candidates: list[Candidate]) -> ExecutionResult:
        """Deliver a brain-crafted payload (prompt injection / SSTI / tool abuse)
        against a candidate, via the runner's craft(). Same scope + gating as a
        normal run; craft moves are typically exploit-tier, so they queue for
        approval unless allowed."""
        if not action.args.get("payload"):
            raise ActionError("craft_and_run requires args.payload")
        cand = self._resolve_candidate(action, candidates)
        blocked = self._scope_and_gate(cand, action.rationale)
        if blocked is not None:
            return blocked

        if self.runner is not None and hasattr(self.runner, "craft"):
            run = self.runner.craft(cand, action.args)
        else:
            run = RunResult(
                result="success",
                reason="planned craft",
                evidence=f"would deliver: {str(action.args.get('payload'))[:80]}",
            )
        attempt_id = yhdb.add_attempt(
            self.conn,
            self.engagement_id,
            result=run.result,
            host_id=cand.host_id,
            playbook_rule_id=cand.technique_id,
            technique_id=cand.technique,
            reason=run.reason or action.rationale,
            evidence=run.evidence,
        )
        finding_ids = self._record_findings(cand, run)
        eid = yhdb.log_event(
            self.conn,
            self.engagement_id,
            "craft_executed",
            {
                "technique": cand.technique_id,
                "host": cand.host_ip,
                "result": run.result,
                "findings": len(finding_ids),
                # The phrasing that was delivered, what came back, and whether a
                # guardrail refused it. None of this was persisted anywhere.
                "payload": run.payload,
                "response": run.response,
                "verdict": run.verdict,
            },
        )
        return ExecutionResult(
            Outcome.EXECUTED,
            f"crafted {cand.technique_id} on {cand.host_ip} -> {run.result}",
            attempt_id=attempt_id,
            event_id=eid,
            finding_ids=finding_ids,
        )

    # -- shared resolution + gating ----------------------------------------

    def _resolve_candidate(self, action: Action, candidates: list[Candidate]) -> Candidate:
        if not action.technique_id:
            raise ActionError(f"{action.action} requires a technique_id")
        cand = self._match_candidate(action, candidates)
        if cand is None:
            # The brain may only act on the offered menu. Reject anything else.
            raise ActionError(
                f"technique '{action.technique_id}' is not an applicable candidate"
                + (f" on {action.host_ip}" if action.host_ip else "")
            )
        return cand

    def _scope_and_gate(self, cand: Candidate, rationale: str) -> ExecutionResult | None:
        """Scope guard + autonomy gate + standing approval. Returns an early
        DENIED/QUEUED result, or None to proceed."""
        if self._scope and cand.host_ip and not scope.in_scope(cand.host_ip, self._scope):
            eid = yhdb.log_event(
                self.conn,
                self.engagement_id,
                "scope_violation",
                {"technique": cand.technique_id, "host": cand.host_ip, "scope": self._scope},
            )
            return ExecutionResult(Outcome.DENIED, f"{cand.host_ip} out of scope", event_id=eid)

        decision = pol.gate(cand.autonomy, allow_gated=self.allow_gated)
        # The action-class gate is SEPARATE from autonomy: a high-consequence class
        # (push/listener/code_change/out_of_scope_write) runs only if the operator
        # named it via --allow. `allow_gated` (exploit autonomy) never covers it.
        action_class = getattr(cand, "action_class", None)
        class_decision = pol.class_gate(action_class, self.grants)

        # A standing human approval (recorded via the UI/control channel) is an
        # explicit grant: it clears BOTH gates for this technique+host.
        if pol.Gate.NEEDS_APPROVAL in (decision, class_decision) and control.is_approved(
            self.conn, self.engagement_id, technique=cand.technique_id, host=cand.host_ip
        ):
            if decision is pol.Gate.NEEDS_APPROVAL:
                decision = pol.Gate.PROCEED
            class_decision = pol.Gate.PROCEED

        if decision is pol.Gate.DENY:
            eid = yhdb.log_event(
                self.conn,
                self.engagement_id,
                "action_denied",
                {"technique": cand.technique_id, "host": cand.host_ip, "why": rationale},
            )
            return ExecutionResult(Outcome.DENIED, f"denied {cand.technique_id}", event_id=eid)
        if pol.Gate.NEEDS_APPROVAL in (decision, class_decision):
            payload = {
                "technique": cand.technique_id,
                "host": cand.host_ip,
                "risk": cand.risk,
                "rationale": rationale,
            }
            if class_decision is pol.Gate.NEEDS_APPROVAL:
                # A dangerous class no --allow grant covers: name it so the
                # operator sees exactly which reach must be authorized.
                payload["action_class"] = action_class
            eid = yhdb.log_event(self.conn, self.engagement_id, "approval_requested", payload)
            detail = (
                f"grant '{action_class}' needed for {cand.technique_id}"
                if class_decision is pol.Gate.NEEDS_APPROVAL
                else f"approval needed for {cand.technique_id}"
            )
            return ExecutionResult(Outcome.QUEUED, detail, event_id=eid)
        return None

    def _match_candidate(self, action: Action, candidates: list[Candidate]) -> Candidate | None:
        for c in candidates:
            if c.technique_id != action.technique_id:
                continue
            if action.host_ip and c.host_ip != action.host_ip:
                continue
            return c
        return None

    def _record_findings(self, cand: Candidate, run: RunResult) -> list[int]:
        ids: list[int] = []
        for f in run.findings:
            fid, _ = yhdb.add_finding(
                self.conn,
                host_id=f.get("host_id", cand.host_id),
                surface_id=f.get("surface_id", cand.surface_id),
                cls=f.get("cls", "LLM01"),
                title=f["title"],
                severity=f.get("severity", "medium"),
                evidence=f.get("evidence", ""),
                playbook_rule_id=cand.technique_id,
                tag=f.get("tag"),
                engagement_id=self.engagement_id,
            )
            ids.append(fid)
        return ids

    # -- signals / notes ----------------------------------------------------

    def _signal(self, kind: str, action: Action) -> ExecutionResult:
        eid = yhdb.log_event(
            self.conn,
            self.engagement_id,
            kind,
            {
                "action": action.action,
                "technique": action.technique_id,
                "host": action.host_ip,
                "rationale": action.rationale,
                "args": action.args,
            },
        )
        return ExecutionResult(Outcome.RECORDED, f"{kind}: {action.rationale}", event_id=eid)
