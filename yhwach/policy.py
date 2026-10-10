"""Policy: the deterministic control layer.

The orchestrator's guardrails — budgets, autonomy gating, and halting — all live
here, and all are **deterministic**. Per AGENT.md § "Budgets, safety, replay":
the safety envelope is never delegated to the brain's judgment. The brain
proposes; policy decides whether a move may run automatically, must wait for a
human, or is out of bounds, and when the loop must stop.

No LLM, no I/O (except an injectable clock) — pure, unit-testable logic.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum


class Gate(StrEnum):
    """What may happen to a proposed action."""

    PROCEED = "proceed"  # run it now, unattended
    NEEDS_APPROVAL = "needs_approval"  # queue for a human go/no-go
    DENY = "deny"  # out of policy — never run


# Autonomy tiers as produced by the knowledge catalog (risk -> autonomy):
#   read_only -> "proceed", exploit -> "propose", destructive -> "ask".
_AUTONOMY_TIERS = {"proceed", "propose", "ask"}


class ActionClass(StrEnum):
    """High-consequence action classes gated INDEPENDENTLY of the autonomy tier.

    The autonomy `gate()` decides whether an in-lab move (recon/exploit) may run
    unattended. These classes are different: they reach OUTSIDE the target
    engagement (publishing code, opening network listeners, touching the agent's
    own repo) and a blanket "full autonomy"/`allow_gated` must NEVER cover them.
    Each requires its own explicit human grant, recorded and traceable; anything
    not granted is denied (fail closed). This is the code answer to a brain that
    fabricates its own consent.
    """

    PUSH = "push"  # git push / publish to a remote
    CODE_CHANGE = "code_change"  # modify/commit the yhwach repo itself
    LISTENER = "listener"  # bind a network listener (revshell / OOB / C2)
    OUT_OF_SCOPE_WRITE = "out_of_scope_write"  # any write beyond the lab scope


# The dangerous classes above are ALWAYS gated behind their own named grant, no
# matter how autonomous the run is. `allow_gated` (exploit autonomy) does not
# grant any of them.
_DANGEROUS_CLASSES = frozenset(ActionClass)


def class_gate(action_class: str, grants: frozenset[str] | set[str] | None) -> Gate:
    """Authorize a high-consequence action class against explicit human grants.

    `grants` is the set of `ActionClass` values the human turned on for this run
    (e.g. via `--allow push,code_change`). A dangerous class runs only if it is
    named in `grants`; otherwise it needs approval. Fail closed on unknowns.

    This is deliberately separate from `gate()`: a fully autonomous exploit run
    (`allow_gated`) still cannot push, change code, or open a listener unless the
    operator named that class — so a model cannot escalate its own reach.
    """
    grants = grants or frozenset()
    if action_class in _DANGEROUS_CLASSES:
        return Gate.PROCEED if action_class in grants else Gate.NEEDS_APPROVAL
    # Not a tracked dangerous class -> this gate says nothing; the autonomy
    # `gate()` governs it. Return PROCEED so callers can AND the two gates.
    return Gate.PROCEED


def parse_grants(spec: str | None) -> frozenset[str]:
    """Parse a `--allow` spec ('push,code_change') into a validated grant set.

    Unknown tokens are dropped (fail closed) rather than raising, so a typo can
    never silently widen reach. Case-insensitive; whitespace tolerant.
    """
    if not spec:
        return frozenset()
    valid = {c.value for c in ActionClass}
    out = set()
    for tok in spec.replace(";", ",").split(","):
        t = tok.strip().lower()
        if t in valid:
            out.add(t)
    return frozenset(out)


def gate(autonomy: str, *, allow_gated: bool = False) -> Gate:
    """Decide how a proposed action may run, from its autonomy tier.

    - `proceed` (read-only) always runs unattended.
    - `propose` (exploit) needs approval; `allow_gated=True` lets a fully
      autonomous run proceed on exploit moves (still never on destructive).
    - `ask` (destructive) always needs approval.
    - anything unknown is denied (fail closed).
    """
    if autonomy == "proceed":
        return Gate.PROCEED
    if autonomy == "propose":
        return Gate.PROCEED if allow_gated else Gate.NEEDS_APPROVAL
    if autonomy == "ask":
        return Gate.NEEDS_APPROVAL
    return Gate.DENY


class BudgetError(RuntimeError):
    """Raised when a budget is constructed with nonsensical limits."""


@dataclass
class Budget:
    """A spend ceiling for a run (engagement) or a single worker. Any limit left
    None is unbounded. `clock` is injectable so tests need no real time."""

    max_actions: int | None = None
    max_tokens: int | None = None
    max_wall_seconds: float | None = None
    clock: Callable[[], float] = time.monotonic

    actions_spent: int = field(default=0, init=False)
    tokens_spent: int = field(default=0, init=False)
    _started_at: float = field(init=False)

    def __post_init__(self) -> None:
        for name, val in (
            ("max_actions", self.max_actions),
            ("max_tokens", self.max_tokens),
        ):
            if val is not None and val <= 0:
                raise BudgetError(f"{name} must be positive or None, got {val}")
        if self.max_wall_seconds is not None and self.max_wall_seconds <= 0:
            raise BudgetError("max_wall_seconds must be positive or None")
        self._started_at = self.clock()

    def spend(self, *, actions: int = 0, tokens: int = 0) -> None:
        self.actions_spent += actions
        self.tokens_spent += tokens

    def elapsed(self) -> float:
        return self.clock() - self._started_at

    def exhausted(self) -> bool:
        """True once any configured limit is met or exceeded."""
        return bool(self.reason())

    def reason(self) -> str | None:
        """The name of the first breached limit, or None if within budget."""
        if self.max_actions is not None and self.actions_spent >= self.max_actions:
            return "max_actions"
        if self.max_tokens is not None and self.tokens_spent >= self.max_tokens:
            return "max_tokens"
        if self.max_wall_seconds is not None and self.elapsed() >= self.max_wall_seconds:
            return "max_wall_seconds"
        return None

    def snapshot(self) -> dict:
        """Serializable spend state for the event log / UI."""
        return {
            "actions_spent": self.actions_spent,
            "tokens_spent": self.tokens_spent,
            "elapsed_seconds": round(self.elapsed(), 3),
            "max_actions": self.max_actions,
            "max_tokens": self.max_tokens,
            "max_wall_seconds": self.max_wall_seconds,
        }


@dataclass(frozen=True)
class HaltDecision:
    should_halt: bool
    reason: str | None = None


def should_halt(
    budget: Budget,
    *,
    phase_done: bool,
    candidates_left: int,
    awaiting_approval: bool = False,
) -> HaltDecision:
    """Whether the loop must stop, and why. Order matters: budget first (a hard
    ceiling), then completion, then starvation, then a stall waiting on a human."""
    budget_reason = budget.reason()
    if budget_reason:
        return HaltDecision(True, f"budget:{budget_reason}")
    if phase_done:
        return HaltDecision(True, "phase_done")
    if candidates_left <= 0 and not awaiting_approval:
        return HaltDecision(True, "no_candidates")
    if candidates_left <= 0 and awaiting_approval:
        return HaltDecision(True, "awaiting_approval")
    return HaltDecision(False, None)
