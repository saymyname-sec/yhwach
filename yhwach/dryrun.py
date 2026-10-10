"""Deterministic stand-in brains for a no-key dry run.

`yhwach run --dry-run` exercises the whole pipeline — knowledge -> orchestrator ->
executor -> policy -> judge -> synthesis — without calling a model or needing an
API key. These stand-ins satisfy the DecidingBrain protocol (`.decide(context)`)
but ignore the prose context and reason directly over memory instead:

  * DeterministicDoer picks the first not-yet-tried candidate (read-only before
    gated), mirroring exactly the (technique, host) set the orchestrator filters
    on, so it never proposes a move outside the current menu.
  * DeterministicJudge rules the phase done iff the deterministic evidence shows
    nothing obviously left.

They are not the agent — they are a scaffold that proves the wiring and gives a
real, model-free demonstration and test path.
"""

from __future__ import annotations

import sqlite3

from yhwach import db as yhdb
from yhwach import judge as jg
from yhwach import knowledge as kn
from yhwach.brain import Action


def _succeeded(conn: sqlite3.Connection, engagement_id: int) -> set[tuple[str | None, str | None]]:
    return {
        (a["playbook_rule_id"], a["host_ip"])
        for a in yhdb.list_attempts(conn, engagement_id, result="success")
        if a["playbook_rule_id"]
    }


class DeterministicDoer:
    """Picks candidates in a fixed order: read-only first, then gated. Tracks what
    it has emitted so it stays in lockstep with the orchestrator's `tried` set."""

    def __init__(self, conn: sqlite3.Connection, engagement_id: int, *, host_ip: str | None = None):
        self.conn = conn
        self.engagement_id = engagement_id
        self.host_ip = host_ip
        self._emitted: set[tuple[str | None, str | None]] = set()

    def decide(self, context: str, *, history=None) -> Action:
        candidates = kn.candidates_for(self.conn, self.engagement_id, host_ip=self.host_ip)
        excluded = self._emitted | _succeeded(self.conn, self.engagement_id)
        available = [c for c in candidates if (c.technique_id, c.host_ip) not in excluded]
        if not available:
            return Action(action="mark_phase_done", rationale="no untried candidates remain")

        # read-only before gated (proceed tier first)
        available.sort(key=lambda c: 0 if c.autonomy == "proceed" else 1)
        pick = available[0]
        self._emitted.add((pick.technique_id, pick.host_ip))
        return Action(
            action="run_technique",
            technique_id=pick.technique_id,
            host_ip=pick.host_ip,
            rationale=f"dry-run: {pick.rationale}",
        )


class DeterministicJudge:
    """Phase is done iff the deterministic evidence shows nothing obviously left."""

    def __init__(self, conn: sqlite3.Connection, engagement_id: int, *, phase: str = "enumeration"):
        self.conn = conn
        self.engagement_id = engagement_id
        self.phase = phase

    def decide(self, context: str, *, history=None) -> Action:
        ev = jg.gather_evidence(self.conn, self.engagement_id, phase=self.phase)
        flag = ev.obvious_incomplete()
        if flag is None:
            return Action(
                action="mark_phase_done", rationale="dry-run: evidence shows nothing left"
            )
        return Action(action="note", rationale=f"dry-run: {flag}", args={"whats_left": [flag]})
