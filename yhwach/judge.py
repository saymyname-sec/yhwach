"""Judge: rule whether a phase is complete, from evidence.

Per AGENT.md § "Letting the AI decide": the AI decides done-ness, but it decides
from memory and shows its work. The deterministic facts (unscanned hosts, coverage
gaps, remaining candidates) are gathered here and fed to a JUDGE-role brain as
*evidence it must reckon with* — not a gate that overrides it. A judge that marks
a phase done while facts say otherwise does so deliberately and on the record.

The judge is a *separate* brain invocation from the doers (a fresh, minimal
context) so a tired worker never grades its own homework. The brain is injectable
so this is testable without a key.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Protocol

from yhwach import knowledge as kn
from yhwach.brief import build_brief

_OPEN_STAGES = ("undiscovered", "scanned")


class DecidingBrain(Protocol):
    """Anything that turns a context string into an Action (yhwach.brain.Brain)."""

    def decide(self, context: str, *, history: list[dict] | None = ...): ...


@dataclass(frozen=True)
class Evidence:
    """The deterministic picture the judge must reckon with."""

    phase: str
    stage_counts: dict[str, int]
    unenumerated_hosts: list[str]
    hosts_missing_full_scan: list[str]
    open_leads: int
    candidates_left: int

    def obvious_incomplete(self) -> str | None:
        """A plainly-unfinished signal, or None. Not a gate — the judge sees it as
        evidence, and may still override it deliberately."""
        if self.unenumerated_hosts:
            return f"{len(self.unenumerated_hosts)} host(s) not yet enumerated"
        if self.hosts_missing_full_scan:
            return f"{len(self.hosts_missing_full_scan)} host(s) with no full-port scan on record"
        return None

    def render(self) -> str:
        lines = [
            f"## DETERMINISTIC EVIDENCE (phase: {self.phase})",
            "Host stages: "
            + (", ".join(f"{k}={v}" for k, v in sorted(self.stage_counts.items())) or "none"),
            f"Hosts not yet enumerated: {', '.join(self.unenumerated_hosts) or 'none'}",
            f"Hosts missing a full-port scan: "
            f"{', '.join(self.hosts_missing_full_scan) or 'none'}",
            f"Open leads (tagged findings): {self.open_leads}",
            f"Applicable candidate techniques remaining: {self.candidates_left}",
        ]
        flag = self.obvious_incomplete()
        lines.append(
            f"Deterministic read: {flag}" if flag else "Deterministic read: nothing obviously left"
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class Verdict:
    done: bool
    reasoning: str
    whats_left: list[str] = field(default_factory=list)
    evidence: Evidence | None = None


def gather_evidence(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    phase: str = "enumeration",
    candidates: list | None = None,
) -> Evidence:
    """Read the deterministic completion picture from memory. Pure SELECTs."""
    stage_rows = conn.execute(
        "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage",
        (engagement_id,),
    ).fetchall()
    stage_counts = {r["stage"]: r["n"] for r in stage_rows}

    unenum = [
        r["ip"]
        for r in conn.execute(
            "SELECT ip FROM host WHERE engagement_id=? AND stage IN (?, ?) ORDER BY ip",
            (engagement_id, *_OPEN_STAGES),
        ).fetchall()
    ]

    missing_scan = [
        r["ip"]
        for r in conn.execute(
            "SELECT ip FROM host WHERE engagement_id=? AND stage NOT IN ('undiscovered') "
            "AND id NOT IN (SELECT host_id FROM scan_coverage "
            "WHERE proto='tcp' AND full_range=1) ORDER BY ip",
            (engagement_id,),
        ).fetchall()
    ]

    open_leads = conn.execute(
        "SELECT COUNT(*) n FROM finding WHERE engagement_id=? AND status IN ('open','confirmed','exploited') "
        "AND COALESCE(tag,'')<>''",
        (engagement_id,),
    ).fetchone()["n"]

    if candidates is None:
        candidates = kn.candidates_for(conn, engagement_id)

    return Evidence(
        phase=phase,
        stage_counts=stage_counts,
        unenumerated_hosts=unenum,
        hosts_missing_full_scan=missing_scan,
        open_leads=open_leads,
        candidates_left=len(candidates),
    )


def build_prompt(conn: sqlite3.Connection, engagement_id: int, evidence: Evidence) -> str:
    """The judge's reading: the engagement brief + the deterministic evidence +
    the explicit instruction to justify the verdict against the rows."""
    brief = build_brief(conn, engagement_id)
    return (
        f"{brief}\n\n{evidence.render()}\n\n"
        f"## YOUR TASK — judge phase completeness ({evidence.phase})\n"
        "Decide whether this phase is complete. Reckon with the deterministic "
        "evidence above: if you mark it done while facts say otherwise, justify "
        "why explicitly.\n"
        "Call emit_action exactly once:\n"
        "  - action='mark_phase_done' if the phase is complete; or\n"
        "  - action='note' if it is NOT complete.\n"
        "Put your one-line justification in `rationale`, and a list of remaining "
        "work items in args.whats_left."
    )


def judge_phase(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    brain: DecidingBrain,
    phase: str = "enumeration",
    candidates: list | None = None,
) -> Verdict:
    """Ask the judge brain to rule on phase completeness, evidence in hand."""
    evidence = gather_evidence(conn, engagement_id, phase=phase, candidates=candidates)
    action = brain.decide(build_prompt(conn, engagement_id, evidence))
    done = action.action == "mark_phase_done"
    whats_left = action.args.get("whats_left") or []
    if isinstance(whats_left, str):
        whats_left = [whats_left]
    return Verdict(
        done=done,
        reasoning=action.rationale,
        whats_left=list(whats_left),
        evidence=evidence,
    )
