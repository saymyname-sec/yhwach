"""yhwach next — the fused "what do I do next, and what am I about to miss" view.

The recall menu (`knowledge.candidates_for`) is the deterministic set of *every*
technique that applies to the current world model — the one thing the rule engine
genuinely beats the brain at (recall, not ranking). Until now it was consumed only
by the autonomous runtime and collapsed to a per-worker integer in the UI, with no
CLI/MCP surface at all: an operator driving yhwach over MCP could not ask "which
techniques apply to host X" — the exact under-recall failure the menu exists to
prevent.

`next` surfaces that menu as a first-class operator move, grouped by host and split
read-only vs. gated, fused with the three things an operator most often forgets
under engagement time pressure:

  - **under-enumeration** (`coverage.enum_gaps`) — the #1 point loss in engagements,
  - **untried credentials** still sitting in the vault (a loaded chamber, safety on),
  - **uncaptured objectives** (the objectives being scored).

Pure reads. No scoring, no ranking (that stays the brain's job), no DB writes.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from yhwach import knowledge as kn
from yhwach.coverage import HostCoverage, gaps_as_dicts, render_gaps, started_gaps


@dataclass
class NextMoves:
    """The fused next-move view. `auto`/`gated` are the recall menu (already
    de-duped against successes); the rest is "what you're about to miss"."""

    auto: list[kn.Candidate] = field(default_factory=list)
    gated: list[kn.Candidate] = field(default_factory=list)
    coverage: list[HostCoverage] = field(default_factory=list)
    untried_creds: list[dict] = field(default_factory=list)
    objectives: list[dict] = field(default_factory=list)
    pending_scan: int = 0

    @property
    def empty(self) -> bool:
        return not (
            self.auto or self.gated or self.coverage
            or self.untried_creds or self.objectives
        )


def _succeeded(conn: sqlite3.Connection, engagement_id: int) -> set[tuple]:
    """(rule_id, host_ip) pairs already proven — never recommend them again.

    Mirrors ``synthesis._succeeded`` so `next` and the phase report agree on
    what counts as done."""
    from yhwach import db as yhdb

    return {
        (a["playbook_rule_id"], a["host_ip"])
        for a in yhdb.list_attempts(conn, engagement_id, result="success")
        if a["playbook_rule_id"]
    }


def next_moves(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    techniques: list[kn.Technique] | None = None,
) -> NextMoves:
    """Compute the fused next-move view for the engagement (or one host).

    `techniques` may be passed to reuse an already-loaded catalog (the UI loads
    it once per poll); otherwise `candidates_for` loads it from the default dir.
    """
    cands = kn.candidates_for(
        conn, engagement_id, host_ip=host_ip, techniques=techniques
    )
    done = _succeeded(conn, engagement_id)
    cands = [c for c in cands if (c.technique_id, c.host_ip) not in done]
    auto = [c for c in cands if c.autonomy == "proceed"]
    gated = [c for c in cands if c.autonomy != "proceed"]

    # Coverage here is the "started hosts" view — undiscovered hosts are the scan
    # queue (pending_scan), not an under-enumeration gap, so they don't double-count.
    coverage = started_gaps(conn, engagement_id, host_ip=host_ip)

    # Untried creds: in the vault, never proven on any host. Same definition the
    # brief uses (validated_on_host_id IS NULL). Creds are global reuse fuel, so
    # they are surfaced even for a host-scoped view.
    untried = [
        {"identifier": r["identifier"], "kind": r["kind"], "source": r["source"] or ""}
        for r in conn.execute(
            "SELECT identifier, kind, COALESCE(source,'') source FROM credential "
            "WHERE engagement_id=? AND validated_on_host_id IS NULL ORDER BY id",
            (engagement_id,),
        ).fetchall()
    ]

    obj_rows = conn.execute(
        "SELECT o.label, o.kind, COALESCE(o.points,0) points, COALESCE(h.ip,'-') ip "
        "FROM objective o LEFT JOIN host h ON h.id=o.host_id "
        "WHERE o.engagement_id=? AND COALESCE(o.captured,0)=0 "
        + (" AND h.ip=?" if host_ip else "")
        + " ORDER BY o.points DESC, o.id",
        (engagement_id, host_ip) if host_ip else (engagement_id,),
    ).fetchall()
    objectives = [
        {"label": r["label"], "kind": r["kind"], "points": r["points"], "ip": r["ip"]}
        for r in obj_rows
    ]

    pending = conn.execute(
        "SELECT COUNT(*) FROM host WHERE engagement_id=? AND scan_needed=1",
        (engagement_id,),
    ).fetchone()[0]

    return NextMoves(
        auto=auto,
        gated=gated,
        coverage=coverage,
        untried_creds=untried,
        objectives=objectives,
        pending_scan=int(pending),
    )


def _by_host(cands: list[kn.Candidate]) -> list[tuple[str, list[kn.Candidate]]]:
    groups: dict[str, list[kn.Candidate]] = {}
    for c in cands:
        groups.setdefault(c.host_ip, []).append(c)
    return sorted(groups.items())


def render_next(nm: NextMoves, *, gap_limit: int = 8) -> list[str]:
    """Compact operator-facing lines — shared by the CLI and the MCP tool."""
    lines: list[str] = []

    if nm.auto:
        lines.append("AUTO — read-only, safe to run now:")
        for ip, cs in _by_host(nm.auto):
            lines.append(f"  {ip}")
            for c in cs:
                star = " ★AI" if c.technique_class == "ai" else ""
                surf = c.surface_kind or "host"
                maps = f"  [{'/'.join(c.maps)}]" if c.maps else ""
                lines.append(f"    - {c.technique_id} ({surf}{star}){maps}")
    if nm.gated:
        lines.append("GATED — needs your go-ahead:")
        for ip, cs in _by_host(nm.gated):
            lines.append(f"  {ip}")
            for c in cs:
                chain = f" chains<-{c.chained_from}" if c.chained_from else ""
                surf = c.surface_kind or "host"
                lines.append(f"    - {c.technique_id} ({surf}) [{c.risk}{chain}]")
    if not nm.auto and not nm.gated:
        lines.append("(no applicable techniques remain — enumerate more or advance a host)")

    miss: list[str] = []
    if nm.coverage:
        miss.append("UNDER-ENUMERATION — you may be about to miss points:")
        miss += render_gaps(nm.coverage, limit=gap_limit)
    if nm.untried_creds:
        preview = ", ".join(
            f"{c['identifier']}({c['kind']})" for c in nm.untried_creds[:12]
        )
        more = f" +{len(nm.untried_creds) - 12} more" if len(nm.untried_creds) > 12 else ""
        miss.append(f"UNTRIED CREDS (spray these): {preview}{more}")
    if nm.objectives:
        miss.append("UNCAPTURED OBJECTIVES:")
        for o in nm.objectives:
            pts = f" · {o['points']}pts" if o["points"] else ""
            miss.append(f"  - {o['label']} @ {o['ip']}{pts}")
    if miss:
        lines.append("")
        lines += miss

    return lines


def _cand_as_dict(c: kn.Candidate) -> dict:
    return {
        "technique_id": c.technique_id,
        "host_ip": c.host_ip,
        "surface_kind": c.surface_kind,
        "risk": c.risk,
        "autonomy": c.autonomy,
        "technique_class": c.technique_class,
        "maps": list(c.maps),
        "chained_from": c.chained_from,
        "routes": c.routes,
        "points": c.points,
    }


def next_as_dict(nm: NextMoves) -> dict:
    """JSON-shaped view for `--json` output and programmatic callers."""
    return {
        "auto": [_cand_as_dict(c) for c in nm.auto],
        "gated": [_cand_as_dict(c) for c in nm.gated],
        "coverage_gaps": gaps_as_dicts(nm.coverage),
        "untried_creds": nm.untried_creds,
        "objectives": nm.objectives,
        "pending_scan": nm.pending_scan,
    }
