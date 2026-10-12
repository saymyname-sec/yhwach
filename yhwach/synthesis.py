"""Synthesis: the "State + Next Steps" report at a phase boundary.

Per AGENT.md § "The reporting vision": at the end of a phase the engagement steps
back and produces a decision document — where we stand and what to do next. It is
a **query over memory**, regenerable at any time (like the brief), not an authored
essay: the facts come from the world model, the judge verdict supplies the "done?"
call, and the remaining candidates are the machine-facing next-step queue.

This is the auto/human boundary: read-only recon runs free, then the report is
where a human decides whether to proceed into gated exploitation.
"""

from __future__ import annotations

import sqlite3

from yhwach import knowledge as kn
from yhwach.judge import Verdict


def _scalar(conn: sqlite3.Connection, sql: str, params=()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _succeeded(conn: sqlite3.Connection, engagement_id: int) -> set[tuple]:
    from yhwach import db as yhdb

    return {
        (a["playbook_rule_id"], a["host_ip"])
        for a in yhdb.list_attempts(conn, engagement_id, result="success")
        if a["playbook_rule_id"]
    }


def phase_report(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    phase: str = "enumeration",
    verdict: Verdict | None = None,
    candidates: list | None = None,
    include_candidates: bool = True,
) -> str:
    """Render the phase report from memory. Pure reads.

    `include_candidates=False` omits the "Recommended next steps" section
    entirely. Passing `candidates=[]` is NOT the same thing: that prints the
    heading plus a false "(no applicable techniques remain)".
    """
    if candidates is None:
        candidates = kn.candidates_for(conn, engagement_id)
    # Don't recommend a (technique, host) that already succeeded.
    done = _succeeded(conn, engagement_id)
    candidates = [c for c in candidates if (c.technique_id, c.host_ip) not in done]

    out: list[str] = [f"# ENGAGEMENT STATE — after {phase}", ""]

    # -- verdict -------------------------------------------------------------
    if verdict is not None:
        mark = "COMPLETE" if verdict.done else "NOT COMPLETE"
        out += [f"## Phase verdict: {mark}", f"- {verdict.reasoning}"]
        for item in verdict.whats_left:
            out.append(f"- left: {item}")
        out.append("")

    # -- what we know --------------------------------------------------------
    stages = conn.execute(
        "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage ORDER BY stage",
        (engagement_id,),
    ).fetchall()
    n_creds = _scalar(
        conn, "SELECT COUNT(*) FROM credential WHERE engagement_id=?", (engagement_id,)
    )
    n_surf = _scalar(
        conn,
        "SELECT COUNT(*) FROM surface s JOIN host h ON h.id=s.host_id WHERE h.engagement_id=?",
        (engagement_id,),
    )
    out += ["## What we know"]
    out.append("- Hosts: " + (", ".join(f"{r['stage']}={r['n']}" for r in stages) or "none"))
    out.append(f"- Surfaces: {n_surf} · Credentials held: {n_creds}")
    obj = conn.execute(
        "SELECT COUNT(*) t, COALESCE(SUM(captured),0) c FROM objective WHERE engagement_id=?",
        (engagement_id,),
    ).fetchone()
    if obj and obj["t"]:
        out.append(f"- Objectives: {obj['c']}/{obj['t']} captured")
    out.append("")

    # -- confirmed leads (P0) -----------------------------------------------
    leads = conn.execute(
        "SELECT COALESCE(h.ip,'-') ip, f.tag, f.severity, f.title FROM finding f "
        "LEFT JOIN host h ON h.id=f.host_id WHERE f.engagement_id=? AND f.status IN ('open','confirmed','exploited') "
        "AND COALESCE(f.tag,'')<>'' ORDER BY CASE f.severity WHEN 'critical' THEN 0 "
        "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.id",
        (engagement_id,),
    ).fetchall()
    out += ["## Confirmed leads"]
    if leads:
        for f in leads:
            out.append(f"- [{f['severity']}] {f['ip']} `{f['tag']}` — {f['title']}")
    else:
        out.append("- (none yet)")
    out.append("")

    # -- recommended next steps (the candidate queue) -----------------------
    # The whole section is optional. Spacing around it is not: a caller that
    # suppresses it must get a report otherwise byte-identical to the default.
    if include_candidates:
        out += ["## Recommended next steps"]
        if candidates:
            auto = [c for c in candidates if c.autonomy == "proceed"]
            gated = [c for c in candidates if c.autonomy != "proceed"]
            if auto:
                out.append("Read-only (agent can run unattended):")
                for c in auto:
                    star = " ★AI" if c.technique_class == "ai" else ""
                    out.append(
                        f"  - `{c.technique_id}` @ {c.host_ip} ({c.surface_kind or 'host'}{star})"
                    )
            if gated:
                out.append("Gated (needs your go-ahead):")
                for c in gated:
                    chain = f" chains<-{c.chained_from}" if c.chained_from else ""
                    out.append(f"  - `{c.technique_id}` @ {c.host_ip} [{c.risk}{chain}]")
        else:
            out.append("- (no applicable techniques remain)")
    out.append("")

    # -- dead ends (attempt ledger) -----------------------------------------
    dead = conn.execute(
        "SELECT a.playbook_rule_id rid, a.result, COALESCE(a.reason,'') reason, "
        "COALESCE(h.ip,'-') ip FROM attempt a LEFT JOIN host h ON h.id=a.host_id "
        "WHERE a.engagement_id=? AND a.result IN ('fail','blocked') ORDER BY a.id DESC LIMIT 20",
        (engagement_id,),
    ).fetchall()
    if dead:
        out += ["## Dead ends (already burned)"]
        for d in dead:
            out.append(f"- {d['ip']} `{d['rid']}` — {d['result']}: {d['reason'][:60]}")
        out.append("")

    # -- findings by standard (audit lens) ----------------------------------
    from yhwach.audit import findings_by_standard, render_findings_by_standard

    fam = findings_by_standard(conn, engagement_id)
    if fam:
        out += ["## Findings by standard"]
        out += render_findings_by_standard(fam)
        out.append("")

    return "\n".join(out).rstrip() + "\n"
