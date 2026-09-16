"""Context assembly for the operator handoff.

Phase 1.4 model: Yhwach does NOT call an LLM. It emits a single structured
block — persona frame + state slice + EV-ranked candidates — that the operator
(Claude Code on Kali, or any capable model) reasons over to produce the
Autonomy Contract. The persona travels with the block so it overrides whatever
reasoning style the host CLI would otherwise apply.
"""
from __future__ import annotations

import sqlite3

from yhwach import persona_path
from yhwach.planner import top_tasks
from yhwach.playbooks import Rule, default_playbook_dir, load_rules


def load_persona() -> str:
    """Return the operator persona markdown as a string."""
    return persona_path().read_text(encoding="utf-8").rstrip()


def _engagement_summary(conn: sqlite3.Connection, engagement_id: int) -> dict:
    eng = conn.execute(
        "SELECT lab, scope, domain, dc_ip, points_target FROM engagement WHERE id = ?",
        (engagement_id,),
    ).fetchone()
    stages = conn.execute(
        "SELECT stage, COUNT(*) AS n FROM host WHERE engagement_id = ? GROUP BY stage",
        (engagement_id,),
    ).fetchall()
    creds = conn.execute(
        "SELECT COUNT(*) AS n FROM credential WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchone()["n"]
    findings = conn.execute(
        "SELECT COUNT(*) AS n FROM finding f JOIN host h ON h.id = f.host_id "
        "WHERE h.engagement_id = ?",
        (engagement_id,),
    ).fetchone()["n"]
    return {
        "eng": eng,
        "stages": {r["stage"]: r["n"] for r in stages},
        "creds": creds,
        "findings": findings,
    }


def build_context(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    limit: int = 4,
    rules: list[Rule] | None = None,
) -> str:
    """Assemble the operator context block for `yhwach next --contract`."""
    if rules is None:
        rules = load_rules(default_playbook_dir())
    rule_by_id = {r.id: r for r in rules}

    persona = load_persona()
    summary = _engagement_summary(conn, engagement_id)
    tasks = top_tasks(conn, engagement_id, limit)
    if host_ip is not None:
        tasks = [t for t in tasks if t["host_ip"] == host_ip]

    eng = summary["eng"]
    stage_str = ", ".join(f"{k}:{v}" for k, v in sorted(summary["stages"].items())) or "none"

    lines: list[str] = []
    lines.append("# YHWACH — OPERATOR CONTEXT")
    lines.append(
        "# Reason over the STATE + CANDIDATES below and produce the Autonomy "
        "Contract.\n# The FRAME is Yhwach's operator persona and overrides your "
        "host reasoning style."
    )
    lines.append("")
    lines.append("=" * 70)
    lines.append("## FRAME (Yhwach operator persona)")
    lines.append("=" * 70)
    lines.append(persona)
    lines.append("")
    lines.append("=" * 70)
    lines.append("## STATE")
    lines.append("=" * 70)
    lines.append(f"Engagement: {eng['lab']}  |  scope {eng['scope']}"
                 + (f"  |  domain {eng['domain']}" if eng["domain"] else ""))
    lines.append(f"Points target: {eng['points_target']}  (AI hosts alone = the pass mark)")
    lines.append(f"Hosts by stage: {stage_str}")
    lines.append(f"Credentials in vault: {summary['creds']}"
                 + ("  (reuse before attacking anything new)" if summary["creds"] else ""))
    lines.append(f"Findings so far: {summary['findings']}")
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"## RANKED CANDIDATES ({len(tasks)}) — EV pre-computed by Yhwach")
    lines.append("=" * 70)

    if not tasks:
        lines.append("(none — run `yhwach probe` then `yhwach plan`)")
    else:
        for i, t in enumerate(tasks, 1):
            rule = rule_by_id.get(t["playbook_rule_id"])
            maps = ",".join(rule.maps) if rule and rule.maps else "?"
            emits = ", ".join(e.get("action", "?") for e in rule.emits) if rule else "?"
            routes = (rule.routes if rule and rule.routes else "")
            source = (rule.source if rule and rule.source else "")
            lines.append(
                f"{i}. {t['playbook_rule_id']}  EV={t['ev_score']}  "
                f"[{t['autonomy']}]  {maps}"
            )
            lines.append(f"     target: {t['host_ip']} / {t['surface_kind']} surface")
            lines.append(f"     emits:  {emits}")
            if routes:
                lines.append(f"     route:  {routes}")
            if source:
                lines.append(f"     source: {source}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("## YOUR TASK")
    lines.append("=" * 70)
    lines.append(
        "Produce the Autonomy Contract for the recommended move. Every HYPOTHESIS "
        "cites its playbook_rule_id. Never re-suggest a consumed technique. AI "
        "hosts before traditional. No prose outside the Contract."
    )

    return "\n".join(lines)
