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
from yhwach.db import list_credentials
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
    # Match report.py / mcp_tools counting: include engagement hosts' findings
    # plus unscoped (host_id IS NULL) ones, via a LEFT JOIN so counts agree.
    findings = conn.execute(
        "SELECT COUNT(*) AS n FROM finding f LEFT JOIN host h ON h.id = f.host_id "
        "WHERE h.engagement_id = ? OR f.host_id IS NULL",
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
    tasks = top_tasks(conn, engagement_id, limit, host_ip=host_ip)

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

    # ------------------------------------------------------------------
    # VAULT — inline so "reuse before you work" is actionable, not aspirational.
    # Every stored access artifact (password/hash/ssh_key/token) is quoted in
    # full: the operator downstream (Claude, msf, spray) can't reuse what it
    # can't see. Long/multiline secrets are one-line-summarised.
    # ------------------------------------------------------------------
    cred_rows = list_credentials(conn, engagement_id)
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"## VAULT ({len(cred_rows)})  — reuse before you work")
    lines.append("=" * 70)
    if not cred_rows:
        lines.append("(empty)")
    else:
        for r in cred_rows:
            sec = r["secret"] or "(none)"
            if "\n" in sec:
                sec = sec.split("\n", 1)[0][:60] + " …(multiline; use yhwach_creds)"
            src = r["source"] or ""
            if r["source_host_ip"]:
                src = f"{src} @ {r['source_host_ip']}"
            lines.append(f"  - {r['identifier']}  ({r['kind']})  =  {sec}   [{src}]")

    lines.append("")
    lines.append("=" * 70)
    lines.append(f"## RANKED CANDIDATES ({len(tasks)}) — EV pre-computed by Yhwach")
    lines.append("=" * 70)

    if not tasks:
        lines.append("(none — run `yhwach probe` then `yhwach plan`)")
    else:
        import json as _json

        from yhwach.actions import context_from_surface, get_action, render_action

        for i, t in enumerate(tasks, 1):
            rule = rule_by_id.get(t["playbook_rule_id"])
            maps = ",".join(rule.maps) if rule and rule.maps else "?"
            routes = (rule.routes if rule and rule.routes else "")
            source = (rule.source if rule and rule.source else "")
            lines.append(
                f"{i}. {t['playbook_rule_id']}  EV={t['ev_score']}  "
                f"[{t['autonomy']}]  {maps}"
            )
            lines.append(f"     target: {t['host_ip']} / {t['surface_kind']} surface")

            # Render concrete commands for each emitted action.
            meta = {}
            try:
                meta = _json.loads(t["surface_meta"]) if t["surface_meta"] else {}
            except (ValueError, TypeError):
                meta = {}
            ctx = context_from_surface(t["host_ip"], t["surface_port"] or "PORT", meta)

            emits = rule.emits if rule else []
            for emit in emits:
                action = get_action(emit.get("action", ""))
                if action is None:
                    lines.append(f"     - {emit.get('action', '?')}: (no command mapped yet)")
                    continue
                for cmd in render_action(action, ctx):
                    flag = "" if (action.risk == "read_only" and action.runnable) else f"  [{action.risk}]"
                    lines.append(f"     $ {cmd}{flag}")
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
    lines.append("")
    lines.append(
        "NOTEBOOK: the engagement notebook is the Obsidian vault, and it is the "
        "single source of truth for write-ups. Whenever this turn reaches an "
        "objective — a confirmed finding, foothold, loot, a working PoC, or a "
        "pivot — write it into the vault via the Obsidian MCP, in full detail "
        "(exact commands, payloads, captured output, evidence paths), following "
        "the notebook protocol in the FRAME. Notes are never stored in Yhwach's DB."
    )

    return "\n".join(lines)
