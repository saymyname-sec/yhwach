"""MCP tool logic — pure functions returning text, independent of the MCP SDK.

These back the Yhwach MCP server (mcp_server.py) but carry no `mcp` dependency,
so they are unit-tested directly. Each takes a db path + args and returns a
string the operator's Claude reads. Yhwach never calls a model; `tool_next`
returns the persona-framed context block for the host to reason over.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.context import build_context
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import default_playbook_dir, load_rules
from yhwach.report import build_report
from yhwach.spray import build_spray_plan


def _eng(conn, lab: str) -> int:
    eid = yhdb.engagement_id_for(conn, lab)
    if eid is None:
        raise ValueError(f"unknown lab '{lab}' — run engage first")
    return eid


def tool_status(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        stages = conn.execute(
            "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage ORDER BY stage",
            (eid,)).fetchall()
        svc = conn.execute(
            "SELECT COUNT(*) n FROM service s JOIN host h ON h.id=s.host_id WHERE h.engagement_id=?",
            (eid,)).fetchone()["n"]
        pend = conn.execute(
            "SELECT COUNT(*) n FROM task WHERE engagement_id=? AND status='pending'", (eid,)).fetchone()["n"]
        creds = conn.execute(
            "SELECT COUNT(*) n FROM credential WHERE engagement_id=?", (eid,)).fetchone()["n"]
    lines = [f"Engagement '{lab}':"]
    lines += [f"  {r['stage']}: {r['n']}" for r in stages] or ["  (no hosts)"]
    lines.append(f"  services={svc}  pending_tasks={pend}  vault={creds}")
    return "\n".join(lines)


def tool_plan(db_path: Path | str, lab: str) -> str:
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rep = match_rules(conn, eid, rules)
    msg = (f"rules matched {rep.rules_matched}; tasks {rep.tasks_created} new, "
           f"{rep.tasks_updated} updated")
    if rep.rules_skipped_consumed:
        msg += f"; skipped consumed: {', '.join(rep.rules_skipped_consumed)}"
    if rep.surfaces_filtered_denylist:
        msg += f"; filtered {rep.surfaces_filtered_denylist} denylisted surface(s)"
    return msg


def tool_next(db_path: Path | str, lab: str, limit: int = 4) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_context(conn, eid, limit=limit)


def tool_findings(db_path: Path | str, lab: str) -> str:
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 ELSE 3 END")
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rows = conn.execute(
            "SELECT f.class, f.title, f.severity, h.ip ip FROM finding f "
            "LEFT JOIN host h ON h.id=f.host_id "
            "WHERE (h.engagement_id=? OR f.host_id IS NULL) AND f.status='open' "
            f"ORDER BY {order}, f.id", (eid,)).fetchall()
    if not rows:
        return "no findings"
    return "\n".join(f"[{r['severity'].upper()}] {r['class']} {r['ip'] or '-'} {r['title']}"
                     for r in rows)


def tool_report(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_report(conn, eid)


def tool_spray(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        cmds = build_spray_plan(conn, eid)
    return "\n".join(cmds) if cmds else "nothing to spray (empty vault or no sprayable surfaces)"


def tool_add_cred(db_path: Path | str, lab: str, user: str, secret: str,
                  kind: str = "password", source: str = "operator") -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        _, created = yhdb.add_credential(conn, eid, user, secret, kind, source)
        yhdb.log_event(conn, eid, "credential", {"id": user, "kind": kind, "source": source})
    return f"credential '{user}' ({kind}) {'added' if created else 'updated'}"


def tool_advance(db_path: Path | str, lab: str, host: str, stage: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        changed, msg = yhdb.set_host_stage(conn, eid, host, stage)
        if changed:
            yhdb.log_event(conn, eid, "stage", {"host": host, "stage": stage})
    return f"{host} -> {stage}" if changed else f"refused: {msg}"


# Registry of (name, fn, description) for the server to expose.
TOOL_SPECS = [
    ("yhwach_status", tool_status, "Engagement scoreboard: hosts by stage, services, tasks, vault."),
    ("yhwach_plan", tool_plan, "Match playbooks against the world model; populate the task queue."),
    ("yhwach_next", tool_next, "The operator context block (persona + state + ranked candidates + commands)."),
    ("yhwach_findings", tool_findings, "Recorded findings, most severe first."),
    ("yhwach_report", tool_report, "Full Markdown engagement report."),
    ("yhwach_spray", tool_spray, "Credential-spray commands (vault creds x sprayable surfaces)."),
    ("yhwach_add_cred", tool_add_cred, "Add a credential to the vault."),
    ("yhwach_advance", tool_advance, "Advance a host's FSM stage (foothold/looted/pivoted/...)."),
]
