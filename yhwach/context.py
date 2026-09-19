"""Context assembly for the operator handoff.

Phase 1.4 model: Yhwach does NOT call an LLM. It emits a single structured
block — persona frame + state slice + EV-ranked candidates — that the operator
(Claude Code on Kali, or any capable model) reasons over to produce the
Autonomy Contract. The persona travels with the block so it overrides whatever
reasoning style the host CLI would otherwise apply.

Two knobs exist for the operator's own context budget:

  * `persona=False` — emit the persona's SHA-256 instead of its ~7 KB body. The
    frame is already in the model's context on turn 2..N of a session; re-sending
    it every turn is pure token cost. The digest lets the operator verify the
    frame it holds is the frame in effect (`yhwach persona` reprints it).
  * `build_context_json` — the same slice as data, for an operator that would
    rather parse than read.
"""
from __future__ import annotations

import hashlib
import json as _json
import sqlite3

from yhwach import persona_path
from yhwach.coverage import enum_gaps, gaps_as_dicts, render_gaps
from yhwach.db import list_credentials
from yhwach.memory import dead_ends
from yhwach.planner import top_tasks
from yhwach.playbooks import Rule, default_playbook_dir, load_rules
from yhwach.primitives import p0_leads

# How many under-enumerated hosts to name inline before deferring to `yhwach gaps`.
GAPS_IN_HANDOFF = 3


def load_persona() -> str:
    """Return the operator persona markdown as a string."""
    return persona_path().read_text(encoding="utf-8").rstrip()


def persona_digest() -> str:
    """Short SHA-256 of the persona in effect — proof of which frame shaped a judgment."""
    return hashlib.sha256(load_persona().encode("utf-8")).hexdigest()[:12]


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
        "SELECT COUNT(*) AS n FROM finding WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchone()["n"]
    return {
        "eng": eng,
        "stages": {r["stage"]: r["n"] for r in stages},
        "creds": creds,
        "findings": findings,
    }


def _candidates(
    tasks: list[sqlite3.Row],
    rule_by_id: dict[str, Rule],
    domain: str | None,
) -> list[dict]:
    """Ranked tasks as data: rule provenance + the concrete commands to run."""
    from yhwach.actions import context_from_surface, get_action, render_action

    out: list[dict] = []
    for i, t in enumerate(tasks, 1):
        rule = rule_by_id.get(t["playbook_rule_id"])
        try:
            meta = _json.loads(t["surface_meta"]) if t["surface_meta"] else {}
        except (ValueError, TypeError):
            meta = {}
        ctx = context_from_surface(t["host_ip"], t["surface_port"] or "PORT", meta)
        if domain:
            ctx["DOMAIN"] = domain

        commands: list[dict] = []
        for emit in (rule.emits if rule else []):
            action = get_action(emit.get("action", ""))
            if action is None:
                commands.append({"action": emit.get("action", "?"), "cmd": None,
                                 "risk": None, "runnable": False})
                continue
            for cmd in render_action(action, ctx):
                commands.append({"action": action.id, "cmd": cmd, "risk": action.risk,
                                 "runnable": bool(action.risk == "read_only"
                                                  and action.runnable)})
        out.append({
            "rank": i,
            "task_id": t["id"],
            "rule_id": t["playbook_rule_id"],
            "ev": t["ev_score"],
            "autonomy": t["autonomy"],
            "technique_class": t["technique_class"],
            "maps": list(rule.maps) if rule and rule.maps else [],
            "host": t["host_ip"],
            "surface": t["surface_kind"],
            "port": t["surface_port"],
            "route": (rule.routes if rule else None),
            "source": (rule.source if rule else None),
            "commands": commands,
        })
    return out


def collect_context(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    limit: int = 4,
    rules: list[Rule] | None = None,
) -> dict:
    """Everything the handoff is built from, as data. Shared by both renderers."""
    if rules is None:
        rules = load_rules(default_playbook_dir())
    rule_by_id = {r.id: r for r in rules}

    summary = _engagement_summary(conn, engagement_id)
    eng = summary["eng"]
    tasks = top_tasks(conn, engagement_id, limit, host_ip=host_ip)

    return {
        "persona_sha256": persona_digest(),
        "engagement": {
            "lab": eng["lab"],
            "scope": eng["scope"],
            "domain": eng["domain"],
            "points_target": eng["points_target"],
        },
        "stages": summary["stages"],
        "findings_count": summary["findings"],
        "vault": [
            {"identifier": r["identifier"], "kind": r["kind"], "secret": r["secret"],
             "source": r["source"], "source_host": r["source_host_ip"]}
            for r in list_credentials(conn, engagement_id)
        ],
        "p0_leads": [dict(r) for r in p0_leads(conn, engagement_id)],
        "dead_ends": [dict(r) for r in dead_ends(conn, engagement_id, limit=8)],
        "enum_gaps": gaps_as_dicts(enum_gaps(conn, engagement_id, host_ip=host_ip)),
        "attack_path": _attack_path_data(conn, engagement_id),
        "candidates": _candidates(tasks, rule_by_id, eng["domain"]),
    }


def _attack_path_data(conn: sqlite3.Connection, engagement_id: int) -> dict | None:
    """The shortest owned->DA path as data, for the JSON handoff (None if none)."""
    best = shortest_owned_to_da(conn, engagement_id)
    if not best:
        return None
    return {"hops": len(best) - 1, "route": render_attack_path(conn, best),
            "nodes": best}


def build_context_json(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    limit: int = 4,
    rules: list[Rule] | None = None,
) -> str:
    """The handoff as JSON (no persona body — the digest identifies the frame)."""
    data = collect_context(conn, engagement_id, host_ip=host_ip, limit=limit, rules=rules)
    return _json.dumps(data, indent=2, sort_keys=False)


_OWNED_STAGES = ("foothold", "looted", "pivoted", "done")


def _fmt_node(conn: sqlite3.Connection, node: str) -> str:
    kind, _, nid = node.partition(":")
    if kind == "principal":
        r = conn.execute("SELECT name FROM principal WHERE id=?", (nid,)).fetchone()
        return r["name"] if r else node
    r = conn.execute("SELECT hostname, ip FROM host WHERE id=?", (nid,)).fetchone()
    return (r["hostname"] or r["ip"]) if r else node


def shortest_owned_to_da(conn: sqlite3.Connection, engagement_id: int) -> list[str] | None:
    """Shortest edge-path (node ids) from an owned node to Domain/Enterprise Admins.

    Owned = hosts at foothold+ and principals we hold a credential for (linked by
    principal_id or by identifier==name). None when there is no graph, no owned
    node, no DA target, or no known path. Shared by the text and JSON handoffs."""
    from yhwach.db import shortest_path

    if not conn.execute("SELECT 1 FROM edge WHERE engagement_id=? LIMIT 1",
                        (engagement_id,)).fetchone():
        return None
    targets = [f"principal:{r['id']}" for r in conn.execute(
        "SELECT id FROM principal WHERE engagement_id=? AND type='group' "
        "AND name IN ('Domain Admins','Enterprise Admins')", (engagement_id,))]
    if not targets:
        return None

    owned: list[str] = [f"host:{r['id']}" for r in conn.execute(
        "SELECT id FROM host WHERE engagement_id=? AND stage IN (?,?,?,?)",
        (engagement_id, *_OWNED_STAGES))]
    owned += [f"principal:{r['id']}" for r in conn.execute(
        "SELECT DISTINCT p.id FROM principal p WHERE p.engagement_id=? AND ("
        "EXISTS (SELECT 1 FROM credential c WHERE c.principal_id=p.id) OR "
        "EXISTS (SELECT 1 FROM credential c WHERE c.engagement_id=p.engagement_id "
        "AND c.identifier=p.name COLLATE NOCASE))", (engagement_id,))]
    if not owned:
        return None

    best: list[str] | None = None
    for src in owned:
        for dst in targets:
            p = shortest_path(conn, engagement_id, src, dst)
            if p and (best is None or len(p) < len(best)):
                best = p
    return best


def render_attack_path(conn: sqlite3.Connection, path: list[str]) -> str:
    """A node-id path -> 'DC01 --HasSession--> svc_sql --MemberOf--> Domain Admins'."""
    rendered = _fmt_node(conn, path[0])
    for i in range(1, len(path)):
        e = conn.execute("SELECT kind FROM edge WHERE src=? AND dst=? LIMIT 1",
                         (path[i - 1], path[i])).fetchone()
        rendered += f"  --{e['kind'] if e else '?'}-->  {_fmt_node(conn, path[i])}"
    return rendered


def _attack_path_block(conn: sqlite3.Connection, engagement_id: int) -> list[str]:
    """The text-handoff PATH TO OBJECTIVE block ([] when there's nothing to show)."""
    if not conn.execute("SELECT 1 FROM edge WHERE engagement_id=? LIMIT 1",
                        (engagement_id,)).fetchone():
        return []
    # A DA target exists but no route -> say so; no target at all -> stay silent.
    has_da = conn.execute(
        "SELECT 1 FROM principal WHERE engagement_id=? AND type='group' "
        "AND name IN ('Domain Admins','Enterprise Admins') LIMIT 1", (engagement_id,)).fetchone()
    best = shortest_owned_to_da(conn, engagement_id)
    if not best:
        if has_da:
            return ["  (no known path yet — enumerate more edges via bloodhound/netexec)"]
        return []
    return [f"  {render_attack_path(conn, best)}",
            f"  ({len(best) - 1} hop(s) — `yhwach path` for alternatives)"]


def build_context(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    limit: int = 4,
    rules: list[Rule] | None = None,
    persona: bool = True,
) -> str:
    """Assemble the operator context block for `yhwach next --contract`."""
    if rules is None:
        rules = load_rules(default_playbook_dir())
    rule_by_id = {r.id: r for r in rules}

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
    if persona:
        lines.append(load_persona())
    else:
        # Cheap turn: the frame is already loaded; this pins WHICH frame it is.
        lines.append(f"(persona omitted — sha256:{persona_digest()} is in effect; "
                     "run `yhwach persona` to re-read it in full)")
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

    # P0 leads — high-EV findings (DA/cred paths) surfaced above the ranked queue.
    leads = p0_leads(conn, engagement_id)
    if leads:
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"## P0 LEADS ({len(leads)}) — attack these first (credential/DA paths)")
        lines.append("=" * 70)
        for lead in leads:
            lines.append(f"  ! [{lead['severity'].upper()}] {lead['ip'] or '-'}  "
                         f"{lead['tag']}  — {lead['title']}")

    # ------------------------------------------------------------------
    # DEAD ENDS — the attempt ledger's negative half. Without this block a
    # compacted context re-proposes the move it already burned an hour on.
    # ------------------------------------------------------------------
    burned = dead_ends(conn, engagement_id, limit=8)
    if burned:
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"## DEAD ENDS ({len(burned)}) — already tried, do NOT re-propose")
        lines.append("=" * 70)
        for d in burned:
            why = f" — {d['reason']}" if d["reason"] else ""
            lines.append(f"  x {d['host_ip'] or '-'}  {d['rule_id']}  "
                         f"({d['result']} x{d['tries']}, last {d['attempted_at']}){why}")

    # ------------------------------------------------------------------
    # ENUM GAPS — under-enumeration is the top OSAI failure mode; name it
    # before the operator commits to an attack on a half-scanned host.
    # ------------------------------------------------------------------
    gaps = enum_gaps(conn, engagement_id, host_ip=host_ip)
    if gaps:
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"## ENUM GAPS ({len(gaps)}) — finish enumeration before you commit")
        lines.append("=" * 70)
        lines += render_gaps(gaps, limit=GAPS_IN_HANDOFF)

    # PATH TO OBJECTIVE — the attack graph made actionable: shortest known route
    # from what we already hold (owned hosts / principals we have creds for) to
    # Domain/Enterprise Admins, so the operator sees the goal, not just candidates.
    path_lines = _attack_path_block(conn, engagement_id)
    if path_lines:
        lines.append("")
        lines.append("=" * 70)
        lines.append("## PATH TO OBJECTIVE — shortest known route to Domain Admins")
        lines.append("=" * 70)
        lines.extend(path_lines)

    lines.append("")
    lines.append("=" * 70)
    lines.append(f"## RANKED CANDIDATES ({len(tasks)}) — EV pre-computed by Yhwach")
    lines.append("=" * 70)

    if not tasks:
        lines.append("(none — run `yhwach probe` then `yhwach plan`)")
    else:
        for cand in _candidates(tasks, rule_by_id, eng["domain"]):
            maps = ",".join(cand["maps"]) if cand["maps"] else "?"
            lines.append(
                f"{cand['rank']}. {cand['rule_id']}  EV={cand['ev']}  "
                f"[{cand['autonomy']}]  {maps}"
            )
            lines.append(f"     target: {cand['host']} / {cand['surface']} surface"
                         f"   (task {cand['task_id']})")
            for c in cand["commands"]:
                if c["cmd"] is None:
                    lines.append(f"     - {c['action']}: (no command mapped yet)")
                    continue
                flag = "" if c["runnable"] else f"  [{c['risk']}]"
                lines.append(f"     $ {c['cmd']}{flag}")
            if cand["route"]:
                lines.append(f"     route:  {cand['route']}")
            if cand["source"]:
                lines.append(f"     source: {cand['source']}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("## YOUR TASK")
    lines.append("=" * 70)
    lines.append(
        "Produce the Autonomy Contract for the recommended move. Every HYPOTHESIS "
        "cites its playbook_rule_id. Never re-suggest a consumed technique or a "
        "DEAD END. AI hosts before traditional. No prose outside the Contract."
    )
    lines.append("")
    lines.append(
        "REPORT BACK: when the recommended move resolves, record it with "
        "`yhwach outcome --task <id> --result success|fail|blocked|partial --why "
        "'<one line>'`. That is what stops this handoff from proposing it again "
        "after your context is compacted — an unrecorded attempt is a repeated one."
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
