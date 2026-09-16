"""Yhwach CLI.

Phase 1.1 subcommands: engage / ingest / status. Full planned surface is in
`cli/README.md`; the rest lands as later phases add their capabilities.

DB location resolution:
  1. --db flag on the subcommand
  2. YHWACH_DB env var
  3. ~/osai/current/state/yhwach.db (matches /osai-engage's lab directory)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from yhwach import __version__
from yhwach import db as yhdb
from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml
from yhwach.probes import PROBES_BY_PORT, new_session, run_probes

DEFAULT_DB_ENV = "YHWACH_DB"
DEFAULT_DB_FALLBACK = "~/osai/current/state/yhwach.db"


def _db_path(override: str | None = None) -> Path:
    raw = override or os.environ.get(DEFAULT_DB_ENV) or DEFAULT_DB_FALLBACK
    return Path(os.path.expanduser(raw))


@click.group()
@click.version_option(__version__, prog_name="yhwach")
def main() -> None:
    """Yhwach — deterministic red-team engagement engine.

    Authorized for the OffSec OSAI exam and authorized AI-security labs only.
    See AUTHORIZATION.md.
    """


@main.command()
@click.option("--lab", required=True, help="Lab name (unique per engagement).")
@click.option("--scope", required=True, help="Comma-separated CIDRs / IPs.")
@click.option("--domain", default=None, help="AD domain (optional).")
@click.option("--dc", "dc_ip", default=None, help="DC IP (optional).")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path (else $YHWACH_DB or the default).")
def engage(lab: str, scope: str, domain: str | None, dc_ip: str | None,
           db_path: str | None) -> None:
    """Initialize an engagement: create the DB if needed, upsert the engagement row."""
    path = _db_path(db_path)
    if not path.exists():
        yhdb.init(path)
        click.echo(f"[+] Created DB at {path}")
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab=lab, scope=scope,
                                        domain=domain, dc_ip=dc_ip)
    click.echo(f"[+] Engagement '{lab}' ready (id={eng_id})")


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--lab", required=True, help="Lab name (must exist).")
@click.option("--kind", type=click.Choice(["nmap"]), default="nmap",
              help="Parser kind. Only 'nmap' is implemented in Phase 1.1.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path.")
def ingest(file: str, lab: str, kind: str, db_path: str | None) -> None:
    """Parse a tool output file and update the world model."""
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)

    if kind != "nmap":  # future-proof; click.Choice enforces the set for now
        click.echo(f"[!] Parser '{kind}' not implemented yet.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'. Did you run `yhwach engage`?", err=True)
            sys.exit(2)
        hosts = parse_nmap_xml(file)
        h, s = insert_hosts(conn, eng_id, hosts)
    click.echo(f"[+] Ingested {kind}: {h} hosts, {s} services")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path.")
def status(lab: str, db_path: str | None) -> None:
    """Print the engagement scoreboard: hosts x stage, services, tasks."""
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)

        stage_counts = conn.execute(
            "SELECT stage, COUNT(*) AS n FROM host "
            "WHERE engagement_id = ? GROUP BY stage ORDER BY stage",
            (eng_id,),
        ).fetchall()
        service_total = conn.execute(
            "SELECT COUNT(*) AS n FROM service s "
            "JOIN host h ON h.id = s.host_id WHERE h.engagement_id = ?",
            (eng_id,),
        ).fetchone()["n"]
        task_counts = conn.execute(
            "SELECT status, COUNT(*) AS n FROM task "
            "WHERE engagement_id = ? GROUP BY status",
            (eng_id,),
        ).fetchall()

    click.echo(f"== Engagement '{lab}' (id={eng_id}) ==")
    click.echo("Hosts by stage:")
    if not stage_counts:
        click.echo("  (none)")
    for row in stage_counts:
        click.echo(f"  {row['stage']:<15} {row['n']}")
    click.echo(f"Services: {service_total}")
    click.echo("Tasks:")
    if not task_counts:
        click.echo("  (none)")
    for row in task_counts:
        click.echo(f"  {row['status']:<15} {row['n']}")


@main.command()
@click.option("--lab", required=True, help="Lab name (must exist).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def plan(lab: str, db_path: str | None) -> None:
    """Match playbook rules against the world model; populate the task queue.

    Deterministic — no LLM. Reads playbooks/*.yaml, matches each rule's `when`
    clause against current surfaces, and upserts an EV-scored task per match.
    """
    from yhwach.planner import match_rules
    from yhwach.playbooks import default_playbook_dir, load_rules

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)

    rules = load_rules(default_playbook_dir())

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        report = match_rules(conn, eng_id, rules)

    click.echo(f"[+] Rules loaded: {len(rules)}")
    click.echo(f"[+] Rules matched: {report.rules_matched}")
    click.echo(f"[+] Tasks: {report.tasks_created} new, {report.tasks_updated} updated")
    if report.rules_skipped_unsupported:
        click.echo(
            "[i] Skipped (unsupported when-keys, land in a later phase): "
            + ", ".join(report.rules_skipped_unsupported)
        )


@main.command("next")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--limit", default=5, show_default=True, type=int,
              help="How many top tasks to show.")
@click.option("--host", "host_ip", default=None, help="Focus on one host IP.")
@click.option("--contract", is_flag=True, default=False,
              help="Emit the full operator context block (persona + state + "
                   "candidates) for Claude Code to reason over into an Autonomy Contract.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def next_cmd(lab: str, limit: int, host_ip: str | None, contract: bool,
             db_path: str | None) -> None:
    """Show the top EV-ranked pending tasks, or (--contract) the operator context.

    Default: a compact ranked list. With --contract: the full persona + state +
    candidate block the operator reasons over. Yhwach never calls a model itself.
    """
    from yhwach.context import build_context
    from yhwach.planner import top_tasks

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)

        if contract:
            block = build_context(conn, eng_id, host_ip=host_ip, limit=limit)
            click.echo(block)
            return

        tasks = top_tasks(conn, eng_id, limit)
        if host_ip is not None:
            tasks = [t for t in tasks if t["host_ip"] == host_ip]

    if not tasks:
        click.echo("[!] No pending tasks. Run `yhwach probe` then `yhwach plan` first.")
        return

    click.echo(f"== Top {len(tasks)} tasks for '{lab}' (by EV) ==")
    for i, t in enumerate(tasks, 1):
        click.echo(
            f"{i}. EV={t['ev_score']:<6} [{t['autonomy']:<7}] "
            f"{t['host_ip']} {t['surface_kind']} -> {t['playbook_rule_id']} ({t['kind']})"
        )
        click.echo(f"     {t['rationale']}")


@main.command()
@click.option("--lab", required=True, help="Lab name (must exist).")
@click.option("--out", "out_path", default=None, type=click.Path(),
              help="Write the fixture YAML here (default: stdout).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def snapshot(lab: str, out_path: str | None, db_path: str | None) -> None:
    """Dump the current world model as a fixture YAML (for the regression corpus).

    Run this after a lab so the scenario becomes a permanent golden test. Add an
    `expected:` block by hand (or your correction) to turn it into an assertion.
    """
    import yaml as _yaml

    from yhwach.fixtures import snapshot_world_model

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        snap = snapshot_world_model(conn, eng_id)

    snap["expected"] = {
        "autonomy": None,
        "top_hypothesis": {"playbook_rule_id": None},
        "must_include_hypotheses": [],
        "must_not_include": [],
    }
    text = _yaml.safe_dump(snap, sort_keys=False, allow_unicode=True)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        click.echo(f"[+] wrote {out_path} — fill in the `expected:` block to make it a golden test")
    else:
        click.echo(text)


@main.command()
@click.option("--fixtures", "fixtures_dir", default=None, type=click.Path(),
              help="Fixtures dir (default: repo tests/fixtures).")
def selftest(fixtures_dir: str | None) -> None:
    """Run all golden fixtures and report pass/fail. Exits non-zero on any failure."""
    from yhwach.fixtures import default_fixtures_dir, run_fixture_file

    d = Path(fixtures_dir) if fixtures_dir else default_fixtures_dir()
    files = sorted(d.rglob("*.yaml"))
    if not files:
        click.echo(f"[!] No *.yaml fixtures in {d}.", err=True)
        sys.exit(2)

    failed = 0
    for f in files:
        res = run_fixture_file(f)
        mark = "PASS" if res.passed else "FAIL"
        click.echo(f"[{mark}] {res.name}  (top={res.top_actual})")
        for msg in res.failures:
            click.echo(f"        - {msg}")
        failed += 0 if res.passed else 1

    total = len(files)
    click.echo(f"[=] {total - failed}/{total} fixtures passed.")
    if failed:
        sys.exit(1)


@main.command()
@click.option("--risk", type=click.Choice(["read_only", "propose", "destructive"]), default=None,
              help="Filter by risk.")
def actions(risk: str | None) -> None:
    """List the registered actions (emits -> concrete commands)."""
    from yhwach.actions import ACTION_REGISTRY

    for aid in sorted(ACTION_REGISTRY):
        a = ACTION_REGISTRY[aid]
        if risk and a.risk != risk:
            continue
        runflag = "run" if (a.risk == "read_only" and a.runnable) else "render-only"
        click.echo(f"{aid:<28} {a.risk:<12} {runflag}")
        if a.note:
            click.echo(f"    note: {a.note}")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--task", "task_id", required=True, type=int, help="Task id (from `yhwach next`).")
@click.option("--go", is_flag=True, default=False,
              help="Execute read-only actions and capture output to loot/ (default: render only).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def run(lab: str, task_id: int, go: bool, db_path: str | None) -> None:
    """Render (and with --go, execute read-only) the actions for a task.

    Proposal-tier and render-only actions are printed for the operator to run,
    never auto-executed — Yhwach proposes, the operator exploits.
    """
    import json as _json

    from yhwach.actions import context_from_surface, get_action, render_action, run_action
    from yhwach.playbooks import default_playbook_dir, load_rules

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)

    rules = {r.id: r for r in load_rules(default_playbook_dir())}

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        row = conn.execute(
            "SELECT t.playbook_rule_id AS rule_id, t.target_host_id AS host_id, "
            "t.target_surface_id AS surface_id, h.ip AS ip, s.meta_json AS meta, "
            "svc.port AS port "
            "FROM task t JOIN host h ON h.id = t.target_host_id "
            "LEFT JOIN surface s ON s.id = t.target_surface_id "
            "LEFT JOIN service svc ON svc.id = s.service_id "
            "WHERE t.id = ? AND t.engagement_id = ?",
            (task_id, eng_id),
        ).fetchone()

    if row is None:
        click.echo(f"[!] Task {task_id} not found in lab '{lab}'.", err=True)
        sys.exit(2)

    rule = rules.get(row["rule_id"])
    if rule is None:
        click.echo(f"[!] Rule '{row['rule_id']}' not found in playbooks.", err=True)
        sys.exit(2)

    try:
        meta = _json.loads(row["meta"]) if row["meta"] else {}
    except (ValueError, TypeError):
        meta = {}
    ctx = context_from_surface(row["ip"], row["port"] or "PORT", meta)
    loot_dir = path.parent.parent / "loot"

    click.echo(f"== Task {task_id}: {row['rule_id']} @ {row['ip']} ==")
    for emit in rule.emits:
        action = get_action(emit.get("action", ""))
        if action is None:
            click.echo(f"[-] {emit.get('action', '?')}: no command mapped")
            continue
        rendered = render_action(action, ctx)
        can_run = action.risk == "read_only" and action.runnable
        for cmd in rendered:
            click.echo(f"  $ {cmd}" + ("" if can_run else f"   [{action.risk}, render-only]"))
        if go and can_run:
            from yhwach.interpret import interpret_output

            for res in run_action(action, ctx, loot_dir=loot_dir):
                head = "\n".join((res["output"] or "").splitlines()[:8])
                click.echo(f"    -> rc={res['returncode']}  loot={res.get('loot_file','-')}")
                if head.strip():
                    click.echo("    | " + head.replace("\n", "\n    | "))
                # Deterministic finding extraction.
                found = interpret_output(action.id, res.get("output", ""), ctx)
                if found is not None:
                    with yhdb.transaction(path) as c2:
                        _, created = yhdb.add_finding(
                            c2, row["host_id"], row["surface_id"], found.cls,
                            found.title, found.severity, found.evidence, row["rule_id"],
                        )
                    click.echo(
                        f"    [finding] {found.severity.upper()} {found.cls} "
                        f"{found.title} ({'new' if created else 'updated'})"
                    )
        elif go and not can_run:
            click.echo(f"    (skipped --go: {action.risk}/render-only — operator runs this)")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def findings(lab: str, db_path: str | None) -> None:
    """List recorded findings, most severe first."""
    order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
            "WHEN 'medium' THEN 2 ELSE 3 END"
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        rows = conn.execute(
            "SELECT f.class, f.title, f.severity, f.evidence, h.ip AS ip "
            "FROM finding f LEFT JOIN host h ON h.id = f.host_id "
            "WHERE (h.engagement_id = ? OR f.host_id IS NULL) AND f.status = 'open' "
            f"ORDER BY {order}, f.id",
            (eng_id,),
        ).fetchall()
    if not rows:
        click.echo("[!] No findings yet. Run `yhwach run --task N --go` on read-only tasks.")
        return
    click.echo(f"== Findings for '{lab}' ({len(rows)}) ==")
    for r in rows:
        click.echo(f"[{r['severity'].upper():<8}] {r['class']:<8} {r['ip'] or '-':<16} {r['title']}")
        if r["evidence"]:
            click.echo(f"           {r['evidence']}")


@main.command()
def persona() -> None:
    """Print the operator persona in effect (the reasoning frame Yhwach injects)."""
    import hashlib

    from yhwach.context import load_persona

    text = load_persona()
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    click.echo(text)
    click.echo("")
    click.echo(f"# persona sha256:{digest}")


@main.command()
@click.option("--lab", required=True, help="Lab name (must exist).")
@click.option("--host", "host_ip", default=None,
              help="Restrict probing to one host IP; if omitted, probe every scanned host.")
@click.option("--timeout", default=3.0, show_default=True, type=float,
              help="Per-request HTTP timeout in seconds.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path.")
def probe(lab: str, host_ip: str | None, timeout: float, db_path: str | None) -> None:
    """Probe scanned hosts for AI attack surfaces (Ollama/OpenAI/chatbot/MCP/Gradio).

    Sends short-timeout HTTP requests to authorized targets only. Populates the
    `surface` table with kind/auth/meta so playbook rules can match against it.
    """
    import json as _json

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)

    from yhwach.probes.traditional import detect_traditional

    session = new_session()

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)

        services = yhdb.all_services_for_scanned_hosts(conn, eng_id)
        if host_ip is not None:
            services = [s for s in services if s["ip"] == host_ip]

        if not services:
            click.echo("[!] No scanned hosts with services.")
            return

        surfaces_found = 0
        surfaces_new = 0

        def _record(t, result, label):
            nonlocal surfaces_found, surfaces_new
            _, created = yhdb.upsert_surface(
                conn,
                host_id=t["host_id"],
                service_id=t["service_id"],
                kind=result.kind,
                auth=result.auth,
                meta_json=_json.dumps(result.meta, sort_keys=True),
            )
            surfaces_found += 1
            surfaces_new += 1 if created else 0
            click.echo(
                f"[+] {t['ip']}:{t['port']} -> {result.kind} (auth={result.auth}) "
                f"[{label}] {'NEW' if created else 'UPD'}"
            )

        for s in services:
            # AI surfaces (fixed port list).
            if s["port"] in PROBES_BY_PORT:
                ai = run_probes(session, s["ip"], s["port"], timeout=timeout)
                if ai is not None:
                    _record(s, ai, "ai")
            # Traditional surfaces (all services).
            trad = detect_traditional(session, s["ip"], s["port"], s["product"], timeout=timeout)
            if trad is not None:
                _record(s, trad, "traditional")

        click.echo(f"[=] {surfaces_found} surfaces detected ({surfaces_new} new).")


if __name__ == "__main__":
    main()
