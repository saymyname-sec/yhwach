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

    session = new_session()

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)

        targets = yhdb.scanned_hosts_with_ports(conn, eng_id, list(PROBES_BY_PORT.keys()))
        if host_ip is not None:
            targets = [t for t in targets if t["ip"] == host_ip]

        if not targets:
            click.echo("[!] No scanned hosts with probe-eligible ports.")
            return

        surfaces_found = 0
        surfaces_new = 0
        for t in targets:
            result = run_probes(session, t["ip"], t["port"], timeout=timeout)
            if result is None:
                continue
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
                f"{'NEW' if created else 'UPD'}"
            )

        click.echo(f"[=] {surfaces_found} surfaces detected ({surfaces_new} new).")


if __name__ == "__main__":
    main()
