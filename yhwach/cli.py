"""Yhwach CLI.

The engagement driver: engage / ingest / enum / probe / plan / next / run,
post-foothold (advance / cred / creds / spray / consume), findings / report,
and the MCP server (mcp). See `cli/README.md` for the full command reference.

Notes are not a CLI concern: the engagement notebook is the Obsidian vault,
written by the operator via the Obsidian MCP (see persona/notebook.md).

DB location resolution:
  1. --db flag on the subcommand
  2. YHWACH_DB env var
  3. ~/osai/current/state/yhwach.db (matches /osai-engage's lab directory)
"""
from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

import click

from yhwach import __version__
from yhwach import db as yhdb
from yhwach.engine import artifact_dir as _artifact_dir
from yhwach.engine import execute_task
from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml
from yhwach.probes import PROBES_BY_PORT, new_session, run_probes

DEFAULT_DB_ENV = "YHWACH_DB"
DEFAULT_DB_FALLBACK = "~/osai/current/state/yhwach.db"
_HEXSTRIKE_DEFAULT = "http://127.0.0.1:8888"


def _db_path(override: str | None = None) -> Path:
    raw = override or os.environ.get(DEFAULT_DB_ENV) or DEFAULT_DB_FALLBACK
    return Path(os.path.expanduser(raw))


def _force_utf8_output() -> None:
    """Emit UTF-8 regardless of the console codepage.

    Personas, reports, and rendered commands contain non-ASCII (→, —, ·); a
    legacy Windows console (cp1252) would otherwise raise UnicodeEncodeError.
    """
    for stream in (sys.stdout, sys.stderr):
        # not a reconfigurable stream (e.g. captured in tests) -> leave it as-is
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")


@click.group()
@click.version_option(__version__, prog_name="yhwach")
def main() -> None:
    """Yhwach — deterministic red-team engagement engine.

    Authorized for the OffSec OSAI exam and authorized AI-security labs only.
    See AUTHORIZATION.md.
    """
    _force_utf8_output()


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
@click.option("--kind", type=click.Choice(["nmap", "linpeas", "winpeas"]), default="nmap",
              help="Parser kind.")
@click.option("--host", "host_ip", default=None,
              help="Host IP (required for linpeas/winpeas — findings are host-scoped).")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path.")
def ingest(file: str, lab: str, kind: str, host_ip: str | None, db_path: str | None) -> None:
    """Parse a tool output file and update the world model.

    nmap XML -> hosts + services. linpeas/winpeas -> privesc findings on --host
    (also advances that host to 'enumerated').
    """
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'. Did you run `yhwach engage`?", err=True)
            sys.exit(2)

        if kind == "nmap":
            hosts = parse_nmap_xml(file)
            h, s = insert_hosts(conn, eng_id, hosts)
            click.echo(f"[+] Ingested nmap: {h} hosts, {s} services")
            return

        # PEAS: host-scoped privesc findings
        if not host_ip:
            click.echo(f"[!] --host is required for {kind}.", err=True)
            sys.exit(2)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
                            (eng_id, host_ip)).fetchone()
        if hrow is None:
            click.echo(f"[!] Host {host_ip} not found; ingest an nmap scan first.", err=True)
            sys.exit(2)

        from yhwach.parsers.peas import parse_peas

        text = Path(file).read_text(encoding="utf-8", errors="replace")
        found = parse_peas(text, kind)
        for f in found:
            yhdb.add_finding(conn, hrow["id"], None, f.cls, f.title, f.severity, f.evidence,
                             tag=f.tag)
        yhdb.set_host_stage(conn, eng_id, host_ip, "enumerated")
        yhdb.log_event(conn, eng_id, "ingest", {"kind": kind, "host": host_ip, "findings": len(found)})

    click.echo(f"[+] Ingested {kind} on {host_ip}: {len(found)} privesc finding(s); "
               "host -> enumerated")
    for f in found:
        click.echo(f"    [{f.severity.upper()}] {f.cls} {f.title}")


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
@click.option("--target", required=True, help="IP/CIDR to scan (must be in scope).")
@click.option("--ports", default=None, help="Port spec (e.g. '1-1000' or '80,443'). "
              "DEFAULT: full-port scan (-p-, all 65535). Narrow only for a deliberate re-scan.")
@click.option("--hexstrike-url", default=None, help=f"HexStrike base URL (default {_HEXSTRIKE_DEFAULT}).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def enum(lab: str, target: str, ports: str | None, hexstrike_url: str | None,
         db_path: str | None) -> None:
    """Run nmap through HexStrike and ingest the result (delegated enumeration).

    Yhwach owns the world model; HexStrike owns tool execution. The raw XML is
    saved to recon/ for the report.

    Every new endpoint gets a FULL-PORT scan (-p-) by default — top-ports scans
    miss high-port scored surfaces (AI/LLM APIs, ELK, mgmt panels). Pass --ports
    only to deliberately narrow a re-scan.
    """
    from yhwach.hexstrike import DEFAULT_URL, HexStrikeClient, HexStrikeError, is_loopback
    from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml_text

    url = hexstrike_url or DEFAULT_URL
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)
    if not is_loopback(url):
        click.echo(f"[!] OPSEC: HexStrike URL {url} is not loopback — unauthenticated "
                   "RCE over a network. Continuing, but bind HexStrike to 127.0.0.1.", err=True)

    client = HexStrikeClient(url)
    try:
        client.health()
    except Exception as e:  # noqa: BLE001
        click.echo(f"[!] HexStrike not reachable at {url}: {e}", err=True)
        sys.exit(2)

    click.echo(f"[*] Running nmap on {target} via HexStrike …")
    try:
        xml = client.nmap_xml(target, ports=ports)
    except HexStrikeError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)

    recon = _artifact_dir(path, "recon")
    try:
        recon.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
        (recon / f"hexstrike_nmap_{safe}.xml").write_text(xml, encoding="utf-8")
    except OSError as e:  # best-effort; ingest is what matters
        click.echo(f"[i] Could not save recon XML ({e}); continuing with ingest.", err=True)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        hosts = parse_nmap_xml_text(xml)
        h, s = insert_hosts(conn, eng_id, hosts)
        yhdb.log_event(conn, eng_id, "enum", {"target": target, "hosts": h, "services": s,
                                              "via": "hexstrike"})
    click.echo(f"[+] HexStrike nmap: {h} hosts, {s} services ingested. "
               "Next: `yhwach probe` then `yhwach plan`.")


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
    if report.rules_skipped_consumed:
        click.echo("[i] Skipped (technique already consumed): "
                   + ", ".join(report.rules_skipped_consumed))
    if report.surfaces_filtered_denylist:
        click.echo(f"[i] Filtered {report.surfaces_filtered_denylist} surface(s) on "
                   "denylisted (dev-artifact) hosts")
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

        tasks = top_tasks(conn, eng_id, limit, host_ip=host_ip)

    if not tasks:
        click.echo("[!] No pending tasks. Run `yhwach probe` then `yhwach plan` first.")
        return

    click.echo(f"== Top {len(tasks)} tasks for '{lab}' (by EV) ==")
    for i, t in enumerate(tasks, 1):
        click.echo(
            f"{i}. [task #{t['id']}] EV={t['ev_score']:<6} [{t['autonomy']:<7}] "
            f"{t['host_ip']} {t['surface_kind']} -> {t['playbook_rule_id']} ({t['kind']})"
        )
        click.echo(f"     {t['rationale']}  (run: yhwach run --lab {lab} --task {t['id']} --go)")


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
    never auto-executed — Yhwach proposes, the operator exploits. Shares the
    execution core with the `yhwach_run` MCP tool (see engine.execute_task).
    """
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)

    lines, ok = execute_task(path, eng_id, task_id, go=go)
    for ln in lines:
        click.echo(ln)
    if not ok:
        sys.exit(2)


@main.command()
@click.option("--host", "host_ip", required=True, help="Host IP.")
@click.option("--to", "stage", required=True,
              type=click.Choice(yhdb.STAGES + ["blocked"]),
              help="New FSM stage.")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--force", is_flag=True, default=False, help="Allow moving the stage backwards.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def advance(host_ip: str, stage: str, lab: str, force: bool, db_path: str | None) -> None:
    """Advance a host's FSM stage (foothold/looted/pivoted/...). Monotonic by default."""
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        changed, msg = yhdb.set_host_stage(conn, eng_id, host_ip, stage, monotonic=not force)
        if changed:
            yhdb.log_event(conn, eng_id, "stage", {"host": host_ip, "stage": stage})
    if changed:
        click.echo(f"[+] {host_ip} -> {stage}")
        click.echo(f"[note] objective reached — write the {host_ip} note in the Obsidian vault "
                   "now (via the Obsidian MCP): full detail per persona/notebook.md.")
    else:
        click.echo(f"[!] {msg}", err=True)
        sys.exit(1)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", required=True, help="Host IP the flag was captured on.")
@click.option("--screenshot", "screenshot_path", required=True, type=click.Path(),
              help="Path to the proof screenshot (must exist).")
@click.option("--flag", "flag_path", default=None, type=click.Path(),
              help="Path to the flag/proof file (optional).")
@click.option("--flag-content", default=None, help="The flag text itself (optional).")
@click.option("--no-advance", is_flag=True, default=False,
              help="Record the proof but do not advance the host to 'looted'.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def proof(lab: str, host_ip: str, screenshot_path: str, flag_path: str | None,
          flag_content: str | None, no_advance: bool, db_path: str | None) -> None:
    """Bind a flag + screenshot to a host, then advance it to 'looted'.

    The screenshot is the evidence that gates `foothold -> looted`; Yhwach
    refuses if the file does not exist. If a --flag file is given, its content
    is stored. Capture the screenshot as you take the flag, then mirror it into
    the Obsidian vault.
    """
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)

    shot = Path(os.path.expanduser(screenshot_path))
    if not shot.is_file():
        click.echo(f"[!] Screenshot not found: {shot} — a proof needs a real screenshot.",
                   err=True)
        sys.exit(2)

    if flag_content is None and flag_path:
        fp = Path(os.path.expanduser(flag_path))
        if fp.is_file():
            flag_content = fp.read_text(encoding="utf-8", errors="replace").strip()

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
                            (eng_id, host_ip)).fetchone()
        if hrow is None:
            click.echo(f"[!] Host {host_ip} not found; ingest a scan first.", err=True)
            sys.exit(2)
        pid = yhdb.add_proof(conn, hrow["id"], flag_path or "-", str(shot),
                             flag_content=flag_content)
        yhdb.log_event(conn, eng_id, "proof",
                       {"host": host_ip, "screenshot": str(shot), "flag": flag_path or None})
        advanced = False
        if not no_advance:
            advanced, msg = yhdb.set_host_stage(conn, eng_id, host_ip, "looted")
            if advanced:
                yhdb.log_event(conn, eng_id, "stage", {"host": host_ip, "stage": "looted"})

    click.echo(f"[+] Proof #{pid} recorded for {host_ip} (screenshot: {shot.name}).")
    if not no_advance:
        click.echo(f"[+] {host_ip} -> looted" if advanced
                   else f"[i] stage unchanged ({msg}).")
    click.echo("[note] mirror the screenshot into the Obsidian vault and bind it to the host "
               "note + Attack Chain step it proves (via the Obsidian MCP).")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--via-host", "via_ip", required=True, help="Pivot host IP (runs the agent).")
@click.option("--subnet", required=True, help="CIDR now reachable through the pivot.")
@click.option("--lport", default=11601, show_default=True, type=int,
              help="Ligolo proxy listener port on Kali.")
@click.option("--no-advance", is_flag=True, default=False,
              help="Record the tunnel but don't advance the pivot host to 'pivoted'.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def pivot(lab: str, via_ip: str, subnet: str, lport: int, no_advance: bool,
          db_path: str | None) -> None:
    """Record a pivot (tunnel into a subnet via a host) and render the deploy commands.

    Uses the pre-staged obfuscated Ligolo agent (svcmon.exe) for a Windows pivot,
    a stock agent otherwise. Recording the tunnel unblocks the host's
    `looted -> pivoted` transition.
    """
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        hrow = conn.execute("SELECT id, os FROM host WHERE engagement_id = ? AND ip = ?",
                            (eng_id, via_ip)).fetchone()
        if hrow is None:
            click.echo(f"[!] Pivot host {via_ip} not found.", err=True)
            sys.exit(2)
        _, created = yhdb.add_tunnel(conn, eng_id, hrow["id"], subnet)
        yhdb.log_event(conn, eng_id, "tunnel", {"via": via_ip, "subnet": subnet})
        advanced = False
        if not no_advance:
            advanced, msg = yhdb.set_host_stage(conn, eng_id, via_ip, "pivoted")
            if advanced:
                yhdb.log_event(conn, eng_id, "stage", {"host": via_ip, "stage": "pivoted"})
        os_name = hrow["os"]

    from yhwach.engine import render_pivot

    click.echo(f"[+] Tunnel {'recorded' if created else 'already known'}: {subnet} via {via_ip}")
    if not no_advance:
        click.echo(f"[+] {via_ip} -> pivoted" if advanced else f"[i] stage unchanged ({msg}).")
    click.echo("== Deploy (propose — operator runs) ==")
    for line in render_pivot(via_ip, subnet, os_name, lport=lport):
        click.echo(line)
    click.echo("[note] record the pivot in the Obsidian vault (Network Map + Attack Chain).")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--user", "identifier", required=True, help="Username / key label / token id.")
@click.option("--secret", default=None, help="Password / hash / key material.")
@click.option("--kind", default="password",
              type=click.Choice(["password", "ntlm", "kerberos", "ssh_key", "api_key",
                                 "token", "dpapi"]), help="Credential kind.")
@click.option("--source", default="user_provided",
              help="Where it came from (prompt_injection/chrome/dump/spray/...).")
@click.option("--host", "host_ip", default=None, help="Host it was recovered from.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def cred(lab: str, identifier: str, secret: str | None, kind: str, source: str,
         host_ip: str | None, db_path: str | None) -> None:
    """Add a credential to the vault. Creds are never exhausted — always in play."""
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        host_id = None
        if host_ip:
            r = conn.execute("SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
                             (eng_id, host_ip)).fetchone()
            host_id = r["id"] if r else None
        _, created = yhdb.add_credential(conn, eng_id, identifier, secret, kind, source, host_id)
        yhdb.log_event(conn, eng_id, "credential",
                       {"id": identifier, "kind": kind, "source": source, "host": host_ip})
    click.echo(f"[+] Credential '{identifier}' ({kind}) {'added' if created else 'updated'}. "
               "Run `yhwach spray` to reuse it across the scope.")
    click.echo("[note] loot is an objective — add it to the Credentials note in the Obsidian "
               "vault (via the Obsidian MCP), with source and reuse ideas.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--proto", default=None,
              type=click.Choice(["smb", "winrm", "ssh", "ldap", "mssql", "rdp"]),
              help="Restrict to one protocol.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def spray(lab: str, proto: str | None, db_path: str | None) -> None:
    """Render credential-spray commands (vault creds x sprayable surfaces).

    Proposal-tier: active auth-testing, so Yhwach renders — the operator runs.
    """
    from yhwach.spray import build_spray_plan

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        cmds = build_spray_plan(conn, eng_id, proto_filter=proto)

    if not cmds:
        click.echo("[!] Nothing to spray (empty vault or no sprayable surfaces).")
        return
    click.echo(f"== Spray plan for '{lab}' ({len(cmds)} commands) [propose — operator runs] ==")
    for c in cmds:
        click.echo(f"  $ {c}")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def creds(lab: str, db_path: str | None) -> None:
    """List the credential vault."""
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        rows = yhdb.list_credentials(conn, eng_id)
    if not rows:
        click.echo("[!] Vault empty.")
        return
    click.echo(f"== Vault for '{lab}' ({len(rows)}) ==")
    for r in rows:
        # Print secrets in full — the vault IS the operator's authoritative
        # access ledger; hidden secrets can't be reused. Multiline blobs
        # (SSH keys) get a one-line note so the table stays scannable.
        sec = r["secret"] or "(none)"
        if "\n" in sec:
            head = sec.split("\n", 1)[0][:44]
            sec = f"{head} …(multiline)"
        src = r["source"] or ""
        # Look up the source-host IP if the row carries one. NB: r is a
        # sqlite3.Row — `in r` tests VALUES, so `.keys()` is required here.
        src_ip = r["source_host_ip"] if "source_host_ip" in r.keys() else None  # noqa: SIM118
        if src_ip:
            src = f"{src} @ {src_ip}"
        click.echo(f"  {r['identifier']:<20} {r['kind']:<10} {sec:<40} ({src})")


@main.command()
@click.argument("technique")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", default=None, help="Host where it landed (optional).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def consume(technique: str, lab: str, host_ip: str | None, db_path: str | None) -> None:
    """Mark a technique consumed — the planner will stop proposing it this engagement.

    TECHNIQUE is a rule id or a rule's `technique:` key. Use after a technique
    lands: OSAI labs don't reuse infra flaws, so re-proposing it wastes turns.
    """
    from yhwach.primitives import mark_technique_consumed

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        host_id = None
        if host_ip:
            r = conn.execute(
                "SELECT id FROM host WHERE engagement_id = ? AND ip = ?", (eng_id, host_ip)
            ).fetchone()
            host_id = r["id"] if r else None
        mark_technique_consumed(conn, eng_id, technique, host_id)
    click.echo(f"[+] Technique '{technique}' marked consumed for '{lab}'. "
               "Re-run `yhwach plan` to drop it from the queue.")


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
@click.option("--lab", required=True, help="Lab name.")
@click.option("--out", "out_path", default=None, type=click.Path(),
              help="Write the Markdown report here (default: stdout).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def report(lab: str, out_path: str | None, db_path: str | None) -> None:
    """Render a Markdown engagement report from the world model."""
    from yhwach.report import build_report

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        md = build_report(conn, eng_id)

    if out_path:
        Path(out_path).write_text(md, encoding="utf-8")
        click.echo(f"[+] wrote {out_path}")
    else:
        click.echo(md)


@main.command()
def mcp() -> None:
    """Run Yhwach as an MCP server (stdio) for Claude Code. Needs `pip install yhwach[mcp]`."""
    from yhwach.mcp_server import run
    run()


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
