"""Yhwach CLI.

The engagement driver: engage / ingest / enum / probe / brief, post-foothold
(advance / cred / creds), findings / report / gaps / path / recon / vulns,
and the MCP server (mcp). See `cli/README.md` for the full command reference.

Notes are not a CLI concern: the engagement notebook is a LOCAL Obsidian vault,
written with the file tools (no MCP) — see persona/notebook.md.

DB location resolution:
  1. --db flag on the subcommand
  2. YHWACH_DB env var
  3. <workspace>/state/yhwach.db (see yhwach.config; default ~/.local/share/yhwach)
"""
from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

import click

from yhwach import __version__
from yhwach import config as yhconfig
from yhwach import db as yhdb
from yhwach.coverage import enum_gaps, render_gaps
from yhwach.engine import artifact_dir as _artifact_dir
from yhwach.parsers.nmap import insert_hosts, parse_nmap
from yhwach.probes import PROBES_BY_PORT, new_session, run_probes, software_from_result

DEFAULT_DB_ENV = "YHWACH_DB"
_HEXSTRIKE_DEFAULT = "http://127.0.0.1:8888"


def _db_path(override: str | None = None) -> Path:
    raw = override or os.environ.get(DEFAULT_DB_ENV) or yhconfig.default_db()
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
    """Yhwach — AI-Driven Memory & Playbook.

    Authorized for engagements you have explicit written permission to test.
    See AUTHORIZATION.md.
    """
    _force_utf8_output()


@main.command()
@click.option("--lab", required=True, help="Lab name (unique per engagement).")
@click.option("--scope", required=True, help="Comma-separated IPs / CIDRs / hostnames / *.wildcards.")
@click.option("--kind", default=None,
              type=click.Choice(["lab", "ctf", "internal", "external", "web",
                                 "cloud", "redteam", "bounty", "retest"]),
              help="Engagement profile (default lab). Non-lab/ctf start record_only "
                   "(active tools disarmed until `yhwach arm`).")
@click.option("--client", default=None, help="Client / program name (optional).")
@click.option("--domain", default=None, help="AD domain (optional).")
@click.option("--dc", "dc_ip", default=None, help="DC IP (optional).")
@click.option("--points-target", "points_target", type=int, default=None,
              help="Optional: target/pass points for this engagement (drives the scoreboard pace view).")
@click.option("--points-max", "points_max", type=int, default=None,
              help="Optional: max achievable points for this engagement.")
@click.option("--time-budget-h", "time_budget_h", type=float, default=None,
              help="Optional: time budget in hours (drives the elapsed/remaining view).")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path (else $YHWACH_DB or the default).")
def engage(lab: str, scope: str, kind: str | None, client: str | None,
           domain: str | None, dc_ip: str | None,
           points_target: int | None, points_max: int | None,
           time_budget_h: float | None, db_path: str | None) -> None:
    """Initialize an engagement: create the DB if needed, upsert the engagement row.

    Scoring is optional and engagement-specific: pass --points-target/--points-max/
    --time-budget-h to enable the pace view; omit them for a plain running count.
    """
    from yhwach import scope as yhscope

    bad = yhscope.validate_tokens(scope)
    if bad:
        click.echo(f"[!] Invalid scope token(s): {', '.join(bad)} — use IPs/CIDRs/"
                   "hostnames/*.wildcards (e.g. 10.10.10.0/24,app.example.com,*.example.com).",
                   err=True)
        sys.exit(2)

    path = _db_path(db_path)
    if not path.exists():
        yhdb.init(path)
        click.echo(f"[+] Created DB at {path}")
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab=lab, scope=scope,
                                        domain=domain, dc_ip=dc_ip,
                                        points_target=points_target,
                                        points_max=points_max,
                                        time_budget_h=time_budget_h,
                                        kind=kind, client=client)
        yhscope.sync_from_string(conn, eng_id, scope, source="engage")
        mode = "armed" if yhdb.engagement_armed(conn, eng_id) else "record_only"
    click.echo(f"[+] Engagement '{lab}' ready (id={eng_id}; kind={kind or 'lab'}; {mode})")
    if mode == "record_only":
        click.echo("[i] record_only: active tools (scan/enum/probe/spray + autospray) "
                   "are disarmed. Run `yhwach arm --lab " + lab + "` to enable them.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def arm(lab: str, db_path: str | None) -> None:
    """Enable active traffic (scan/enum/probe/spray + autospray) for an engagement.

    Arming is deliberately a terminal-only act — the MCP model can never turn
    traffic on, only ask you to.
    """
    path = _db_path(db_path)
    with yhdb.transaction(path) as conn:
        eid = yhdb.engagement_id_for(conn, lab)
        if eid is None:
            click.echo(f"[!] unknown lab '{lab}'", err=True)
            sys.exit(2)
        yhdb.set_active_mode(conn, eid, "armed")
    click.echo(f"[+] '{lab}' is ARMED — active tools will send traffic. Stay in scope.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def disarm(lab: str, db_path: str | None) -> None:
    """Return an engagement to record_only (no active traffic)."""
    path = _db_path(db_path)
    with yhdb.transaction(path) as conn:
        eid = yhdb.engagement_id_for(conn, lab)
        if eid is None:
            click.echo(f"[!] unknown lab '{lab}'", err=True)
            sys.exit(2)
        yhdb.set_active_mode(conn, eid, "record_only")
    click.echo(f"[+] '{lab}' is record_only — active tools are disarmed.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.argument("view")
@click.option("--where", "wheres", multiple=True,
              help="Filter col=val (repeatable). Operators: col>=val, col<=val, "
                   "col!=val, 'col like=%x%', 'col in=a,b'.")
@click.option("-q", "search", default=None, help="Substring search across the view's text columns.")
@click.option("--field", "fields", multiple=True, help="Only these columns (repeatable).")
@click.option("--order", default=None, help="Order by a column (prefix '-' for desc).")
@click.option("--limit", default=25, show_default=True, type=int)
@click.option("--offset", default=0, show_default=True, type=int)
@click.option("--reveal", is_flag=True, default=False, help="Show masked secrets in full.")
@click.option("--fmt", type=click.Choice(["text", "json"]), default="text", show_default=True,
              help="Output format.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Shortcut for --fmt json.")
@click.option("--max-chars", "max_chars", default=None, type=int,
              help="Cap output size; drops trailing rows and prints the next call.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def query(lab: str, view: str, wheres: tuple, search: str | None, fields: tuple,
          order: str | None, limit: int, offset: int, reveal: bool,
          fmt: str, as_json: bool, max_chars: int | None, db_path: str | None) -> None:
    """Query a named read view of the world model (read-only)."""
    from yhwach import views as yhviews

    if as_json:
        fmt = "json"

    where: dict = {}
    for tok in wheres:
        low = tok.lower()
        if " in=" in low or low.rstrip().endswith(" in"):
            col, _, val = tok.partition("=")
            where[col.strip()] = [v.strip() for v in val.split(",") if v.strip()]
            continue
        if " like=" in low:
            col, _, val = tok.partition("=")
            where[col.strip()] = val
            continue
        for o in (">=", "<=", "!=", ">", "<"):
            if o in tok:
                col, _, val = tok.partition(o)
                where[f"{col.strip()}{o}"] = val.strip()
                break
        else:  # plain equality
            col, _, val = tok.partition("=")
            where[col.strip()] = val.strip()
    path = _db_path(db_path)
    try:
        with yhdb.transaction(path) as conn:
            eid = yhdb.engagement_id_for(conn, lab)
            if eid is None:
                click.echo(f"[!] unknown lab '{lab}'", err=True)
                sys.exit(2)
            cols, rows, total = yhviews.query(
                conn, eid, view, where=where or None, q=search,
                fields=list(fields) or None, order=order, limit=limit,
                offset=offset, reveal=reveal)
            click.echo(yhviews.format_result(cols, rows, total, view, limit,
                                             offset, fmt=fmt, max_chars=max_chars))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--lab", required=True, help="Lab name.")
@click.option("--kind", default="auto",
              help="auto (sniff) | a parser kind | x:<action_id> for an extractor.")
@click.option("--host", "host_ip", default=None, help="Host IP the output is about.")
@click.option("--url", default=None, help="Base URL (for web output).")
@click.option("--title", default=None, help="Title for an unparsed/raw record.")
@click.option("--dry-run", is_flag=True, default=False, help="Classify without writing.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def interpret(file: str, lab: str, kind: str, host_ip: str | None, url: str | None,
              title: str | None, dry_run: bool, db_path: str | None) -> None:
    """Interpret a saved tool-output file into typed rows (auto-sniffed)."""
    from yhwach.mcp_tools import tool_interpret

    text = Path(file).read_text(encoding="utf-8", errors="replace")
    try:
        click.echo(tool_interpret(_db_path(db_path), lab, text, kind=kind,
                                  host=host_ip, url=url, title=title, dry_run=dry_run))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.argument("action_id")
@click.option("--host", "host_ip", default=None, help="Target host IP.")
@click.option("--port", default=None, type=int, help="Target port.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def action(lab: str, action_id: str, host_ip: str | None, port: int | None,
           db_path: str | None) -> None:
    """Render a recall action id as a runnable command for a target."""
    from yhwach.mcp_tools import tool_action

    try:
        click.echo(tool_action(_db_path(db_path), lab, action_id, host=host_ip, port=port))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.argument("tool", required=False)
def schema(tool: str | None) -> None:
    """Discover the tool surface: args, examples, query views and operators.

    No argument lists every tool; TOOL='yhwach_<name>' shows one tool's args and
    an example. Pure discovery — reads nothing, needs no lab.
    """
    from yhwach.mcp_tools import tool_schema

    click.echo(tool_schema(None, tool=tool))


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--body", default=None, help="Notice text; omit to list the log.")
@click.option("--kind", default="status_update", help="Notice kind.")
@click.option("--finding", default=None, type=int, help="Link to a finding id.")
@click.option("--channel", default=None, help="How it was communicated (call|email|...).")
@click.option("--actor", default=None, help="Who recorded it.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def notice(lab: str, body: str | None, kind: str, finding: int | None,
           channel: str | None, actor: str | None, db_path: str | None) -> None:
    """Record or list client communications (G4a)."""
    from yhwach.mcp_tools import tool_notice

    click.echo(tool_notice(_db_path(db_path), lab, body=body, kind=kind,
                           finding=finding, channel=channel, actor=actor))


@main.command(name="log")
@click.option("--lab", required=True, help="Lab name.")
@click.argument("action")
@click.option("--command", default=None, help="The command you ran (secrets redacted).")
@click.option("--host", default=None, help="Target host IP.")
@click.option("--target", default=None, help="Target (host:port / url).")
@click.option("--result", default=None, help="success|fail|blocked|cached|error.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def log_cmd(lab: str, action: str, command: str | None, host: str | None,
            target: str | None, result: str | None, db_path: str | None) -> None:
    """Record a hand-run command into the activity ledger (I05)."""
    from yhwach.mcp_tools import tool_log

    click.echo(tool_log(_db_path(db_path), lab, action, command=command,
                        host=host, target=target, result=result))


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--location", default=None, help="Where it lives; omit to list.")
@click.option("--kind", default="file", help="tunnel_agent|implant|webshell|file|account|service.")
@click.option("--host", default=None, help="Host IP it is on.")
@click.option("--note", default=None, help="Optional note.")
@click.option("--remove", default=None, type=int, help="Artifact id to mark removed.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def artifact(lab: str, location: str | None, kind: str, host: str | None,
             note: str | None, remove: int | None, db_path: str | None) -> None:
    """Record, remove or list cleanup artefacts (I39)."""
    from yhwach.mcp_tools import tool_artifact

    click.echo(tool_artifact(_db_path(db_path), lab, location=location, kind=kind,
                             host=host, note=note, remove=remove))


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def reuse(lab: str, db_path: str | None) -> None:
    """Derive credential-reuse attack-graph edges (G2e)."""
    from yhwach.mcp_tools import tool_reuse

    click.echo(tool_reuse(_db_path(db_path), lab))


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--program", default=None, help="Bounty program name.")
@click.option("--finding", default=None, type=int, help="Finding id.")
@click.option("--endpoint", default=None, help="Affected endpoint/path.")
@click.option("--param", default=None, help="Affected parameter.")
@click.option("--cls", default=None, help="Vuln class (for program-noise advice).")
@click.option("--status", default=None, help="Operator-set status label.")
@click.option("--note", default=None, help="Optional note.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def submission(lab: str, program: str | None, finding: int | None, endpoint: str | None,
               param: str | None, cls: str | None, status: str | None,
               note: str | None, db_path: str | None) -> None:
    """Record or list bounty submissions with duplicate-risk advice (I20)."""
    from yhwach.mcp_tools import tool_submission

    click.echo(tool_submission(_db_path(db_path), lab, program=program, finding=finding,
                               endpoint=endpoint, param=param, cls=cls, status=status,
                               note=note))


@main.command(name="finding-set")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--id", "finding_id", required=True, type=int, help="Finding id.")
@click.option("--status", default=None,
              type=click.Choice(["open", "confirmed", "exploited", "false_positive",
                                 "duplicate", "remediated", "dead"]))
@click.option("--severity", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--evidence", default=None, help="Replace the one-line evidence.")
@click.option("--why", "reason", default="", help="One-line reason for the change.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def finding_set(lab: str, finding_id: int, status: str | None, severity: str | None,
                evidence: str | None, reason: str, db_path: str | None) -> None:
    """Correct a finding (status/severity/evidence); closes rather than deletes."""
    from yhwach.mcp_tools import tool_finding_set

    try:
        click.echo(tool_finding_set(_db_path(db_path), lab, finding_id, status=status,
                                    severity=severity, evidence=evidence, reason=reason))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--kind", required=True,
              type=click.Choice(["screenshot", "request", "response", "output", "file", "log"]))
@click.option("--path", "ev_path", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Saved artefact file (hashed; refused if missing/empty).")
@click.option("--finding", "finding_id", default=None, type=int, help="Bind to this finding id.")
@click.option("--objective", default=None, help="Bind to this PoC objective slug.")
@click.option("--caption", default=None, help="Short caption.")
@click.option("--secret", "contains_secret", is_flag=True, default=False,
              help="Mark that the artefact contains a secret.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def evidence(lab: str, kind: str, ev_path: str | None, finding_id: int | None,
             objective: str | None, caption: str | None, contains_secret: bool,
             db_path: str | None) -> None:
    """Bind a proof artefact (screenshot/request/response/output) to a finding."""
    from yhwach.mcp_tools import tool_add_evidence

    try:
        click.echo(tool_add_evidence(_db_path(db_path), lab, kind, path=ev_path,
                                     finding=finding_id, objective=objective,
                                     caption=caption, contains_secret=contains_secret))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--rule", default=None, help="Playbook technique id that was tried.")
@click.option("--technique", default=None, help="Free-text label for an off-catalog move.")
@click.option("--result", required=True,
              type=click.Choice(["success", "fail", "blocked", "partial"]))
@click.option("--host", "host_ip", default=None, help="Target host IP.")
@click.option("--why", "reason", default="", help="One-line reason / outcome.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def attempt(lab: str, rule: str | None, technique: str | None, result: str,
            host_ip: str | None, reason: str, db_path: str | None) -> None:
    """Record a tried move so recall stops re-proposing it (dead-ends ledger)."""
    from yhwach.mcp_tools import tool_attempt

    if not rule and not technique:
        click.echo("[!] pass --rule <id> or --technique <text>.", err=True)
        sys.exit(2)
    try:
        click.echo(tool_attempt(_db_path(db_path), lab, rule=rule or "", result=result,
                                reason=reason, host=host_ip, technique=technique))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.argument("action", type=click.Choice(["list", "add", "exclude", "remove", "check"]),
                default="list")
@click.argument("target", required=False, default=None)
@click.option("--note", default=None, help="Note on an add/exclude entry.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def scope(lab: str, action: str, target: str | None, note: str | None,
          db_path: str | None) -> None:
    """Manage the typed engagement scope (ip/cidr/hostname/*.wildcard; exclude wins)."""
    from yhwach.mcp_tools import tool_scope

    path = _db_path(db_path)
    try:
        click.echo(tool_scope(path, lab, action=action, target=target, note=note))
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(2)


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--lab", required=True, help="Lab name (must exist).")
@click.option("--kind",
              type=click.Choice(["nmap", "linpeas", "winpeas", "bloodhound", "certipy",
                                 "netexec", "web", "raw"]),
              default="nmap", help="Parser kind. 'raw' records bespoke tool output "
                                   "(curl/openssl/etc.) as a finding + saves the full output to loot.")
@click.option("--host", "host_ip", default=None,
              help="Host IP (required for linpeas/winpeas/bloodhound/certipy/netexec/web — "
                   "facts are host-scoped; for bloodhound/certipy use the DC or CA).")
@click.option("--title", "raw_title", default=None,
              help="Finding title for --kind raw (required for raw). Also used as the loot filename.")
@click.option("--severity", "raw_severity",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="info", help="Finding severity for --kind raw.")
@click.option("--url", "base_url", default=None,
              help="Base URL for --kind web (e.g. http://10.0.0.5:80) — the web_app the "
                   "discovered paths attach to.")
@click.option("--server", default=None, help="Server banner for --kind web (e.g. nginx/1.24.0).")
@click.option("--tech", default=None, help="Tech stack for --kind web (comma list).")
@click.option("--page-title", "page_title", default=None,
              help="Page title for --kind web (--title is taken by --kind raw).")
@click.option("--vhost", default=None, help="Virtual host for --kind web.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path.")
def ingest(file: str, lab: str, kind: str, host_ip: str | None, base_url: str | None,
           server: str | None, tech: str | None, page_title: str | None, vhost: str | None,
           raw_title: str | None, raw_severity: str, db_path: str | None) -> None:
    """Parse a tool output file and update the world model.

    nmap XML -> hosts + services + software (CPE). linpeas/winpeas -> privesc
    findings + software on --host (also advances it to 'enumerated'). bloodhound ->
    AD findings + the principal/privilege/edge graph on --host (the DC). netexec ->
    SMB shares, users, admin edges, password policy on --host. web -> web_app +
    paths (needs --url).
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

        if kind == "raw":
            # Bespoke tool output (curl/openssl/sqlite3/etc.) that has no dedicated
            # parser still becomes a typed finding, so operator-discovered intel
            # never skips the world model. The full output is saved to loot; the
            # finding carries only a one-line excerpt (schema rule: evidence is
            # never a raw dump).
            if not raw_title:
                click.echo("[!] --title is required for --kind raw.", err=True)
                sys.exit(2)
            content = Path(file).read_text(encoding="utf-8", errors="replace")
            host_id = None
            if host_ip:
                hrow = conn.execute(
                    "SELECT id FROM host WHERE engagement_id = ? AND ip = ?", (eng_id, host_ip)
                ).fetchone()
                host_id = hrow["id"] if hrow else None
            loot_dir = yhconfig.loot_dir()
            loot_dir.mkdir(parents=True, exist_ok=True)
            slug = "".join(c if c.isalnum() else "_" for c in raw_title)[:48]
            loot_path = loot_dir / f"raw_{slug}.txt"
            loot_path.write_text(content, encoding="utf-8")
            excerpt = " ".join(content.split())[:180]
            fid, _ = yhdb.add_finding(
                conn, host_id, None, "INFO", raw_title, raw_severity,
                f"{excerpt}  [full: {loot_path}]", engagement_id=eng_id,
            )
            yhdb.log_event(conn, eng_id, "ingest",
                           {"kind": "raw", "host": host_ip, "finding": fid, "loot": str(loot_path)})
            click.echo(f"[+] Recorded raw finding #{fid} ({raw_severity}); full output -> {loot_path}")
            return

        if kind == "nmap":
            from yhwach.parsers.nmap import parse_scan_meta

            raw = Path(file).read_text(encoding="utf-8", errors="replace")
            hosts = parse_nmap(raw)
            meta = parse_scan_meta(raw)
            h, s = insert_hosts(conn, eng_id, hosts, meta)
            # Log it: the CLI path used to be invisible to the timeline (and so
            # to `recall`/`report`), unlike the MCP one.
            yhdb.log_event(conn, eng_id, "ingest",
                           {"kind": "nmap", "hosts": h, "services": s})
            click.echo(f"[+] Ingested nmap: {h} hosts, {s} services")
            for cov in meta.coverage:
                click.echo(f"    coverage: {cov.proto} {cov.ports} "
                           f"({cov.port_count} ports)"
                           + ("  full-range" if cov.full_range else "")
                           + ("  +versions" if meta.version_scan else ""))
            gaps = enum_gaps(conn, eng_id)
            if gaps:
                click.echo(f"[!] {len(gaps)} host(s) under-enumerated — `yhwach gaps --lab {lab}`")
            return

        # Host-scoped ingestion (privesc, AD facts, SMB facts, web paths).
        if not host_ip:
            click.echo(f"[!] --host is required for {kind}.", err=True)
            sys.exit(2)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
                            (eng_id, host_ip)).fetchone()
        if hrow is None:
            click.echo(f"[!] Host {host_ip} not found; ingest an nmap scan first.", err=True)
            sys.exit(2)

        text = Path(file).read_text(encoding="utf-8", errors="replace")

        # Structured (non-finding-only) ingestion — NetExec SMB facts, web paths.
        if kind == "netexec":
            from yhwach.ingest import ingest_netexec
            summ = ingest_netexec(conn, eng_id, hrow["id"], text)
            yhdb.log_event(conn, eng_id, "ingest", {"kind": kind, "host": host_ip, **summ})
            click.echo(f"[+] Ingested netexec on {host_ip}: {summ['shares']} share(s), "
                       f"{summ['principals']} user(s), {summ['admin']} admin, "
                       f"{summ['findings']} finding(s)")
            return
        if kind == "web":
            if not base_url:
                click.echo("[!] --url is required for --kind web.", err=True)
                sys.exit(2)
            from yhwach.ingest import ingest_web
            summ = ingest_web(conn, hrow["id"], base_url, text, server=server,
                              tech=tech, title=page_title, vhost=vhost)
            yhdb.log_event(conn, eng_id, "ingest", {"kind": kind, "host": host_ip, **summ})
            click.echo(f"[+] Ingested web on {base_url}: {summ['paths']} path(s), "
                       f"{summ['interesting']} interesting, {summ['with_params']} with "
                       f"params, {summ['auth_gated']} auth-gated")
            return

        if kind == "bloodhound":
            from yhwach.ingest import ingest_bloodhound_graph
            from yhwach.parsers.bloodhound import parse_bloodhound
            found = parse_bloodhound(text)
            graph = ingest_bloodhound_graph(conn, eng_id, text)
            advanced_note = (f"; graph: {graph['principals']} principals, "
                             f"{graph['privileges']} privs, {graph['edges']} edges")
        elif kind == "certipy":
            from yhwach.parsers.adcs import parse_certipy
            found = parse_certipy(text)
            advanced_note = ""
        else:
            from yhwach.ingest import ingest_peas_software
            from yhwach.parsers.peas import parse_peas
            found = parse_peas(text, kind)
            sw = ingest_peas_software(conn, hrow["id"], text, kind)
            yhdb.set_host_stage(conn, eng_id, host_ip, "enumerated",
                                note=f"ingest {kind}")
            advanced_note = f"; {sw} software row(s); host -> enumerated"
        for f in found:
            yhdb.add_finding(conn, hrow["id"], None, f.cls, f.title, f.severity, f.evidence,
                             tag=f.tag)
        yhdb.log_event(conn, eng_id, "ingest", {"kind": kind, "host": host_ip, "findings": len(found)})

    click.echo(f"[+] Ingested {kind} on {host_ip}: {len(found)} finding(s){advanced_note}")
    for f in found:
        tag = f" [tag:{f.tag}]" if f.tag else ""
        click.echo(f"    [{f.severity.upper()}] {f.cls} {f.title}{tag}")


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
        vault_total = conn.execute(
            "SELECT COUNT(*) AS n FROM credential WHERE engagement_id = ?", (eng_id,),
        ).fetchone()["n"]

    click.echo(f"== Engagement '{lab}' (id={eng_id}) ==")
    click.echo("Hosts by stage:")
    if not stage_counts:
        click.echo("  (none)")
    for row in stage_counts:
        click.echo(f"  {row['stage']:<15} {row['n']}")
    click.echo(f"Services: {service_total}   Vault: {vault_total}")
    click.echo("(read `yhwach brief` to reason over the full map)")


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
    from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml_text, parse_scan_meta

    url = hexstrike_url or DEFAULT_URL
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)

    # Fail fast — unknown lab or out-of-scope target — before any HexStrike traffic.
    from yhwach.scope import in_scope, is_ip_or_cidr

    with yhdb.transaction(path) as conn:
        srow = conn.execute("SELECT scope FROM engagement WHERE lab = ?", (lab,)).fetchone()
    if srow is None:
        click.echo(f"[!] Unknown lab '{lab}'.", err=True)
        sys.exit(2)
    if is_ip_or_cidr(target):
        if not in_scope(target, srow["scope"] or ""):
            click.echo(f"[!] Target {target} is not in scope ({srow['scope']}). Refusing.",
                       err=True)
            sys.exit(2)
    else:
        click.echo(f"[i] Target {target} is not an IP/CIDR — cannot verify scope; continuing.",
                   err=True)

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
        h, s = insert_hosts(conn, eng_id, hosts, parse_scan_meta(xml))
        yhdb.log_event(conn, eng_id, "enum", {"target": target, "hosts": h, "services": s,
                                              "via": "hexstrike"})
    click.echo(f"[+] HexStrike nmap: {h} hosts, {s} services ingested. "
               "Next: `yhwach probe` then `yhwach plan`.")


@main.command()
@click.option("--host", "host_ip", required=True, help="Host IP.")
@click.option("--to", "stage", required=True,
              type=click.Choice(yhdb.STAGES + ["blocked"]),
              help="New FSM stage.")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--force", is_flag=True, default=False, help="Allow moving the stage backwards.")
@click.option("--why", "note", default=None,
              help="What moved it (recorded on the transition, shown in the host dossier).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def advance(host_ip: str, stage: str, lab: str, force: bool, note: str | None,
            db_path: str | None) -> None:
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
        changed, msg = yhdb.set_host_stage(conn, eng_id, host_ip, stage,
                                           monotonic=not force, note=note)
        if changed:
            yhdb.log_event(conn, eng_id, "stage",
                           {"host": host_ip, "stage": stage, "why": note})
        # Advisory under-enumeration check. Calling a half-scanned host
        # under-enumeration is the top failure mode in engagements; the engine warns rather than
        # refuses, because scans legitimately arrive out of band.
        warn_gaps = enum_gaps(conn, eng_id, host_ip=host_ip) if (
            changed and stage == "enumerated") else []
    if changed:
        click.echo(f"[+] {host_ip} -> {stage}")
        if warn_gaps:
            click.echo(f"[!] {host_ip} is NOT fully enumerated: {warn_gaps[0].summary}", err=True)
            for g in warn_gaps[0].gaps:
                click.echo(f"      $ {g.fix}", err=True)
        click.echo(f"[note] objective reached — write hosts/{host_ip}.md in the local vault "
                   "now (file tools, no MCP): full detail per persona/notebook.md.")
    else:
        click.echo(f"[!] {msg}", err=True)
        sys.exit(1)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--via-host", "via_ip", required=True, help="Pivot host IP (runs the agent).")
@click.option("--subnet", required=True, help="CIDR now reachable through the pivot.")
@click.option("--lport", default=11601, show_default=True, type=int,
              help="Listener port on Kali (ligolo default 11601 / chisel default 9055).")
@click.option("--kind", "kind", default=None, type=click.Choice(["ligolo", "chisel"]),
              help="Pivot kind. Auto-picked from host OS (Windows->ligolo, Linux->chisel).")
@click.option("--os-hint", "os_hint", default=None,
              help="Override the DB's recorded OS (used when it is missing/wrong).")
@click.option("--no-advance", is_flag=True, default=False,
              help="Record the tunnel but don't advance the pivot host to 'pivoted'.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def pivot(lab: str, via_ip: str, subnet: str, lport: int, kind: str | None,
          os_hint: str | None, no_advance: bool, db_path: str | None) -> None:
    """Record a pivot (tunnel into a subnet via a host) and render the deploy commands.

    Uses CANONICAL absolute arsenal paths (yhwach.arsenal):

      - Windows targets  -> the arsenal `svcmon.exe` (obfuscated ligolo agent)
      - Linux targets    -> `/usr/local/bin/chisel` (reverse-SOCKS, no root needed)
                            or the arsenal `ligolo-agent-linux` with `--kind ligolo`.

    `--kind` overrides the auto-pick (chisel on Linux, ligolo on Windows).
    Recording the tunnel unblocks the host's `looted -> pivoted` transition.
    """
    from yhwach import arsenal
    from yhwach.db import TUNNEL_KINDS
    from yhwach.engine import render_pivot

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
        os_name = os_hint or hrow["os"]
        resolved_kind = kind or (
            "ligolo" if (os_name or "").lower().startswith("win") else "chisel"
        )
        if resolved_kind not in TUNNEL_KINDS:
            click.echo(f"[!] Unknown --kind '{resolved_kind}'; expected {TUNNEL_KINDS}.", err=True)
            sys.exit(2)
        agent_key = (
            "CHISEL" if resolved_kind == "chisel"
            else "SVCMON_WIN" if (os_name or "").lower().startswith("win")
            else "LIGOLO_AGENT_LINUX"
        )
        _, created = yhdb.add_tunnel(
            conn, eng_id, hrow["id"], subnet,
            kind=resolved_kind, agent_path=agent_key,
        )
        yhdb.log_event(
            conn, eng_id, "tunnel",
            {"via": via_ip, "subnet": subnet, "kind": resolved_kind, "agent": agent_key},
        )
        advanced = False
        msg = ""
        if not no_advance:
            advanced, msg = yhdb.set_host_stage(
                conn, eng_id, via_ip, "pivoted", note=f"tunnel to {subnet}")
            if advanced:
                yhdb.log_event(conn, eng_id, "stage", {"host": via_ip, "stage": "pivoted"})

    click.echo(
        f"[+] Tunnel {'recorded' if created else 'already known'}: "
        f"{subnet} via {via_ip} [kind={resolved_kind}, agent={agent_key}]"
    )
    if not no_advance:
        click.echo(f"[+] {via_ip} -> pivoted" if advanced else f"[i] stage unchanged ({msg}).")
    click.echo("== Deploy (propose — operator runs) ==")
    for line in render_pivot(via_ip, subnet, os_name, lport=lport, pivot_kind=resolved_kind):
        click.echo(line)
    click.echo(f"[canonical arsenal binary] {agent_key} = {arsenal.get(agent_key).path}")
    click.echo("[note] record the pivot in the Obsidian vault (Network Map + Attack Chain).")


@main.command()
@click.option("--lhost", required=False, default=None,
              help="Listener host IP (skip if using --iface to auto-detect from interface).")
@click.option("--lport", required=True, type=int, help="Listener port.")
@click.option("--iface", default="tun0", show_default=True,
              help="Local interface to derive LHOST from (Windows gen.sh only).")
@click.option("--os", "os_choice", type=click.Choice(["win", "linux"]), required=True,
              help="Target OS — picks the canonical generator (gen.sh vs gen_linux_shell.sh).")
@click.option("--outdir", default=None, type=click.Path(),
              help="Output dir for generated payloads. Default: <workspace>/loot/revshells/ (see yhwach.config).")
@click.option("--max-retries", default=5, show_default=True, type=int,
              help="Windows gen.sh: reconnect retry count.")
@click.option("--jitter-ms", default=3000, show_default=True, type=int,
              help="Windows gen.sh: pre-connect jitter (max ms).")
def revshell(lhost: str | None, lport: int, iface: str, os_choice: str,
             outdir: str | None, max_retries: int, jitter_ms: int) -> None:
    """Render the canonical revshell generator invocation for a target OS.

    Uses the CANONICAL arsenal generators (yhwach.arsenal):

      - Windows (--os win)   -> the arsenal `gen_cs_shell.sh`
                                (v2 C#: 4-byte XOR, jitter, reconnect)
      - Linux   (--os linux) -> the arsenal `gen_linux_shell.sh`
                                (7 payloads: bash/dev/tcp, python PTY, socat, ...)

    Renders the exact command to run; the operator executes it. Output lands
    under `<workspace>/loot/revshells/` by default.
    """
    from yhwach import pivot_renderers as pr

    resolved_lhost = lhost or "<auto from iface>"
    if os_choice == "win":
        lines = pr.render_gen_sh(
            kali_ip=resolved_lhost, lport=lport, outdir=outdir,
            max_retries=max_retries, jitter_ms=jitter_ms, iface=iface,
        )
    else:
        lines = pr.render_gen_linux_shell(
            kali_ip=resolved_lhost, lport=lport, outdir=outdir, iface=iface,
        )
    for line in lines:
        click.echo(line)
    click.echo("[note] a new port per host — record it, don't reuse across hosts.")


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
@click.option("--validated-on", "validated_on", default=None,
              help="Prove it against a host you authenticated to: IP | IP:PORT | IP:PORT/PROTO "
                   "(e.g. 10.0.0.72:5985/winrm).")
@click.option("--admin", is_flag=True, default=False,
              help="The validated access is local/domain admin.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def cred(lab: str, identifier: str, secret: str | None, kind: str, source: str,
         host_ip: str | None, validated_on: str | None, admin: bool,
         db_path: str | None) -> None:
    """Add a credential to the vault. Creds are never exhausted — always in play."""
    from yhwach.mcp_tools import _parse_validated_on

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
        cred_id, created = yhdb.add_credential(
            conn, eng_id, identifier, secret, kind, source, host_id)
        if validated_on:
            vip, vport, vproto = _parse_validated_on(validated_on)
            vr = conn.execute("SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
                              (eng_id, vip)).fetchone()
            if vr is None:
                click.echo(f"[!] --validated-on host {vip} not in lab — access not recorded.",
                           err=True)
            else:
                yhdb.mark_credential_validated(
                    conn, eng_id, cred_id, int(vr["id"]), port=vport, proto=vproto,
                    service_kind=vproto, result="admin" if admin else "success", source=source)
                click.echo(f"[+] Proven on {vip}" + (f":{vport}" if vport else "")
                           + (f"/{vproto}" if vproto else "") + (" (admin)" if admin else "") + ".")
        yhdb.log_event(conn, eng_id, "credential",
                       {"id": identifier, "kind": kind, "source": source, "host": host_ip,
                        "validated_on": validated_on})
    click.echo(f"[+] Credential '{identifier}' ({kind}) {'added' if created else 'updated'}. "
               "Run `yhwach spray` to reuse it across the scope.")
    click.echo("[note] loot is an objective — add it to the Credentials note in the Obsidian "
               "vault (via the Obsidian MCP), with source and reuse ideas.")


@main.command("host-set")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", required=True, help="Host IP to label.")
@click.option("--hostname", default=None, help="Hostname (e.g. DC01).")
@click.option("--os", "os_", default=None, help="OS (windows/linux/...).")
@click.option("--role", default=None,
              help="What it mainly hosts (Domain Controller | Jenkins CI | File server | ...).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def host_set(lab: str, host_ip: str, hostname: str | None, os_: str | None,
             role: str | None, db_path: str | None) -> None:
    """Name/classify a host (hostname, os, role) for the board and map labels."""
    path = _db_path(db_path)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        if not yhdb.set_host_meta(conn, eng_id, host_ip, hostname=hostname, os=os_, role=role):
            click.echo(f"[!] Host {host_ip} not in lab '{lab}'.", err=True)
            sys.exit(2)
    click.echo(f"[+] {host_ip} labelled.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", required=True, help="Host IP to tag.")
@click.option("--tag", required=True, help="Free-form label (dc, ai-target, dual-homed, ...).")
@click.option("--note", default=None, help="Optional note on the tag.")
@click.option("--remove", is_flag=True, default=False, help="Remove the tag instead of adding.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def tag(lab: str, host_ip: str, tag: str, note: str | None, remove: bool,
        db_path: str | None) -> None:
    """Add or remove a free-form host tag (orthogonal to the FSM stage)."""
    path = _db_path(db_path)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        if remove:
            ok = yhdb.remove_host_tag(conn, eng_id, host_ip, tag)
            click.echo(f"[+] {'removed' if ok else 'no such tag on'} {host_ip}: {tag.lower()}")
        else:
            ok, msg = yhdb.add_host_tag(conn, eng_id, host_ip, tag, note=note)
            if not ok:
                click.echo(f"[!] {msg}", err=True)
                sys.exit(2)
            click.echo(f"[+] tagged {host_ip}: {tag.strip().lower()}")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", required=True, help="Host that owns the interface.")
@click.option("--ip", required=True, help="The interface IP.")
@click.option("--segment", default=None, help="Subnet/segment label (e.g. 10.0.0.0/24).")
@click.option("--mac", default=None, help="MAC address.")
@click.option("--primary", is_flag=True, default=False, help="Mark as the primary interface.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def interface(lab: str, host_ip: str, ip: str, segment: str | None, mac: str | None,
              primary: bool, db_path: str | None) -> None:
    """Record an extra interface/IP on a host — marks it dual-homed (the pivot-tree basis)."""
    path = _db_path(db_path)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        r = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                         (eng_id, host_ip)).fetchone()
        if r is None:
            click.echo(f"[!] Host {host_ip} not in lab '{lab}'.", err=True)
            sys.exit(2)
        yhdb.add_host_interface(conn, int(r["id"]), ip, mac=mac, segment=segment,
                                is_primary=primary, source="operator")
    click.echo(f"[+] Interface {ip} ({segment or 'no segment'}) recorded for {host_ip}.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--title", required=True, help="Short finding title.")
@click.option("--severity", default="info",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Finding severity.")
@click.option("--evidence", default="", help="One-line evidence (never a raw dump).")
@click.option("--class", "cls", default="INFO",
              help="Class label: LLM01.. | CWE-.. | CVE-.. | INFO.")
@click.option("--host", "host_ip", default=None, help="Host IP it belongs to (omit for engagement-wide).")
@click.option("--tag", default=None, help="Chaining key a rule's findings_include matches (unlocks a follow-on).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def finding(lab: str, title: str, severity: str, evidence: str, cls: str,
            host_ip: str | None, tag: str | None, db_path: str | None) -> None:
    """Record an operator-confirmed finding/lead (intel with no auto-extractor)."""
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
            if r is None:
                click.echo(f"[!] Host {host_ip} not in lab '{lab}'.", err=True)
                sys.exit(2)
            host_id = r["id"]
        fid, created = yhdb.add_finding(conn, host_id, None, cls, title, severity,
                                        evidence, tag=tag, engagement_id=eng_id)
        yhdb.log_event(conn, eng_id, "finding",
                       {"id": fid, "title": title, "severity": severity, "host": host_ip, "tag": tag})
    click.echo(f"[+] Finding #{fid} {'recorded' if created else 'updated'}: "
               f"[{severity}] {title}" + (f" [tag:{tag}]" if tag else ""))


@main.command(name="poc-step")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--objective", required=True, help="PoC objective this step belongs to (e.g. n8n-intake-rce).")
@click.option("--title", required=True, help="Short step title.")
@click.option("--command", default="", help="Verbatim command run (real values inline, no aliases).")
@click.option("--output", default="", help="Relevant console output / key excerpt.")
@click.option("--script", "script_file", default=None, type=click.Path(exists=True),
              help="Path to a script/payload used this step — saved verbatim into the engagement.")
@click.option("--cve", default=None, help="CVE / technique id.")
@click.option("--source", default=None, help="Exploit source URL / searchsploit id / arsenal path.")
@click.option("--host", default=None, help="Target host IP for this step.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def poc_step(lab: str, objective: str, title: str, command: str, output: str,
             script_file: str | None, cve: str | None, source: str | None,
             host: str | None, db_path: str | None) -> None:
    """Append one reproducible step (command+output+script+CVE) to a PoC chain."""
    from yhwach import poc as pocmod
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        script_path = None
        if script_file:
            content = Path(script_file).read_text()
            script_path = str(pocmod.save_script(path, objective, Path(script_file).name, content))
        seq = pocmod.add_step(conn, eng_id, objective, title=title, command=command,
                              output=output, script_path=script_path, cve=cve,
                              source=source, host=host)
    click.echo(f"[+] PoC '{pocmod.slug(objective)}' step #{seq} recorded: {title}"
               + (f"  [script: {script_path}]" if script_path else ""))


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--objective", default=None, help="Objective to render; omit to list all objectives.")
@click.option("--out", "out_file", default=None, type=click.Path(), help="Also write the chain here.")
@click.option("--scaffold", is_flag=True, default=False,
              help="Auto-seed a chain stub for every successful attempt with no PoC yet, "
                   "then list objectives.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def poc(lab: str, objective: str | None, out_file: str | None, scaffold: bool,
        db_path: str | None) -> None:
    """Render a reproducible PoC chain (chains/<objective>.md), or list objectives."""
    from yhwach import poc as pocmod
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        if scaffold:
            seeded = pocmod.scaffold_from_attempts(conn, eng_id)
            click.echo(f"[+] Scaffolded {len(seeded)} chain stub(s) from successful attempts"
                       + (": " + ", ".join(seeded) if seeded else " (none needed)."))
        if objective is None:
            objs = pocmod.list_objectives(conn, eng_id)
            if not objs:
                click.echo("[!] No PoC steps recorded yet. Use `yhwach poc-step`.")
                return
            click.echo("== PoC objectives ==")
            for label, n in objs:
                click.echo(f"  {label}  ({n} step(s))  -> yhwach poc --lab {lab} --objective {label}")
            return
        md = pocmod.render_poc(conn, eng_id, objective, lab=lab, write=True, db_path=path)
    if out_file:
        Path(out_file).write_text(md)
    click.echo(md)


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
@click.option("--lab", required=True, help="Lab name.")
@click.option("--section", default=None,
              type=click.Choice(["reach", "hold", "surfaces", "unlocks", "unexplored",
                                 "objectives", "lessons"]),
              help="Only this section of the brief.")
@click.option("--limit", default=60, show_default=True, type=int,
              help="Cap per host/cred/surface list (keeps a big scope legible).")
@click.option("--stage", default=None, help="Filter REACH to one FSM stage (e.g. scanned).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def brief(lab: str, section: str | None, limit: int, stage: str | None,
          db_path: str | None) -> None:
    """The AI-legible engagement map: REACH / HOLD / SURFACES / UNLOCKS / UNEXPLORED /
    OBJECTIVES. Read this to reason over the memory; yhwach decides nothing."""
    from yhwach.brief import build_brief
    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        click.echo(build_brief(conn, eng_id, section=section, limit=limit, stage=stage))


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
            "WHERE f.engagement_id = ? AND f.status IN ('open','confirmed','exploited') "
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
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", default=None, help="Check one host IP.")
@click.option("--all", "show_all", is_flag=True, default=False,
              help="Include hosts whose enumeration is already complete.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def gaps(lab: str, host_ip: str | None, show_all: bool, as_json: bool,
         db_path: str | None) -> None:
    """Show under-enumerated hosts and the exact scan that closes each gap.

    Built from `scan_coverage` â€” what the ingested nmap runs actually covered,
    not what they found. A host is complete when it has a full-port TCP scan,
    service versions, and a UDP top-100 sweep.
    """
    import json as _json

    from yhwach.coverage import gaps_as_dicts

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        found = enum_gaps(conn, eng_id, host_ip=host_ip, include_complete=show_all)
    if as_json:
        click.echo(_json.dumps(gaps_as_dicts(found), indent=2))
        return
    click.echo(f"== Enumeration gaps for '{lab}' ({len(found)} host(s)) ==")
    for line in render_gaps(found):
        click.echo(line)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", default=None, help="Scope to one host IP.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def coverage(lab: str, host_ip: str | None, as_json: bool, db_path: str | None) -> None:
    """World-model honesty: how thoroughly the hosts you've reached are enumerated.

    Scores the started hosts (scanned+) that are fully enumerated, and lists each
    one's remaining gaps with the exact fix. `yhwach gaps` shows the same for the
    WHOLE estate (incl. never-scanned hosts); this scores what you've *started*.
    """
    import json as _json

    from yhwach.coverage import coverage_score, gaps_as_dicts, started_gaps

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        cs = coverage_score(conn, eng_id)
        gaps = started_gaps(conn, eng_id, host_ip=host_ip)
    if as_json:
        click.echo(_json.dumps({
            "honesty_pct": cs.pct,
            "complete": cs.complete,
            "considered": cs.considered,
            "pending_scan": cs.pending_scan,
            "service_enum_gaps": cs.service_enum_gaps,
            "gaps": gaps_as_dicts(gaps),
        }, indent=2))
        return
    honesty = "n/a (no hosts reached yet)" if cs.pct is None else f"{cs.pct}%"
    click.echo(
        f"== Coverage for '{lab}' — honesty {honesty} "
        f"({cs.complete}/{cs.considered} started hosts fully enumerated) =="
    )
    if cs.pending_scan:
        click.echo(f"   [{cs.pending_scan} pending scan · yhwach scan --pending]")
    for line in render_gaps(gaps, considered=cs.considered):
        click.echo(line)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--add", "add_label", default=None, help="Record an objective/flag with this label.")
@click.option("--capture", "capture_label", default=None, help="Mark an objective captured.")
@click.option("--host", "host_ip", default=None, help="Scope --add/--capture to a host IP.")
@click.option("--points", type=int, default=0, help="Points for --add.")
@click.option("--kind", default="flag", help="Objective kind (flag|data|access|domain_admin).")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def objective(lab: str, add_label: str | None, capture_label: str | None, host_ip: str | None,
              points: int, kind: str, as_json: bool, db_path: str | None) -> None:
    """The engagement scoreboard — record flags/objectives + points, and see pace to target.

    \b
    yhwach objective --lab X                                    # scoreboard
    yhwach objective --lab X --add proof.txt --host IP --points 25
    yhwach objective --lab X --capture proof.txt
    """
    import json as _json

    from yhwach import scoreboard as sb_

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        if add_label:
            hid = None
            if host_ip:
                hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                    (eng_id, host_ip)).fetchone()
                if hrow is None:
                    click.echo(f"[!] Host {host_ip} not found.", err=True)
                    sys.exit(2)
                hid = hrow["id"]
            yhdb.add_objective(conn, eng_id, add_label, host_id=hid, points=points, kind=kind)
            click.echo(f"[+] objective '{add_label}' recorded"
                       + (f" ({points}pts)" if points else ""))
        if capture_label:
            n, msg = yhdb.capture_objective(conn, eng_id, capture_label, host_ip=host_ip)
            click.echo(f"[+] captured {n} objective(s): {capture_label}" if n else f"[-] {msg}")
        if as_json:
            click.echo(_json.dumps(sb_.as_dict(conn, eng_id), indent=2))
            return
        click.echo(f"== Scoreboard for '{lab}' ==")
        for line in sb_.render(conn, eng_id):
            click.echo(line)


@main.command("next")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", default=None, help="Scope to one host IP.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def next_(lab: str, host_ip: str | None, as_json: bool, db_path: str | None) -> None:
    """The recall menu + what you're about to miss — the 'what do I do next' move.

    Surfaces every technique that applies to the world model right now (grouped by
    host, split read-only vs. gated), fused with under-enumeration gaps, untried
    vault creds, and uncaptured objectives. Pure reads — yhwach recalls, you decide.
    """
    import json as _json

    from yhwach import nextmoves as nm_

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        nm = nm_.next_moves(conn, eng_id, host_ip=host_ip)
    if as_json:
        click.echo(_json.dumps(nm_.next_as_dict(nm), indent=2))
        return
    scope = f" host {host_ip}" if host_ip else ""
    click.echo(
        f"== Next moves for '{lab}'{scope} "
        f"({len(nm.auto)} read-only, {len(nm.gated)} gated) =="
    )
    if nm.pending_scan:
        click.echo(f"   [{nm.pending_scan} pending scan · yhwach scan --pending]")
    for line in nm_.render_next(nm):
        click.echo(line)


@main.command("export-notes")
@click.option("--lab", required=True, help="Lab name.")
@click.option("--out", "out_dir", default=None, type=click.Path(),
              help="Directory to write the notebook tree into (default: <lab>/notes).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def export_notes(lab: str, out_dir: str | None, db_path: str | None) -> None:
    """Auto-scaffold the Obsidian notebook from the world model.

    Regenerates the standing notes (Services & Software, Vulnerabilities, Web,
    Users & Groups, Shares) and one note per host â€” every table derived straight
    from the DB, with `<!-- yhwach:auto -->` fences around generated blocks. The
    operator writes only prose and syncs the tree into the vault via the Obsidian
    MCP. The DB stays the single source of truth for structured facts.
    """
    from yhwach import notes

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        target = Path(out_dir) if out_dir else _artifact_dir(path, "notes")
        written = notes.export_notes(conn, eng_id, target)
    click.echo(f"[+] wrote {len(written)} note(s) to {target}")
    for w in written:
        click.echo(f"    {w}")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--host", "host_ip", required=True, help="Host IP to render.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def recon(lab: str, host_ip: str, db_path: str | None) -> None:
    """Print the full recon picture for one host (everything the world model holds).

    Services, software, vulns, web paths, shares, on-host privileges, loot,
    interfaces, findings â€” the 'note everything on this host' view, straight from
    the DB. Same rendering `export-notes` writes to the vault.
    """
    from yhwach import notes

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                            (eng_id, host_ip)).fetchone()
        if hrow is None:
            click.echo(f"[!] Host {host_ip} not found.", err=True)
            sys.exit(2)
        click.echo(notes.render_host_note(conn, hrow["id"]))


@main.command()
@click.argument("pack", type=click.Choice(
    ["default-creds", "esc", "gtfobins", "lessons", "services", "tags", "lolbas",
     "wadcoms", "arsenal", "ai-attacks"]))
@click.option("--query", "-q", default=None, help="Filter to matching entries (substring).")
def ref(pack: str, query: str | None) -> None:
    """Query the bundled reference knowledge packs (offline, no engagement needed).

    default-creds - well-known creds per product (try before spraying).
    esc           - AD CS ESC catalog (requirement + abuse).
    gtfobins      - SUID/sudo privesc one-liners for common binaries.
    lessons       - knowledge won in past labs, keyed by trigger_tag.
    services      - the service matrix (identity -> ports -> triage).
    tags          - the chaining-tag registry (producer/consumer/implies).
    lolbas        - signed Windows binaries abused (the Windows gtfobins).
    wadcoms       - Windows/AD command matrix by phase (recon..dominance).
    arsenal       - vendored offensive tooling index (canonical/quick-win/deep).
    ai-attacks    - AI/LLM attack chains (RAG/MCP/A2A/vector-db/cloud) by OWASP-LLM.
    """
    from yhwach.reference import render_pack

    out = render_pack(pack, query)
    if not out:
        click.echo(f"[!] no {pack} entries matching '{query}'.", err=True)
        sys.exit(1)
    click.echo(out)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def vulns(lab: str, db_path: str | None) -> None:
    """Match recorded software versions against the offline CVE knowledge base.

    Records `vulnerability` rows and tags hosts `exploitable_cve` where a matched
    CVE has a known exploit (so `yhwach plan` surfaces `exploit_known_cve`). Fully
    offline and deterministic â€” the map is curated (data/cve_map.yaml).
    """
    from yhwach.vulns import enrich

    dbp = _db_path(db_path)
    if not dbp.exists():
        click.echo(f"[!] DB not found at {dbp}.", err=True)
        sys.exit(2)
    with yhdb.transaction(dbp) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        summ = enrich(conn, eng_id)
        yhdb.log_event(conn, eng_id, "vulns",
                       {"checked": summ["software_checked"], "matched": summ["matched"]})
    click.echo(f"[+] Checked {summ['software_checked']} software row(s): "
               f"{summ['matched']} CVE match(es), {summ['exploitable']} with a known exploit.")
    for h in summ["hits"]:
        click.echo(f"    {h}")
    if summ["matched"]:
        click.echo("    Re-run `yhwach plan` to queue exploit_known_cve; see `yhwach recon --host`.")


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of the report.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def audit(lab: str, as_json: bool, db_path: str | None) -> None:
    """Methodology audit: standards coverage (ATT&CK/OWASP/ATLAS/CWE/CVE) + the
    paths not yet checked (service_enum + scan-coverage gaps). Pure reads."""
    import json as _json

    from yhwach.audit import audit_as_dict, methodology_audit

    dbp = _db_path(db_path)
    if not dbp.exists():
        click.echo(f"[!] DB not found at {dbp}.", err=True)
        sys.exit(2)
    with yhdb.transaction(dbp) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        if as_json:
            click.echo(_json.dumps(audit_as_dict(conn, eng_id), indent=2))
        else:
            click.echo(methodology_audit(conn, eng_id))


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--from", "src", required=True,
              help="Source node: a principal/host name, or an explicit 'principal:<id>'/'host:<id>'.")
@click.option("--to", "dst", required=True, help="Target node (default target: 'Domain Admins').")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def path(lab: str, src: str, dst: str, db_path: str | None) -> None:
    """Shortest attack-graph path between two nodes (owned -> objective).

    Nodes may be given as names ('svc_sql', 'DC01', 'Domain Admins') â€” resolved to
    a principal or host â€” or explicitly as 'principal:<id>' / 'host:<id>'.
    """
    dbp = _db_path(db_path)
    if not dbp.exists():
        click.echo(f"[!] DB not found at {dbp}.", err=True)
        sys.exit(2)
    with yhdb.transaction(dbp) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        s = _resolve_node(conn, eng_id, src)
        d = _resolve_node(conn, eng_id, dst)
        if s is None:
            click.echo(f"[!] Could not resolve source '{src}'.", err=True)
            sys.exit(2)
        if d is None:
            click.echo(f"[!] Could not resolve target '{dst}'.", err=True)
            sys.exit(2)
        result = yhdb.shortest_path(conn, eng_id, s, d)
        if result is None:
            click.echo(f"[-] No known path {src} -> {dst}. Enumerate more edges "
                       "(bloodhound/netexec) or the path may not exist yet.")
            return
        click.echo(f"[+] {src} -> {dst} ({len(result) - 1} hop(s)):")
        click.echo("    " + _fmt_path(conn, result))


def _resolve_node(conn, eng_id: int, token: str) -> str | None:
    """Resolve a node token to 'principal:<id>' / 'host:<id>'."""
    if token.startswith(("principal:", "host:")):
        return token
    prow = conn.execute(
        "SELECT id FROM principal WHERE engagement_id=? AND name=? COLLATE NOCASE ORDER BY id LIMIT 1",
        (eng_id, token)).fetchone()
    if prow:
        return f"principal:{prow['id']}"
    hrow = conn.execute(
        "SELECT id FROM host WHERE engagement_id=? AND (ip=? OR hostname=? COLLATE NOCASE) LIMIT 1",
        (eng_id, token, token)).fetchone()
    if hrow:
        return f"host:{hrow['id']}"
    return None


def _fmt_path(conn, nodes: list[str]) -> str:
    """Render a node-id path as readable names with edge kinds between them."""
    from yhwach.pathfind import render_path
    return render_path(conn, nodes)


@main.command()
@click.option("--lab", required=True, help="Lab name.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def paths(lab: str, as_json: bool, db_path: str | None) -> None:
    """Shortest attack-graph path from what you OWN to each objective / Domain Admins.

    Derives the owned nodes (principals you hold creds for + owned hosts) and the
    targets (uncaptured objective hosts + the Domain/Enterprise Admins groups),
    then renders the shortest path to each. Unreachable targets are shown too —
    "no known path yet" means enumerate more edges (bloodhound / netexec).
    """
    import json as _json

    from yhwach import pathfind

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}.", err=True)
        sys.exit(2)
    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)
        found = pathfind.paths_to_objectives(conn, eng_id)
        if as_json:
            out = [{
                "target": p.target_label, "target_node": p.target_node,
                "reachable": p.reachable, "hops": p.hops,
                "path": p.path,
                "path_rendered": pathfind.render_path(conn, p.path) if p.path else None,
            } for p in found]
            click.echo(_json.dumps(out, indent=2))
            return
        lines = pathfind.render_objectives(conn, found)
    reach = sum(1 for p in found if p.reachable)
    click.echo(f"== Paths to objectives for '{lab}' ({reach}/{len(found)} reachable) ==")
    for line in lines:
        click.echo(line)


@main.command()
@click.option("--lab", required=True, help="Lab name (must exist).")
@click.option("--host", "host_ip", default=None,
              help="Restrict the run to one host IP (a single worker's slice).")
@click.option("--phase", default="enumeration", show_default=True, help="Phase label.")
@click.option("--allow-gated", is_flag=True, default=False,
              help="Let exploit-tier moves run unattended (never destructive). Off by default.")
@click.option("--allow", "allow_spec", default=None,
              help="Grant high-consequence action classes, comma-separated: "
                   "push, code_change, listener, out_of_scope_write. These reach OUTSIDE "
                   "the engagement and --allow-gated does NOT cover them; each needs its own "
                   "explicit grant here. Unknown tokens are ignored (fail closed).")
@click.option("--max-actions", default=None, type=int, help="Budget: max brain actions.")
@click.option("--max-iterations", default=200, show_default=True, type=int,
              help="Hard loop backstop.")
@click.option("--fan-out", is_flag=True, default=False,
              help="Dispatch one worker per host (ignored with --host).")
@click.option("--parallel", default=1, show_default=True, type=int,
              help="With --fan-out, run up to N host workers concurrently, each on its own "
                   "DB connection (WAL-safe). 1 = sequential.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Run the loop deterministically with no model / no API key.")
@click.option("--hexstrike-url", default=None,
              help="HexStrike server URL to actually run read-only enumeration "
                   "(e.g. http://127.0.0.1:8888). Without it, runs are recorded as 'planned'.")
@click.option("--model", default=None, help="Override the doer/judge model id.")
@click.option("--provider", "provider_opt", default=None,
              type=click.Choice(["anthropic", "openai"]),
              help="Model provider. Default: inferred from --model, then "
                   "YHWACH_PROVIDER, then whichever API key is set.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def run(lab: str, host_ip: str | None, phase: str, allow_gated: bool, allow_spec: str | None,
        max_actions: int | None, max_iterations: int, fan_out: bool, parallel: int, dry_run: bool,
        hexstrike_url: str | None, model: str | None, provider_opt: str | None,
        db_path: str | None) -> None:
    """Run the autonomous agent loop over an engagement: candidates -> brain ->
    execute -> judge -> a State + Next Steps report.

    Read-only recon runs unattended; exploit/destructive moves are queued for
    approval unless --allow-gated. Without --dry-run this calls a model through
    the selected provider (Anthropic by default, needs ANTHROPIC_API_KEY +
    'yhwach[agent]'; or OpenAI via --provider openai / a gpt* --model, needs
    OPENAI_API_KEY + 'yhwach[agent-openai]'). The provider is inferred from
    --model, then YHWACH_PROVIDER, then whichever key is set. With
    --hexstrike-url, read-only enumeration is actually executed through HexStrike
    and its output parsed into findings.
    """
    from yhwach import policy as pol
    from yhwach import synthesis
    from yhwach.orchestrator import Orchestrator

    grants = pol.parse_grants(allow_spec)
    if allow_spec and not grants:
        click.echo(f"[!] --allow '{allow_spec}' named no known action class; ignoring.", err=True)

    path = _db_path(db_path)
    if not path.exists():
        click.echo(f"[!] DB not found at {path}; run `yhwach engage` first.", err=True)
        sys.exit(2)

    with yhdb.transaction(path) as conn:
        eng_id = yhdb.engagement_id_for(conn, lab)
        if eng_id is None:
            click.echo(f"[!] Unknown lab '{lab}'.", err=True)
            sys.exit(2)

        runner = None
        if hexstrike_url:
            from yhwach.hexstrike import HexStrikeClient
            from yhwach.runners import HexStrikeRunner

            runner = HexStrikeRunner(HexStrikeClient(hexstrike_url), conn, eng_id)
            click.echo(f"[+] enumeration will run through HexStrike at {hexstrike_url}")

        def budget() -> pol.Budget:
            return pol.Budget(max_actions=max_actions)

        if dry_run:
            from yhwach.dryrun import DeterministicDoer, DeterministicJudge

            def make_doer(ip):
                return DeterministicDoer(conn, eng_id, host_ip=ip)

            def make_doer_conn(ip, c):  # parallel: bind the worker's own connection
                return DeterministicDoer(c, eng_id, host_ip=ip)

            judge_brain = DeterministicJudge(conn, eng_id, phase=phase)
        else:
            from yhwach.brain import Brain, Role
            from yhwach.providers import (
                ProviderError,
                make_provider,
                resolve_provider,
            )

            try:
                provider_name = resolve_provider(provider_opt, model=model)
            except ProviderError as exc:
                click.echo(f"[!] {exc}", err=True)
                sys.exit(2)
            click.echo(f"[+] model provider: {provider_name}"
                       + (f" (model={model})" if model else ""))

            # One adapter instance per role; Brain is otherwise connection-agnostic.
            def make_doer(ip):
                return Brain(Role.DOER, model=model, provider=make_provider(provider_name))

            def make_doer_conn(ip, c):
                return Brain(Role.DOER, model=model, provider=make_provider(provider_name))

            judge_brain = Brain(Role.JUDGE, model=model, provider=make_provider(provider_name))

        if grants:
            click.echo(f"[+] high-consequence grants enabled: {', '.join(sorted(grants))}")
        click.echo(f"[+] Running agent on '{lab}' (phase={phase}, "
                   f"{'dry-run' if dry_run else 'live'}"
                   f"{', fan-out' if fan_out and not host_ip else ''})...")

        if fan_out and host_ip is None:
            from yhwach import workers

            report = workers.run_workers(
                conn, eng_id,
                doer_for=make_doer, judge_brain=judge_brain,
                budget_for=lambda ip: budget(), allow_gated=allow_gated, allow_grants=grants,
                phase=phase,
                runner=runner,
                max_parallel=parallel,
                conn_for=(lambda ip: yhdb.connect(path)) if parallel > 1 else None,
                doer_for_conn=make_doer_conn if parallel > 1 else None,
            )
            for ip, r in report.per_host.items():
                click.echo(f"  [{ip}] executed={r.executed} queued={r.queued} "
                           f"halt={r.halt_reason}")
            verdict = report.verdict
            click.echo(f"[=] executed={report.total_executed} queued={report.total_queued}")
        else:
            orch = Orchestrator(
                conn, eng_id,
                doer=make_doer(host_ip), judge_brain=judge_brain,
                runner=runner,
                budget=budget(), allow_gated=allow_gated, allow_grants=grants, phase=phase,
                max_iterations=max_iterations, host_ip=host_ip,
            )
            report = orch.run()
            verdict = report.verdict
            click.echo(f"[=] executed={report.executed} queued={report.queued} "
                       f"halt={report.halt_reason}")
            if report.halt_reason == "brain_error" and report.halt_detail:
                click.echo(f"[!] model call failed: {report.halt_detail}", err=True)

        click.echo("")
        click.echo(synthesis.phase_report(conn, eng_id, phase=phase, verdict=verdict))


@main.command()
@click.option("--lab", default=None, help="Also verify this engagement exists in the DB.")
@click.option("--hexstrike-url", default=None,
              help="Ping this HexStrike URL for reachability (e.g. http://127.0.0.1:8888).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def doctor(lab: str | None, hexstrike_url: str | None, db_path: str | None) -> None:
    """Preflight the box before an engagement: DB, technique catalog, optional
    extras, API key, and HexStrike reachability. Prints a checklist and exits
    non-zero if a hard requirement (writable DB dir, loadable catalog) fails.
    Everything AI needs a key for is a soft check — `--dry-run` needs none.
    """
    import importlib.util
    import socket
    from urllib.parse import urlparse

    state = {"ok": True}

    def check(good: bool, label: str, detail: str = "") -> None:
        if not good:
            state["ok"] = False
        click.echo(f"  [{'✓' if good else '✗'}] {label}" + (f" — {detail}" if detail else ""))

    def note(label: str, detail: str = "") -> None:
        click.echo(f"  [~] {label}" + (f" — {detail}" if detail else ""))

    def have(mod: str) -> bool:
        return importlib.util.find_spec(mod) is not None

    click.echo("yhwach doctor — preflight\n")

    # -- DB ------------------------------------------------------------------
    path = _db_path(db_path)
    check(path.parent.exists() and os.access(path.parent, os.W_OK),
          "DB directory writable", str(path.parent))
    if path.exists():
        try:
            with yhdb.transaction(path) as conn:
                n = conn.execute("SELECT COUNT(*) FROM engagement").fetchone()[0]
                eid = yhdb.engagement_id_for(conn, lab) if lab else None
            note("DB present", f"{path} · {n} engagement(s)")
            if lab:
                check(eid is not None, f"engagement '{lab}' exists",
                      f"id={eid}" if eid is not None else "run `yhwach engage` first")
        except Exception as exc:  # a corrupt/locked DB is worth surfacing
            check(False, "DB opens", str(exc))
    else:
        note("DB absent", f"{path} — run `yhwach engage` to create it")

    # -- DB file permissions (POSIX; the DB holds creds in the clear) --------
    if os.name == "posix":
        insecure = yhdb.perms_insecure(path)
        check(not insecure, "DB permissions owner-only (0600/0700)",
              ("group/world-accessible: " + ", ".join(insecure)
               + " — run `chmod 600`/`700`") if insecure else "")
    else:
        note("DB permissions", "not enforced on this platform (Linux only)")

    # -- technique catalog ---------------------------------------------------
    try:
        from yhwach import knowledge as kn

        techs = kn.load_techniques()
        check(bool(techs), "technique catalog loads", f"{len(techs)} techniques")
    except Exception as exc:
        check(False, "technique catalog loads", str(exc))

    # -- deps / extras (soft) -----------------------------------------------
    check(have("yaml"), "core deps present")
    note("UI extra [ui]",
         "ok" if have("fastapi") and have("uvicorn") else "missing — pip install 'yhwach[ui]'")
    note("agent extra [agent]",
         "ok" if have("anthropic")
         else "missing — pip install 'yhwach[agent]' (live AI only; not --dry-run)")
    note("MCP extra [mcp]", "ok" if have("mcp") else "missing — pip install 'yhwach[mcp]'")
    note("ANTHROPIC_API_KEY",
         "set" if os.environ.get("ANTHROPIC_API_KEY")
         else "unset — use --dry-run (no key), or export it for live AI")

    # -- HexStrike reachability ---------------------------------------------
    if hexstrike_url:
        u = urlparse(hexstrike_url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        try:
            with socket.create_connection((host, port), timeout=3):
                check(True, "HexStrike reachable", f"{host}:{port}")
        except OSError as exc:
            check(False, "HexStrike reachable", f"{host}:{port} — {type(exc).__name__}")
    else:
        note("HexStrike", "no --hexstrike-url; runs record as 'planned' without it")

    click.echo("")
    if state["ok"]:
        click.echo("[=] ready.")
    else:
        click.echo("[!] one or more hard checks failed (see ✗ above).", err=True)
        sys.exit(1)


@main.command()
@click.option("--lab", required=True, help="Lab name to display.")
@click.option("--host", "bind", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=8799, show_default=True, type=int, help="Port.")
@click.option("--redact", is_flag=True, default=False,
              help="Mask credential secrets in the Vault (no reveal/copy).")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def ui(lab: str, bind: str, port: int, redact: bool, db_path: str | None) -> None:
    """Serve the live board: world model + worker activity. Read-only view over
    the DB. Needs `pip install 'yhwach[ui]'`."""
    try:
        import uvicorn

        from yhwach.ui import create_app
    except ImportError:
        click.echo("[!] UI needs extras: pip install 'yhwach[ui]'", err=True)
        sys.exit(2)
    # The board shows credentials in the clear and has no authentication.
    # Binding to all interfaces exposes the whole engagement to the network;
    # refuse it outright. A specific non-loopback address gets a loud warning.
    if bind in ("0.0.0.0", "::", ""):
        click.echo(
            "[!] refusing to bind the board to all interfaces "
            f"({bind!r}) — it serves secrets with no auth. Use --host 127.0.0.1 "
            "(default) and reach it over an SSH tunnel if remote.", err=True)
        sys.exit(2)
    if bind not in ("127.0.0.1", "::1", "localhost"):
        click.echo(
            f"[!] WARNING: binding to {bind} (not loopback). The board serves "
            "secrets with no authentication — only do this on a trusted, "
            "isolated interface.", err=True)
    path = _db_path(db_path)
    click.echo(f"[+] yhwach board for '{lab}' at http://{bind}:{port}  (DB: {path})")
    uvicorn.run(create_app(path, lab, reveal_secrets=not redact),
                host=bind, port=port, log_level="warning")


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
            sw = software_from_result(result)
            if sw is not None:
                yhdb.add_software(
                    conn, t["host_id"], sw[0], sw[1],
                    service_id=t["service_id"], source="probe",
                )
            click.echo(
                f"[+] {t['ip']}:{t['port']} -> {result.kind} (auth={result.auth}) "
                f"[{label}] {'NEW' if created else 'UPD'}"
                + (f" [sw: {sw[0]} {sw[1]}]" if sw else "")
            )

        for s in services:
            # AI surfaces (fixed port list).
            if s["port"] in PROBES_BY_PORT:
                ai = run_probes(
                    session, s["ip"], s["port"], timeout=timeout,
                    on_probe=lambda name, outcome, kind, _s=s: yhdb.record_probe_run(
                        conn, eng_id, _s["host_id"], _s["port"], name, outcome, kind=kind),
                )
                if ai is not None:
                    _record(s, ai, "ai")
            # Traditional surfaces (all services).
            trad = detect_traditional(session, s["ip"], s["port"], s["product"],
                                     proto=s.get("proto", "tcp"), timeout=timeout)
            # The traditional detector is a probe run too: without a row, a
            # service with no surface might have been swept and matched nothing,
            # or never been touched at all.
            yhdb.record_probe_run(
                conn, eng_id, s["host_id"], s["port"], "detect_traditional",
                "hit" if trad is not None else "miss",
                kind=trad.kind if trad is not None else None)
            if trad is not None:
                _record(s, trad, "traditional")

        click.echo(f"[=] {surfaces_found} surfaces detected ({surfaces_new} new).")


if __name__ == "__main__":
    main()
