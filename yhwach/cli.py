"""Yhwach CLI.

The engagement driver: engage / ingest / enum / probe / brief, post-foothold
(advance / cred / creds), findings / report / gaps / path / recon / vulns,
and the MCP server (mcp). See `cli/README.md` for the full command reference.

Notes are not a CLI concern: the engagement notebook is a LOCAL Obsidian vault,
written with the file tools (no MCP) — see persona/notebook.md.

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
from yhwach.coverage import enum_gaps, render_gaps
from yhwach.engine import artifact_dir as _artifact_dir
from yhwach.parsers.nmap import insert_hosts, parse_nmap
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
    from yhwach.scope import validate_scope

    bad = validate_scope(scope)
    if bad:
        click.echo(f"[!] Invalid scope token(s): {', '.join(bad)} — use IPs/CIDRs "
                   "(e.g. 10.10.10.0/24,192.168.1.5).", err=True)
        sys.exit(2)

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
@click.option("--kind",
              type=click.Choice(["nmap", "linpeas", "winpeas", "bloodhound", "certipy",
                                 "netexec", "web"]),
              default="nmap", help="Parser kind.")
@click.option("--host", "host_ip", default=None,
              help="Host IP (required for linpeas/winpeas/bloodhound/certipy/netexec/web — "
                   "facts are host-scoped; for bloodhound/certipy use the DC or CA).")
@click.option("--url", "base_url", default=None,
              help="Base URL for --kind web (e.g. http://10.0.0.5:80) — the web_app the "
                   "discovered paths attach to.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Override DB path.")
def ingest(file: str, lab: str, kind: str, host_ip: str | None, base_url: str | None,
           db_path: str | None) -> None:
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
            summ = ingest_web(conn, hrow["id"], base_url, text)
            yhdb.log_event(conn, eng_id, "ingest", {"kind": kind, "host": host_ip, **summ})
            click.echo(f"[+] Ingested web on {base_url}: {summ['paths']} path(s), "
                       f"{summ['interesting']} interesting")
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
            yhdb.set_host_stage(conn, eng_id, host_ip, "enumerated")
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
        # Advisory under-enumeration check. Calling a half-scanned host
        # 'enumerated' is the top OSAI failure mode; the engine warns rather than
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
              type=click.Choice(["reach", "hold", "surfaces", "unlocks", "unexplored", "objectives"]),
              help="Only this section of the brief.")
@click.option("--db", "db_path", default=None, type=click.Path(), help="Override DB path.")
def brief(lab: str, section: str | None, db_path: str | None) -> None:
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
        click.echo(build_brief(conn, eng_id, section=section))


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
            "WHERE f.engagement_id = ? AND f.status = 'open' "
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
@click.argument("pack", type=click.Choice(["default-creds", "esc", "gtfobins"]))
@click.option("--query", "-q", default=None, help="Filter to matching entries (substring).")
def ref(pack: str, query: str | None) -> None:
    """Query the bundled reference knowledge packs (offline, no engagement needed).

    default-creds â€” well-known creds per product (try before spraying).
    esc           â€” AD CS ESC1-8 catalog (requirement + abuse).
    gtfobins      â€” SUID/sudo privesc one-liners for common binaries.
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
    labels = []
    for n in nodes:
        kind, _, nid = n.partition(":")
        if kind == "principal":
            row = conn.execute("SELECT name FROM principal WHERE id=?", (nid,)).fetchone()
            labels.append(row["name"] if row else n)
        else:
            row = conn.execute("SELECT hostname, ip FROM host WHERE id=?", (nid,)).fetchone()
            labels.append((row["hostname"] or row["ip"]) if row else n)
    parts = [labels[0]]
    for i in range(1, len(nodes)):
        e = conn.execute("SELECT kind FROM edge WHERE src=? AND dst=? LIMIT 1",
                         (nodes[i - 1], nodes[i])).fetchone()
        parts.append(f" --{e['kind'] if e else '?'}--> {labels[i]}")
    return "".join(parts)


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
