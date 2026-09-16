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


if __name__ == "__main__":
    main()
