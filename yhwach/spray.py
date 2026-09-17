"""Credential spray planning — the credential_reuse primitive, made actionable.

Credentials are never exhausted: once the vault is non-empty, every credential is
a candidate against every reachable auth surface. build_spray_plan pairs each
vault credential with each host exposing a sprayable protocol and renders the
netexec commands. Spraying is active auth-testing, so it is proposal-tier — the
operator runs it.
"""
from __future__ import annotations

import shlex
import sqlite3
from collections import defaultdict

from yhwach.db import list_credentials

# surface kind -> netexec protocol
SPRAYABLE = {"smb", "winrm", "ssh", "ldap", "mssql", "rdp"}


def build_spray_plan(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    proto_filter: str | None = None,
) -> list[str]:
    """Return netexec spray commands: each (protocol, credential) across all
    hosts exposing that protocol. Empty if the vault or the surfaces are empty."""
    creds = list_credentials(conn, engagement_id)
    if not creds:
        return []

    rows = conn.execute(
        "SELECT DISTINCT h.ip AS ip, s.kind AS kind "
        "FROM host h JOIN surface s ON s.host_id = h.id "
        "WHERE h.engagement_id = ? AND s.kind IN "
        "('smb','winrm','ssh','ldap','mssql','rdp') "
        "ORDER BY s.kind, h.ip",
        (engagement_id,),
    ).fetchall()

    proto_ips: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        proto_ips[r["kind"]].append(r["ip"])

    commands: list[str] = []
    for proto in sorted(proto_ips):
        if proto_filter and proto != proto_filter:
            continue
        ip_list = " ".join(sorted(set(proto_ips[proto])))
        for c in creds:
            secret = c["secret"] or ""
            # Shell-quote every field: secrets and identifiers can legitimately
            # contain quotes, spaces, or shell metacharacters, which would
            # otherwise break or misfire the rendered nxc line.
            flag = "-H" if c["kind"] == "ntlm" else "-p"
            auth = f"{flag} {shlex.quote(secret)}"
            user = shlex.quote(c["identifier"] or "")
            commands.append(
                f"nxc {proto} {ip_list} -u {user} {auth} --continue-on-success"
            )
    return commands
