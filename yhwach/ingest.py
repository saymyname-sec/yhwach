"""Structured ingestion — parser output -> world-model rows.

The nmap/PEAS/BloodHound/certipy *finding* path lives in the CLI/MCP ingest
handlers already. This module owns the richer, table-shaped ingestion added in
schema v1 (NetExec SMB facts, web content discovery, the AD graph, PEAS software),
so the `yhwach ingest` command and the `ingest` MCP tool share one implementation.

Every function takes an open connection inside a transaction and returns a small
summary dict for the caller to echo. Findings are still emitted (with chaining
tags) so the existing planner picks the new facts up.
"""
from __future__ import annotations

import sqlite3

from yhwach import db as yhdb
from yhwach.parsers.bloodhound import parse_bloodhound_graph
from yhwach.parsers.netexec import parse_netexec
from yhwach.parsers.nmap import _os_class
from yhwach.parsers.peas import parse_peas_software
from yhwach.parsers.web import parse_web


def ingest_netexec(conn: sqlite3.Connection, eng_id: int, host_id: int, text: str) -> dict:
    """NetExec SMB output -> shares, principals, admin edges, password policy, findings."""
    res = parse_netexec(text)
    if res.hostname or res.os:
        conn.execute(
            "UPDATE host SET hostname = COALESCE(?, hostname), os = COALESCE(?, os) WHERE id = ?",
            (res.hostname, _os_class(res.os), host_id),
        )
    for sh in res.shares:
        yhdb.add_share(conn, host_id, sh.name, access=sh.access, remark=sh.remark,
                       source="netexec")
    for p in res.principals:
        yhdb.add_principal(conn, eng_id, p.name, domain=p.domain or res.domain, type="user",
                           description=p.description, source="netexec")
    for admin in sorted(set(res.admin_users)):
        pid, _ = yhdb.add_principal(conn, eng_id, admin, domain=res.domain, type="user",
                                    source="netexec")
        yhdb.add_privilege(conn, eng_id, "local_admin", principal_id=pid, host_id=host_id,
                           source="netexec")
        yhdb.add_edge(conn, eng_id, f"principal:{pid}", f"host:{host_id}", "AdminTo",
                      source="netexec")
    if res.password_policy:
        pp = res.password_policy
        yhdb.add_password_policy(
            conn, eng_id, domain=res.domain, host_id=host_id,
            min_length=pp.get("min_length"), lockout_threshold=pp.get("lockout_threshold"),
            lockout_window_min=pp.get("lockout_window_min"), complexity=pp.get("complexity"),
            source="netexec")
    for f in res.findings:
        yhdb.add_finding(conn, host_id, None, f.cls, f.title, f.severity, f.evidence, tag=f.tag)
    return {
        "shares": len(res.shares), "principals": len(res.principals),
        "admin": len(set(res.admin_users)), "policy": bool(res.password_policy),
        "findings": len(res.findings),
    }


# web_path kind -> (finding class, severity, chaining tag) for the web.yaml rules.
_WEB_KIND_FINDING = {
    "login": ("CWE-287", "medium", "web_login"),
    "upload": ("CWE-434", "high", "web_upload"),
    "admin": ("CWE-284", "medium", "web_admin"),
    "api": ("CWE-200", "medium", "web_api"),
    "source": ("CWE-527", "high", "web_git"),
    "backup": ("CWE-530", "high", "web_backup"),
    "config": ("CWE-538", "high", "web_config"),
}


def ingest_web(conn: sqlite3.Connection, host_id: int, base_url: str, text: str,
               *, server: str | None = None, tech: str | None = None) -> dict:
    """Web content-discovery output -> a web_app, its web_path rows, and one
    chaining finding per interesting path *kind* (so web.yaml rules fire)."""
    wid, _ = yhdb.add_web_app(conn, host_id, base_url, server=server, tech=tech,
                              scheme=base_url.split("://", 1)[0] if "://" in base_url else None)
    paths = parse_web(text, base_url=base_url)
    interesting = 0
    kinds_seen: dict[str, str] = {}   # tag-kind -> first example path
    for p in paths:
        yhdb.add_web_path(conn, wid, p.path, status=p.status, length=p.length, kind=p.kind,
                          interesting=p.interesting, source="web",
                          notes=(f"-> {p.redirect}" if p.redirect else None))
        if p.interesting:
            interesting += 1
            if p.kind in _WEB_KIND_FINDING:
                kinds_seen.setdefault(p.kind, p.path)
    for kind, example in kinds_seen.items():
        cls, sev, tag = _WEB_KIND_FINDING[kind]
        yhdb.add_finding(conn, host_id, None, cls, f"Web {kind} surface", sev,
                         f"{base_url}{example}", tag=tag)
    return {"web_app_id": wid, "paths": len(paths), "interesting": interesting,
            "findings": len(kinds_seen)}


def ingest_bloodhound_graph(conn: sqlite3.Connection, eng_id: int, text: str) -> dict:
    """BloodHound output -> principal / privilege / edge rows (the AD graph)."""
    g = parse_bloodhound_graph(text)
    name_to_id: dict[str, int] = {}

    def resolve(name: str, domain: str | None = None, ptype: str = "user") -> int:
        key = name.lower()
        if key in name_to_id:
            return name_to_id[key]
        pid, _ = yhdb.add_principal(conn, eng_id, name, domain=domain, type=ptype,
                                    source="bloodhound")
        name_to_id[key] = pid
        return pid

    for bp in g.principals:
        pid, _ = yhdb.add_principal(conn, eng_id, bp.name, domain=bp.domain, type=bp.type,
                                    flags=bp.flags, spn=bp.spn, source="bloodhound")
        name_to_id[bp.name.lower()] = pid
    for pname, right, target in g.privileges:
        yhdb.add_privilege(conn, eng_id, right, principal_id=resolve(pname), target=target,
                           source="bloodhound")
    for src, dst, kind in g.edges:
        dtype = "group" if dst.lower() in ("domain admins", "enterprise admins") else "user"
        yhdb.add_edge(conn, eng_id, f"principal:{resolve(src)}",
                      f"principal:{resolve(dst, ptype=dtype)}", kind, source="bloodhound")
    return {"principals": len(g.principals), "privileges": len(g.privileges),
            "edges": len(g.edges)}


def ingest_peas_software(conn: sqlite3.Connection, host_id: int, text: str, kind: str) -> int:
    """PEAS output -> software rows (kernel/sudo/OS build) for the CVE pipeline."""
    rows = parse_peas_software(text, kind)
    for name, version, skind in rows:
        yhdb.add_software(conn, host_id, name, version, kind=skind, source=kind)
    return len(rows)
