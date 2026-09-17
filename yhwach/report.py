"""Engagement report generation: world model -> Markdown.

Builds a report from the authoritative state (hosts / services / surfaces /
findings / proofs). OSAI reports must copy-paste reproduce, so findings carry
their evidence and the rendered command lives in the task/action layer.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

_SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
             "WHEN 'medium' THEN 2 ELSE 3 END"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(conn: sqlite3.Connection, engagement_id: int) -> str:
    eng = conn.execute(
        "SELECT lab, scope, domain, dc_ip, started_at, points_target "
        "FROM engagement WHERE id = ?",
        (engagement_id,),
    ).fetchone()
    if eng is None:
        return "# Yhwach report\n\n(engagement not found)\n"

    out: list[str] = []
    out.append(f"# Yhwach Engagement Report — {eng['lab']}")
    out.append("")
    meta = [f"**Scope:** {eng['scope']}"]
    if eng["domain"]:
        meta.append(f"**Domain:** {eng['domain']}")
    if eng["dc_ip"]:
        meta.append(f"**DC:** {eng['dc_ip']}")
    meta.append(f"**Started:** {eng['started_at']}")
    meta.append(f"**Generated:** {_now()}")
    out.append("  ·  ".join(meta))
    out.append("")

    # --- Scoreboard ---
    stages = conn.execute(
        "SELECT stage, COUNT(*) AS n FROM host WHERE engagement_id = ? GROUP BY stage ORDER BY stage",
        (engagement_id,),
    ).fetchall()
    sev_counts = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM finding f "
        "JOIN host h ON h.id = f.host_id WHERE h.engagement_id = ? AND f.status = 'open' "
        "GROUP BY severity",
        (engagement_id,),
    ).fetchall()
    sev_map = {r["severity"]: r["n"] for r in sev_counts}

    out.append("## Scoreboard")
    out.append("")
    out.append("| Stage | Hosts |")
    out.append("|---|---|")
    for r in stages:
        out.append(f"| {r['stage']} | {r['n']} |")
    out.append("")
    out.append(
        "**Findings:** "
        + ", ".join(f"{sev} {sev_map.get(sev, 0)}"
                    for sev in ("critical", "high", "medium", "low"))
    )
    out.append("")

    # --- Findings (severity-ordered) ---
    findings = conn.execute(
        "SELECT f.class, f.title, f.severity, f.evidence, h.ip AS ip "
        "FROM finding f LEFT JOIN host h ON h.id = f.host_id "
        "WHERE (h.engagement_id = ? OR f.host_id IS NULL) AND f.status = 'open' "
        f"ORDER BY {_SEV_ORDER}, f.id",
        (engagement_id,),
    ).fetchall()
    out.append("## Findings")
    out.append("")
    if not findings:
        out.append("_None recorded._")
    else:
        for f in findings:
            out.append(f"### [{f['severity'].upper()}] {f['class']} — {f['title']}")
            out.append(f"- **Host:** {f['ip'] or '-'}")
            if f["evidence"]:
                out.append(f"- **Evidence:** {f['evidence']}")
            out.append("")

    # --- Hosts detail ---
    out.append("## Hosts")
    out.append("")
    hosts = conn.execute(
        "SELECT id, ip, hostname, os, role, stage, tags FROM host "
        "WHERE engagement_id = ? ORDER BY ip",
        (engagement_id,),
    ).fetchall()
    for h in hosts:
        title = f"### {h['ip']}"
        if h["hostname"]:
            title += f" ({h['hostname']})"
        out.append(title)
        bits = [f"os={h['os'] or '?'}", f"stage={h['stage']}"]
        if h["role"]:
            bits.append(f"role={h['role']}")
        if h["tags"]:
            bits.append(f"tags={h['tags']}")
        out.append("  ·  ".join(bits))

        svcs = conn.execute(
            "SELECT port, proto, product, version FROM service WHERE host_id = ? ORDER BY port",
            (h["id"],),
        ).fetchall()
        if svcs:
            out.append("- **Services:** " + ", ".join(
                f"{s['port']}/{s['proto']} {s['product'] or ''}{(' ' + s['version']) if s['version'] else ''}".strip()
                for s in svcs
            ))
        surfs = conn.execute(
            "SELECT kind, auth FROM surface WHERE host_id = ? ORDER BY kind", (h["id"],)
        ).fetchall()
        if surfs:
            out.append("- **Surfaces:** " + ", ".join(f"{s['kind']}({s['auth']})" for s in surfs))
        hfnd = conn.execute(
            "SELECT class, title, severity FROM finding WHERE host_id = ? AND status = 'open' "
            f"ORDER BY {_SEV_ORDER}",
            (h["id"],),
        ).fetchall()
        if hfnd:
            for f in hfnd:
                out.append(f"- **Finding:** [{f['severity'].upper()}] {f['class']} {f['title']}")
        out.append("")

    # --- Proofs ---
    proofs = conn.execute(
        "SELECT h.ip AS ip, p.flag_path, p.screenshot_path, p.scored "
        "FROM proof p JOIN host h ON h.id = p.host_id WHERE h.engagement_id = ? ORDER BY h.ip",
        (engagement_id,),
    ).fetchall()
    out.append("## Proofs")
    out.append("")
    if not proofs:
        out.append("_None captured._")
    else:
        out.append("| Host | Flag | Screenshot | Scored |")
        out.append("|---|---|---|---|")
        for p in proofs:
            out.append(f"| {p['ip']} | {p['flag_path']} | {p['screenshot_path']} | "
                       f"{'yes' if p['scored'] else 'no'} |")
    out.append("")

    out.append("---")
    out.append("_Generated by Yhwach. Authorized OSAI / lab use only._")
    return "\n".join(out)
