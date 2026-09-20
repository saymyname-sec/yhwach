"""Engagement report generation: world model -> Markdown.

Builds a report from the authoritative state (hosts / services / surfaces /
findings / proofs). OSAI reports must copy-paste reproduce, so findings carry
their evidence and the rendered command lives in the task/action layer.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

_SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
             "WHEN 'medium' THEN 2 ELSE 3 END"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def event_summary(kind: str, payload_json: str | None) -> str:
    """One-line, human summary of an event's payload for the timeline."""
    try:
        p = json.loads(payload_json) if payload_json else {}
    except (ValueError, TypeError):
        p = {}
    if not isinstance(p, dict):
        return str(p)[:80]
    if kind in ("ingest", "enum") and "hosts" in p:
        return f"{p.get('hosts', '?')} hosts, {p.get('services', '?')} services" \
               + (f" (via {p['via']})" if p.get("via") else "")
    if kind == "ingest":
        return f"{p.get('kind', '?')} on {p.get('host', '?')}: {p.get('findings', 0)} finding(s)"
    if kind == "stage":
        return f"{p.get('host', '?')} -> {p.get('stage', '?')}"
    if kind == "credential":
        return f"{p.get('id', '?')} ({p.get('kind', '?')})" \
               + (f" @ {p['host']}" if p.get("host") else "")
    if kind == "tunnel":
        return f"{p.get('subnet', '?')} via {p.get('via', '?')}"
    if kind == "attempt":
        base = f"{p.get('rule', '?')} @ {p.get('host', '-')} -> {p.get('result', '?')}"
        return base + (f" ({p['reason']})" if p.get("reason") else "")
    return ", ".join(f"{k}={v}" for k, v in list(p.items())[:3])[:80]


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
        "SELECT severity, COUNT(*) AS n FROM finding "
        "WHERE engagement_id = ? AND status = 'open' GROUP BY severity",
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
        "WHERE f.engagement_id = ? AND f.status = 'open' "
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

    # --- Reachability / pivots ---
    tunnels = conn.execute(
        "SELECT t.subnet, t.kind, h.ip AS via_ip FROM tunnel t "
        "LEFT JOIN host h ON h.id = t.via_host_id WHERE t.engagement_id = ? "
        "ORDER BY t.created_at",
        (engagement_id,),
    ).fetchall()
    if tunnels:
        out.append("## Reachability / pivots")
        out.append("")
        out.append("| Subnet | Via | Kind |")
        out.append("|---|---|---|")
        for t in tunnels:
            out.append(f"| {t['subnet']} | {t['via_ip'] or '-'} | {t['kind']} |")
        out.append("")

    # --- Attempts (the ledger: what was tried, and what came of it) ---
    # A report that only lists what worked reads as luck. The dead ends are the
    # methodology — and they are also what a re-test needs in order not to
    # repeat the engagement.
    attempts = conn.execute(
        "SELECT a.attempted_at, a.playbook_rule_id AS rule_id, a.result, a.reason, "
        "h.ip AS ip FROM attempt a LEFT JOIN host h ON h.id = a.host_id "
        "WHERE a.engagement_id = ? ORDER BY a.id",
        (engagement_id,),
    ).fetchall()
    if attempts:
        landed = sum(1 for a in attempts if a["result"] == "success")
        out.append(f"## Attempts ({len(attempts)}; {landed} landed)")
        out.append("")
        out.append("| Time (UTC) | Host | Technique | Result | Why |")
        out.append("|---|---|---|---|---|")
        for a in attempts:
            out.append(f"| {a['attempted_at']} | {a['ip'] or '-'} | {a['rule_id'] or '-'} | "
                       f"{a['result']} | {a['reason'] or ''} |")
        out.append("")

    # --- Timeline (from the append-only event log) ---
    events = conn.execute(
        "SELECT ts, kind, payload_json FROM event WHERE engagement_id = ? "
        "ORDER BY ts, id",
        (engagement_id,),
    ).fetchall()
    if events:
        out.append("## Timeline")
        out.append("")
        out.append("| Time (UTC) | Event | Detail |")
        out.append("|---|---|---|")
        for e in events:
            out.append(f"| {e['ts']} | {e['kind']} | {event_summary(e['kind'], e['payload_json'])} |")
        out.append("")

    out.append("---")
    out.append("_Generated by Yhwach. Authorized OSAI / lab use only._")
    return "\n".join(out)
