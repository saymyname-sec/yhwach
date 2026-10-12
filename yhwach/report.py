"""Engagement report generation: world model -> Markdown.

Builds a report from the authoritative state (hosts / services / surfaces /
findings / proofs). Reports must copy-paste reproduce, so findings carry
their evidence and the rendered command lives in the task/action layer.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime

from yhwach.dossier import md

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
    out.append(f"# Yhwach Engagement Report — {md(eng['lab'])}")
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
        "WHERE engagement_id = ? AND status IN ('open','confirmed','exploited') GROUP BY severity",
        (engagement_id,),
    ).fetchall()
    sev_map = {r["severity"]: r["n"] for r in sev_counts}

    out.append("## Scoreboard")
    out.append("")
    out.append("| Stage | Hosts |")
    out.append("|---|---|")
    for r in stages:
        out.append(f"| {md(r['stage'])} | {md(r['n'])} |")
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
        "WHERE f.engagement_id = ? AND f.status IN ('open','confirmed','exploited') "
        f"ORDER BY {_SEV_ORDER}, f.id",
        (engagement_id,),
    ).fetchall()
    out.append("## Findings")
    out.append("")
    if not findings:
        out.append("_None recorded._")
    else:
        for f in findings:
            out.append(f"### [{md(f['severity'].upper())}] {md(f['class'])} — {md(f['title'])}")
            out.append(f"- **Host:** {md(f['ip'] or '-')}")
            if f["evidence"]:
                out.append(f"- **Evidence:** {md(f['evidence'])}")
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
                f"{md(s['port'])}/{md(s['proto'])} {md(s['product'] or '')}{(' ' + s['version']) if s['version'] else ''}".strip()
                for s in svcs
            ))
        surfs = conn.execute(
            "SELECT kind, auth FROM surface WHERE host_id = ? ORDER BY kind", (h["id"],)
        ).fetchall()
        if surfs:
            out.append("- **Surfaces:** " + ", ".join(f"{s['kind']}({s['auth']})" for s in surfs))
        hfnd = conn.execute(
            "SELECT class, title, severity FROM finding WHERE host_id = ? AND status IN ('open','confirmed','exploited') "
            f"ORDER BY {_SEV_ORDER}",
            (h["id"],),
        ).fetchall()
        if hfnd:
            for f in hfnd:
                out.append(f"- **Finding:** [{md(f['severity'].upper())}] {md(f['class'])} {md(f['title'])}")
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
            out.append(f"| {md(t['subnet'])} | {md(t['via_ip'] or '-')} | {md(t['kind'])} |")
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
            out.append(f"| {md(a['attempted_at'])} | {md(a['ip'] or '-')} | {md(a['rule_id'] or '-')} | "
                       f"{md(a['result'])} | {md(a['reason'] or '')} |")
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
            out.append(f"| {md(e['ts'])} | {md(e['kind'])} | {event_summary(e['kind'], e['payload_json'])} |")
        out.append("")

    out.append("---")
    out.append("_Generated by Yhwach. Authorized engagement use only._")
    return "\n".join(out)


# --- I13 readiness gate -----------------------------------------------------
# `yhwach report --check`: block a write-up that is not reproducible. Phased on
# today's columns (evidence, PoC steps, placeholders, secrets) plus the ledger
# QA rules; CVSS/remediation checks are intentionally out (report generation is
# not yhwach's job — it keeps the memory the operator writes from).
_PLACEHOLDER = re.compile(r"\$[A-Z][A-Z0-9_]{2,}|<[A-Z][A-Z0-9_ ]+>|\bTODO\b|\bCHANGEME\b|\bFIXME\b")


def report_check(conn: sqlite3.Connection, engagement_id: int) -> list[tuple[str, str]]:
    """Return (level, message) readiness problems. level is 'fail' (blocking) or
    'warn'. An empty list means the memory is report-ready."""
    from yhwach import db as yhdb
    from yhwach import poc as pocmod

    out: list[tuple[str, str]] = []

    # 1. A proven finding with no evidence cannot be reproduced.
    for r in conn.execute(
        "SELECT f.id, f.title FROM finding f WHERE f.engagement_id=? "
        "AND f.status IN ('confirmed','exploited') "
        "AND NOT EXISTS (SELECT 1 FROM evidence_link l WHERE l.finding_id=f.id)",
        (engagement_id,),
    ).fetchall():
        out.append(("fail", f"finding #{r['id']} '{r['title']}' is proven but has no evidence"))

    # 2. Evidence flagged as holding a secret — redact before it ships to a client.
    for r in conn.execute(
        "SELECT id, caption FROM evidence WHERE engagement_id=? AND contains_secret=1",
        (engagement_id,),
    ).fetchall():
        out.append(("fail", f"evidence #{r['id']} ({r['caption'] or 'secret inline'}) "
                            "holds a secret — redact before export"))

    # 3. Placeholder left in a PoC step — not reproducible as written.
    for ev in conn.execute(
        "SELECT payload_json FROM event WHERE engagement_id=? AND kind='poc_step'",
        (engagement_id,),
    ).fetchall():
        try:
            p = json.loads(ev["payload_json"])
        except (ValueError, TypeError):
            continue
        blob = f"{p.get('command','')}\n{p.get('output','')}"
        m = _PLACEHOLDER.search(blob)
        if m:
            out.append(("fail", f"PoC '{p.get('objective_label', p.get('objective'))}' "
                                f"step {p.get('seq','?')} has a placeholder: {m.group(0)}"))

    # 4. A captured objective with no reproducible chain.
    for r in conn.execute(
        "SELECT label FROM objective WHERE engagement_id=? AND COALESCE(captured,0)=1",
        (engagement_id,),
    ).fetchall():
        if not pocmod.steps_for(conn, engagement_id, r["label"]):
            out.append(("warn", f"captured objective '{r['label']}' has no recorded PoC steps"))

    # 5. Ledger QA rules (G4a / I39).
    for r in yhdb.uncommunicated_critical_findings(conn, engagement_id):
        out.append(("fail", f"critical finding #{r['id']} '{r['title']}' not communicated "
                            "(record a notice)"))
    outstanding = yhdb.outstanding_artifacts(conn, engagement_id)
    if outstanding:
        out.append(("warn", f"{len(outstanding)} artefact(s) not confirmed removed — "
                            "not clean to close"))
    return out
