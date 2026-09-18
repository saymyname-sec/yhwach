"""Render the world model into Obsidian-shaped markdown.

DB is the single source of truth for structured facts; this module regenerates
the *tables* in the engagement notebook from it, so the operator writes only prose
(the why, the payloads, the evidence) and never hand-maintains a host's service /
software / web / user / share tables. `export_notes` writes a notes/ tree the
operator syncs into the vault via the Obsidian MCP.

Every generated section is fenced with `<!-- yhwach:auto:<name> -->` markers so a
future two-way sync can replace just the generated block and leave prose intact.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


def _b(v) -> str:
    return "yes" if v else ""


def _rows(conn, sql, params=()) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


def _wrap(name: str, body: str) -> str:
    return f"<!-- yhwach:auto:{name} -->\n{body}\n<!-- /yhwach:auto:{name} -->"


# --- per-section tables -----------------------------------------------------

def services_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT port, proto, product, version, cpe FROM service "
                       "WHERE host_id=? ORDER BY port", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| Port | Proto | Product | Version | CPE |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['port']} | {r['proto']} | {r['product'] or ''} | "
                   f"{r['version'] or ''} | {r['cpe'] or ''} |")
    return "\n".join(out)


def software_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT name, version, kind, cpe, source FROM software "
                       "WHERE host_id=? ORDER BY kind, name", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| Software | Version | Kind | CPE | Source |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['name']} | {r['version'] or ''} | {r['kind']} | "
                   f"{r['cpe'] or ''} | {r['source'] or ''} |")
    return "\n".join(out)


def vulns_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT cve, title, cvss, state, exploit_ref, exploit_available "
                       "FROM vulnerability WHERE host_id=? ORDER BY state, cvss DESC", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| CVE | Title | CVSS | State | Exploit |", "|---|---|---|---|---|"]
    for r in rows:
        ex = r["exploit_ref"] or ("available" if r["exploit_available"] else "")
        out.append(f"| {r['cve'] or ''} | {r['title'] or ''} | {r['cvss'] or ''} | "
                   f"{r['state']} | {ex} |")
    return "\n".join(out)


def web_table(conn, host_id: int) -> str:
    apps = _rows(conn, "SELECT id, base_url, vhost, server, tech FROM web_app "
                       "WHERE host_id=? ORDER BY base_url", (host_id,))
    if not apps:
        return "_none recorded_"
    blocks = []
    for a in apps:
        head = f"**{a['base_url']}**" + (f" (vhost {a['vhost']})" if a["vhost"] else "")
        meta = " · ".join(x for x in (a["server"], a["tech"]) if x)
        paths = _rows(conn, "SELECT path, method, status, kind, interesting FROM web_path "
                            "WHERE web_app_id=? ORDER BY interesting DESC, path", (a["id"],))
        lines = [head + (f" — {meta}" if meta else "")]
        if paths:
            lines += ["", "| Path | M | Status | Kind | ★ |", "|---|---|---|---|---|"]
            for p in paths:
                star = "★" if p["interesting"] else ""
                lines.append(f"| {p['path']} | {p['method']} | {p['status'] or ''} | "
                             f"{p['kind'] or ''} | {star} |")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def shares_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT name, proto, access, remark FROM share "
                       "WHERE host_id=? ORDER BY name", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| Share | Proto | Access | Remark |", "|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['name']} | {r['proto']} | {r['access'] or ''} | {r['remark'] or ''} |")
    return "\n".join(out)


def host_principals_table(conn, host_id: int) -> str:
    """Local accounts / principals with a privilege ON this host."""
    rows = _rows(conn,
                 "SELECT DISTINCT p.name, p.domain, p.type, pr.right, pr.target "
                 "FROM privilege pr JOIN principal p ON p.id = pr.principal_id "
                 "WHERE pr.host_id=? ORDER BY p.name", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| Principal | Domain | Type | Right | Over |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['name']} | {r['domain'] or ''} | {r['type']} | {r['right']} | "
                   f"{r['target'] or ''} |")
    return "\n".join(out)


def interfaces_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT ip, mac, segment, is_primary FROM host_interface "
                       "WHERE host_id=? ORDER BY is_primary DESC, ip", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| IP | MAC | Segment | Primary |", "|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['ip']} | {r['mac'] or ''} | {r['segment'] or ''} | "
                   f"{_b(r['is_primary'])} |")
    return "\n".join(out)


def loot_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT path, type, contains_secret, summary FROM loot "
                       "WHERE host_id=? ORDER BY id", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| Path | Type | Secret | Summary |", "|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['path'] or ''} | {r['type'] or ''} | {_b(r['contains_secret'])} | "
                   f"{r['summary'] or ''} |")
    return "\n".join(out)


def findings_table(conn, host_id: int) -> str:
    rows = _rows(conn, "SELECT class, title, severity, evidence, tag, status FROM finding "
                       "WHERE host_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                       "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END", (host_id,))
    if not rows:
        return "_none recorded_"
    out = ["| Sev | Class | Title | Tag | Status |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['severity'].upper()} | {r['class']} | {r['title']} | "
                   f"{r['tag'] or ''} | {r['status']} |")
    return "\n".join(out)


# --- whole notes ------------------------------------------------------------

def render_host_note(conn, host_id: int) -> str:
    h = conn.execute("SELECT ip, hostname, os, role, stage FROM host WHERE id=?",
                     (host_id,)).fetchone()
    name = h["hostname"] or h["ip"]
    parts = [
        f"# {name} · `{h['ip']}`",
        f"> Stage: **{h['stage']}** · OS: {h['os'] or '?'} · Role: {h['role'] or '?'}",
        "",
        "## Interfaces", _wrap("interfaces", interfaces_table(conn, host_id)),
        "## Services", _wrap("services", services_table(conn, host_id)),
        "## Software inventory", _wrap("software", software_table(conn, host_id)),
        "## Vulnerabilities", _wrap("vulns", vulns_table(conn, host_id)),
        "## Web", _wrap("web", web_table(conn, host_id)),
        "## SMB / NFS shares", _wrap("shares", shares_table(conn, host_id)),
        "## Principals & privileges (on this host)",
        _wrap("principals", host_principals_table(conn, host_id)),
        "## Loot", _wrap("loot", loot_table(conn, host_id)),
        "## Findings", _wrap("findings", findings_table(conn, host_id)),
        "",
        "## Notes (operator prose — not auto-generated)",
        "_Foothold, PoC, pivot, TODO. Write freely below; the tables above are "
        "regenerated by `yhwach export-notes`._",
    ]
    return "\n\n".join(parts) + "\n"


def render_users_groups(conn, eid: int) -> str:
    prins = _rows(conn, "SELECT id, name, domain, type, flags, spn, enabled FROM principal "
                        "WHERE engagement_id=? ORDER BY type, name", (eid,))
    out = ["# Users & Groups", ""]
    users = [p for p in prins if p["type"] != "group"]
    groups = [p for p in prins if p["type"] == "group"]
    out.append("## Principals")
    if users:
        out += ["| Name | Domain | Type | Flags | SPN | Enabled |", "|---|---|---|---|---|---|"]
        for p in users:
            out.append(f"| {p['name']} | {p['domain'] or ''} | {p['type']} | {p['flags'] or ''} | "
                       f"{p['spn'] or ''} | {_b(p['enabled'])} |")
    else:
        out.append("_none recorded_")
    out += ["", "## Groups & memberships"]
    if groups:
        for g in groups:
            members = _rows(conn, "SELECT p.name FROM membership m "
                                  "JOIN principal p ON p.id=m.member_id WHERE m.group_id=? "
                                  "ORDER BY p.name", (g["id"],))
            mlist = ", ".join(m["name"] for m in members) or "_(no members recorded)_"
            out.append(f"- **{g['name']}** ({g['domain'] or ''}): {mlist}")
    else:
        out.append("_none recorded_")
    out += ["", "## Privileges (domain-wide + per-host)"]
    privs = _rows(conn, "SELECT p.name, pr.right, pr.target, h.ip FROM privilege pr "
                        "JOIN principal p ON p.id=pr.principal_id "
                        "LEFT JOIN host h ON h.id=pr.host_id WHERE pr.engagement_id=? "
                        "ORDER BY p.name", (eid,))
    if privs:
        out += ["| Principal | Right | Over | Host |", "|---|---|---|---|"]
        for r in privs:
            out.append(f"| {r['name']} | {r['right']} | {r['target'] or ''} | {r['ip'] or 'domain'} |")
    else:
        out.append("_none recorded_")
    return "\n".join(out) + "\n"


def render_vulnerabilities(conn, eid: int) -> str:
    rows = _rows(conn, "SELECT h.ip, v.cve, v.title, v.cvss, v.state, v.exploit_ref, "
                       "v.exploit_available FROM vulnerability v JOIN host h ON h.id=v.host_id "
                       "WHERE v.engagement_id=? ORDER BY v.state, v.cvss DESC", (eid,))
    out = ["# Vulnerabilities", ""]
    if not rows:
        out.append("_none recorded_")
        return "\n".join(out) + "\n"
    out += ["| Host | CVE | Title | CVSS | State | Exploit |", "|---|---|---|---|---|---|"]
    for r in rows:
        ex = r["exploit_ref"] or ("available" if r["exploit_available"] else "")
        out.append(f"| {r['ip']} | {r['cve'] or ''} | {r['title'] or ''} | {r['cvss'] or ''} | "
                   f"{r['state']} | {ex} |")
    return "\n".join(out) + "\n"


def render_web_overview(conn, eid: int) -> str:
    apps = _rows(conn, "SELECT wa.id, h.ip, wa.base_url, wa.vhost, wa.server, wa.tech "
                       "FROM web_app wa JOIN host h ON h.id=wa.host_id "
                       "WHERE h.engagement_id=? ORDER BY h.ip, wa.base_url", (eid,))
    out = ["# Web", ""]
    if not apps:
        out.append("_none recorded_")
        return "\n".join(out) + "\n"
    for a in apps:
        out.append(f"## {a['base_url']}" + (f" — vhost {a['vhost']}" if a["vhost"] else ""))
        meta = " · ".join(x for x in (a["server"], a["tech"]) if x)
        if meta:
            out.append(f"_{meta}_")
        interesting = _rows(conn, "SELECT path, status, kind FROM web_path "
                                  "WHERE web_app_id=? AND interesting=1 ORDER BY path", (a["id"],))
        if interesting:
            out += ["", "Interesting paths:", "| Path | Status | Kind |", "|---|---|---|"]
            for p in interesting:
                out.append(f"| {p['path']} | {p['status'] or ''} | {p['kind'] or ''} |")
        out.append("")
    domains = _rows(conn, "SELECT name, type, ip FROM domain WHERE engagement_id=? ORDER BY name",
                    (eid,))
    if domains:
        out += ["## Domains / vhosts", "| Name | Type | IP |", "|---|---|---|"]
        for d in domains:
            out.append(f"| {d['name']} | {d['type']} | {d['ip'] or ''} |")
    return "\n".join(out) + "\n"


def render_services_software(conn, eid: int) -> str:
    out = ["# Services & Software", ""]
    hosts = _rows(conn, "SELECT id, ip, hostname FROM host WHERE engagement_id=? ORDER BY ip",
                  (eid,))
    for h in hosts:
        name = h["hostname"] or h["ip"]
        sw = software_table(conn, h["id"])
        svc = services_table(conn, h["id"])
        if svc == "_none recorded_" and sw == "_none recorded_":
            continue
        out += [f"## {name} · `{h['ip']}`", "### Services", svc, "### Software", sw, ""]
    if len(out) == 2:
        out.append("_none recorded_")
    return "\n".join(out) + "\n"


def render_shares(conn, eid: int) -> str:
    rows = _rows(conn, "SELECT h.ip, s.name, s.proto, s.access, s.remark FROM share s "
                       "JOIN host h ON h.id=s.host_id WHERE h.engagement_id=? "
                       "ORDER BY h.ip, s.name", (eid,))
    out = ["# Shares", ""]
    if not rows:
        out.append("_none recorded_")
        return "\n".join(out) + "\n"
    out += ["| Host | Share | Proto | Access | Remark |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['ip']} | {r['name']} | {r['proto']} | {r['access'] or ''} | "
                   f"{r['remark'] or ''} |")
    return "\n".join(out) + "\n"


def export_notes(conn, eid: int, out_dir: Path | str) -> list[str]:
    """Write the auto-scaffolded notebook tree; return the relative paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    standing = {
        "Services & Software.md": render_services_software(conn, eid),
        "Vulnerabilities.md": render_vulnerabilities(conn, eid),
        "Web.md": render_web_overview(conn, eid),
        "Users & Groups.md": render_users_groups(conn, eid),
        "Shares.md": render_shares(conn, eid),
    }
    for fname, body in standing.items():
        (out / fname).write_text(body, encoding="utf-8")
        written.append(fname)

    hosts_dir = out / "hosts"
    hosts_dir.mkdir(exist_ok=True)
    for h in _rows(conn, "SELECT id, ip, hostname FROM host WHERE engagement_id=? ORDER BY ip",
                   (eid,)):
        name = (h["hostname"] or h["ip"]).replace("/", "_")
        (hosts_dir / f"{name}.md").write_text(render_host_note(conn, h["id"]), encoding="utf-8")
        written.append(f"hosts/{name}.md")
    return written
