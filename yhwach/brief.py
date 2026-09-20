"""yhwach brief — the AI-legible engagement map (read-only over the memory DB).

The single surface the operator reasons over when asked to think: what I can REACH,
what I HOLD, what SURFACES exist, what's UNLOCKS-gated (and by what), what's
UNEXPLORED (the frontier), and the OBJECTIVES. Pure SELECTs — yhwach decides nothing;
the model reads this and finds the path.
"""
from __future__ import annotations

import sqlite3

REACHABLE_STAGES = ("foothold", "looted", "pivoted", "done")
AI_KINDS = {"ollama", "gradio", "openwebui", "chatbot", "rag", "mcp", "a2a", "vectordb"}
SECTIONS = ("reach", "hold", "surfaces", "unlocks", "unexplored", "objectives")


def _rows(conn: sqlite3.Connection, sql: str, params=()) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []


def build_brief(conn: sqlite3.Connection, eng: int, *, section: str | None = None) -> str:
    want = lambda s: section is None or section == s  # noqa: E731
    out: list[str] = [f"# yhwach brief — engagement {eng}", ""]

    if want("reach"):
        hosts = _rows(conn, "SELECT ip, COALESCE(hostname,'') h, COALESCE(os,'') os, stage, "
                      "COALESCE(tags,'') tags FROM host WHERE engagement_id=? "
                      "ORDER BY (stage IN ('foothold','looted','pivoted','done')) DESC, ip", (eng,))
        tuns = _rows(conn, "SELECT t.subnet, t.kind, COALESCE(h.ip,'?') via FROM tunnel t "
                     "LEFT JOIN host h ON h.id=t.via_host_id WHERE t.engagement_id=?", (eng,))
        out += ["## REACH — hosts and how", "| IP | Host | OS | Stage | Tags |",
              "|----|------|----|-------|------|"]
        for r in hosts:
            out.append(f"| {r['ip']} | {r['h']} | {r['os']} | {r['stage']} | {r['tags']} |")
        if tuns:
            out.append("")
            out.append("Tunnels (subnets reachable): " +
                     "; ".join(f"{t['subnet']} via {t['via']} ({t['kind']})" for t in tuns))
        out.append("")

    if want("hold"):
        creds = _rows(conn, "SELECT c.identifier, c.kind, COALESCE(c.source,'') src, "
                      "vh.ip AS validated_on FROM credential c "
                      "LEFT JOIN host vh ON vh.id=c.validated_on_host_id "
                      "WHERE c.engagement_id=? ORDER BY c.id", (eng,))
        out += [f"## HOLD — {len(creds)} credentials/tokens (values via `yhwach creds`)",
              "| Identifier | Kind | Source | Validated on |", "|---|---|---|---|"]
        for c in creds:
            out.append(f"| {c['identifier']} | {c['kind']} | {c['src'][:38]} | "
                     f"{c['validated_on'] or '— untried'} |")
        out.append("")

    if want("surfaces"):
        surf = _rows(conn, "SELECT h.ip, s.kind, COALESCE(s.auth,'?') auth, "
                     "COALESCE(svc.port,'') port FROM surface s JOIN host h ON h.id=s.host_id "
                     "LEFT JOIN service svc ON svc.id=s.service_id WHERE h.engagement_id=? "
                     "ORDER BY h.ip, s.kind", (eng,))
        out += ["## SURFACES — per host (★ = AI target)", "| IP | Surface | Auth | Port |",
              "|----|---------|------|------|"]
        for s in surf:
            star = " ★" if s["kind"] in AI_KINDS else ""
            out.append(f"| {s['ip']} | {s['kind']}{star} | {s['auth']} | {s['port']} |")
        out.append("")

    if want("unlocks"):
        leads = _rows(conn, "SELECT COALESCE(h.ip,'-') ip, f.tag, f.severity, f.title FROM finding f "
                      "LEFT JOIN host h ON h.id=f.host_id WHERE f.engagement_id=? "
                      "AND f.status='open' AND COALESCE(f.tag,'')<>'' ORDER BY f.id", (eng,))
        gated = _rows(conn, "SELECT DISTINCT h.ip, s.kind, s.auth FROM surface s "
                      "JOIN host h ON h.id=s.host_id WHERE h.engagement_id=? "
                      "AND COALESCE(s.auth,'') NOT IN ('','none') "
                      "AND NOT EXISTS (SELECT 1 FROM credential c "
                      "WHERE c.engagement_id=? AND c.validated_on_host_id=h.id) ORDER BY h.ip", (eng, eng))
        out.append("## UNLOCKS — gated targets + live leads")
        for g in gated:
            star = " ★" if g["kind"] in AI_KINDS else ""
            out.append(f"- GATED: {g['ip']} {g['kind']}{star} (auth={g['auth']}) — needs a credential")
        for f in leads:
            out.append(f"- LEAD [{f['severity']}] {f['ip']} `{f['tag']}` — {f['title']}")
        if not gated and not leads:
            out.append("- (none)")
        out.append("")

    if want("unexplored"):
        not_enum = _rows(conn, "SELECT ip, stage FROM host WHERE engagement_id=? "
                         "AND stage IN ('undiscovered','scanned') ORDER BY ip", (eng,))
        unprobed = _rows(conn, "SELECT h.ip, svc.port, COALESCE(svc.product,'') product FROM service svc "
                         "JOIN host h ON h.id=svc.host_id LEFT JOIN surface s ON s.service_id=svc.id "
                         "WHERE h.engagement_id=? AND s.id IS NULL ORDER BY h.ip, svc.port", (eng,))
        no_fullport = _rows(conn, "SELECT ip FROM host WHERE engagement_id=? AND id NOT IN "
                            "(SELECT host_id FROM scan_coverage WHERE proto='tcp' AND full_range=1) "
                            "AND stage NOT IN ('undiscovered') ORDER BY ip", (eng,))
        shares = _rows(conn, "SELECT h.ip, sh.name, COALESCE(sh.access,'?') access FROM share sh "
                       "JOIN host h ON h.id=sh.host_id WHERE h.engagement_id=? ORDER BY h.ip", (eng,))
        untried = _rows(conn, "SELECT identifier, kind FROM credential WHERE engagement_id=? "
                        "AND validated_on_host_id IS NULL ORDER BY id", (eng,))
        out.append("## UNEXPLORED — the frontier (what's left to discover)")
        if not_enum:
            out.append("- Not yet enumerated: " + ", ".join(f"{r['ip']}({r['stage']})" for r in not_enum))
        if no_fullport:
            out.append("- No full-port scan on record: " + ", ".join(r["ip"] for r in no_fullport))
        if unprobed:
            out.append("- Unprobed services: " +
                     ", ".join(f"{r['ip']}:{r['port']} {r['product']}".strip() for r in unprobed[:40]))
        if shares:
            out.append("- Shares to read/loot: " +
                     ", ".join(f"{r['ip']}/{r['name']}({r['access']})" for r in shares[:40]))
        if untried:
            out.append("- Untried creds (spray): " +
                     ", ".join(f"{r['identifier']}({r['kind']})" for r in untried[:40]))
        if not any((not_enum, no_fullport, unprobed, shares, untried)):
            out.append("- (frontier clear — everything reachable has been enumerated)")
        out.append("")

    if want("objectives"):
        objs = _rows(conn, "SELECT o.label, o.captured, COALESCE(o.points,0) points, "
                     "COALESCE(h.ip,'-') ip FROM objective o LEFT JOIN host h ON h.id=o.host_id "
                     "WHERE o.engagement_id=? ORDER BY o.id", (eng,))
        if objs:
            cap = sum(1 for o in objs if o["captured"])
            out.append(f"## OBJECTIVES — {cap}/{len(objs)} captured")
            for o in objs:
                mark = "x" if o["captured"] else " "
                out.append(f"- [{mark}] {o['label']} ({o['ip']})" +
                         (f" · {o['points']}pts" if o["points"] else ""))
            out.append("")

    return "\n".join(out).rstrip() + "\n"
