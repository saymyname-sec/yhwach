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
SECTIONS = ("reach", "hold", "surfaces", "unlocks", "unexplored", "objectives", "lessons")


def _rows(conn: sqlite3.Connection, sql: str, params=()) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []


def _more(total: int, limit: int, sect: str, extra: str = "") -> str | None:
    """Footer line when a list was capped, naming the slice call to see the rest."""
    if total <= limit:
        return None
    return (f"- … +{total - limit} more not shown{extra} — "
            f"ask for the slice: brief(section='{sect}')")


def build_brief(conn: sqlite3.Connection, eng: int, *, section: str | None = None,
                limit: int = 60, stage: str | None = None) -> str:
    want = lambda s: section is None or section == s  # noqa: E731
    out: list[str] = [f"# yhwach brief — engagement {eng}", ""]

    if want("reach"):
        # Started hosts (anything past 'undiscovered') first and in full up to
        # the cap; bare scope placeholders are counted, not dumped — a /24
        # materialises 254 'undiscovered' rows that would otherwise bury the
        # map and blow the model's context on the first call.
        q = ("SELECT ip, COALESCE(hostname,'') h, COALESCE(os,'') os, stage, "
             "COALESCE(tags,'') tags FROM host WHERE engagement_id=? ")
        params: list = [eng]
        if stage:
            q += "AND stage=? "
            params.append(stage)
        q += "ORDER BY (stage IN ('foothold','looted','pivoted','done')) DESC, (stage='undiscovered'), ip"
        hosts = _rows(conn, q, tuple(params))
        placeholders = sum(1 for r in hosts if r["stage"] == "undiscovered")
        # Undiscovered scope placeholders are counted, not dumped — unless the
        # caller explicitly asked for that stage.
        shown = hosts if stage else [r for r in hosts if r["stage"] != "undiscovered"]
        tuns = _rows(conn, "SELECT t.subnet, t.kind, COALESCE(h.ip,'?') via FROM tunnel t "
                     "LEFT JOIN host h ON h.id=t.via_host_id WHERE t.engagement_id=?", (eng,))
        out += ["## REACH — hosts and how", "| IP | Host | OS | Stage | Tags |",
              "|----|------|----|-------|------|"]
        for r in shown[:limit]:
            out.append(f"| {r['ip']} | {r['h']} | {r['os']} | {r['stage']} | {r['tags']} |")
        more = _more(len(shown), limit, "reach")
        if more:
            out.append(more)
        if placeholders and not stage:
            out.append(f"- ({placeholders} undiscovered scope placeholders not shown — "
                       f"brief(section='reach', stage='undiscovered'))")
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
        for c in creds[:limit]:
            out.append(f"| {c['identifier']} | {c['kind']} | {c['src'][:38]} | "
                     f"{c['validated_on'] or '— untried'} |")
        more = _more(len(creds), limit, "hold")
        if more:
            out.append(more)
        out.append("")

    if want("surfaces"):
        surf = _rows(conn, "SELECT h.ip, s.kind, COALESCE(s.auth,'?') auth, "
                     "COALESCE(svc.port,'') port FROM surface s JOIN host h ON h.id=s.host_id "
                     "LEFT JOIN service svc ON svc.id=s.service_id WHERE h.engagement_id=? "
                     "ORDER BY h.ip, s.kind", (eng,))
        out += ["## SURFACES — per host (★ = AI target)", "| IP | Surface | Auth | Port |",
              "|----|---------|------|------|"]
        for s in surf[:limit]:
            star = " ★" if s["kind"] in AI_KINDS else ""
            out.append(f"| {s['ip']} | {s['kind']}{star} | {s['auth']} | {s['port']} |")
        more = _more(len(surf), limit, "surfaces")
        if more:
            out.append(more)
        out.append("")

    if want("unlocks"):
        leads = _rows(conn, "SELECT COALESCE(h.ip,'-') ip, f.tag, f.severity, f.title FROM finding f "
                      "LEFT JOIN host h ON h.id=f.host_id WHERE f.engagement_id=? "
                      "AND f.status IN ('open','confirmed','exploited') AND COALESCE(f.tag,'')<>'' ORDER BY f.id", (eng,))
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

    if want("lessons"):
        # Past-lab knowledge, keyed on trigger_tag — pulled in whenever a host
        # carries a matching finding tag or surface kind (the "lessons memory"
        # AGENT.md describes; previously queryable only via `yhwach ref lessons`).
        from yhwach.reference import lessons_for

        tags: set[str] = set()
        for r in _rows(conn, "SELECT DISTINCT tag FROM finding WHERE engagement_id=? "
                       "AND COALESCE(tag,'')<>'' AND status IN ('open','confirmed','exploited')",
                       (eng,)):
            tags.add(r["tag"])
        for r in _rows(conn, "SELECT DISTINCT s.kind FROM surface s JOIN host h ON h.id=s.host_id "
                       "WHERE h.engagement_id=?", (eng,)):
            tags.add(r["kind"])
        hits = lessons_for(tags)
        if hits:
            out.append("## LESSONS — past-lab knowledge for the tags in play")
            for les in hits:
                trig = ", ".join(les.get("trigger_tag", []) or [])
                out.append(f"- [{trig}] {les.get('lesson', '')}")
            out.append("")
        elif section == "lessons":
            out += ["## LESSONS", "- (no lessons match the current tags)", ""]

    return "\n".join(out).rstrip() + "\n"
