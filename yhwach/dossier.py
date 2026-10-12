"""Dossier: the per-host briefing, composed offline.

What this box *is*, what is known about each surface kind on it, and what is
still dark — for the stage the host is actually in.

**It needs no model.** Every line is either a fact from a DB row or a verbatim
quote from a shipped YAML pack, so it works with no API key, no network and
nothing installed beyond the base package. That matters: the project's primary
mode is Claude Code over MCP with no key at all. An optional LLM annotation can
be layered on top later (design §5.4); the deterministic dossier is the product,
not a fallback.

It is an information surface, not a recommender. It says what a redis surface IS
and what is typically worth looking at on one. It never ranks a technique, scores
a move, or tells the operator what to run next.

Pure reads. Returns markdown; the caller renders it.

See docs/design-ui-information-surface.md §5.
"""
from __future__ import annotations

import sqlite3

from yhwach import db as yhdb
from yhwach.coverage import started_gaps
from yhwach.reference import _load, lessons_for

# The real FSM (db.STAGES): undiscovered, scanned, enumerated, foothold, looted,
# pivoted, done. Each stage has a different information need; a section not
# listed for a stage is simply not composed.
_SECTIONS: dict[str, tuple[str, ...]] = {
    "undiscovered": ("identity",),
    "scanned": ("identity", "services", "kinds", "coverage", "dark"),
    "enumerated": ("identity", "services", "kinds", "web", "leads", "lessons", "coverage", "dark"),
    "foothold": ("identity", "access", "services", "kinds", "web", "leads", "loot", "lessons",
                 "reach", "dark"),
    "looted": ("identity", "access", "loot", "creds", "web", "leads", "lessons", "reach", "dark"),
    "pivoted": ("identity", "access", "reach", "loot", "creds", "leads", "dark"),
    "done": ("identity", "access", "proof", "loot", "leads"),
}
_DEFAULT_SECTIONS = _SECTIONS["enumerated"]


# Exactly the metacharacters `_md_to_html` interprets, and no more. Escaping
# anything else only adds backslashes to identifiers like `rag_poisoning`, which
# also travel to Claude Code over the MCP wire.
_MD_META = str.maketrans({"|": r"\|", "`": r"\`", "*": r"\*"})


def md(v) -> str:
    """A DB value, safe to interpolate into composed markdown.

    The renderer cannot tell author markup from data, so neutralise here. A
    newline in a scanned banner or a finding's evidence would otherwise inject
    new *lines* of markdown — a target could forge a whole '## Objectives
    captured' section, complete with a pipe table, into the dossier or the
    write-up. Escaping alone does not stop that: the output is valid, escaped
    HTML that simply says something untrue.
    """
    if v is None:
        return ""
    out = " ".join(str(v).split())            # collapse every newline and tab
    out = out.translate(_MD_META)
    return out.lstrip("#>-+ ") if out[:1] in "#>-+" else out


def _host(conn: sqlite3.Connection, eid: int, ip: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, ip, COALESCE(hostname,'') hostname, COALESCE(os,'') os, "
        "COALESCE(role,'') role, stage, COALESCE(discovery_source,'') discovery_source "
        "FROM host WHERE engagement_id=? AND ip=?",
        (eid, ip),
    ).fetchone()


def _kinds_for_host(conn: sqlite3.Connection, host_id: int) -> list[str]:
    """Surface kinds on a host, falling back to classifying its services.

    Surfaces are written by `yhwach probe`; a freshly ingested host has services
    and no surfaces at all. Briefing only on surfaces meant a scanned Domain
    Controller — ldap on 389, smb on 445, both classifiable from the port alone —
    got no context until someone ran a probe.
    """
    kinds = {r["kind"] for r in conn.execute(
        "SELECT DISTINCT kind FROM surface WHERE host_id=?", (host_id,))}
    if kinds:
        return sorted(kinds)
    try:
        from yhwach.probes.traditional import PORT_KIND
    except ImportError:  # pragma: no cover
        return []
    rows = conn.execute(
        "SELECT port, COALESCE(product,'') product FROM service WHERE host_id=?", (host_id,))
    by_port, by_product = {}, {}
    for entry in _load("services"):
        for prt in entry.get("tcp_ports") or []:
            by_port.setdefault(prt, entry["kind"])
        for alias in [entry["kind"], *(entry.get("aka") or [])]:
            by_product[str(alias).lower()] = entry["kind"]
    for r in rows:
        k = by_port.get(r["port"]) or PORT_KIND.get(r["port"])
        if not k and r["product"]:
            prod = r["product"].lower()
            k = next((v for a, v in by_product.items() if a and a in prod), None)
        if k:
            kinds.add(k)
    return sorted(kinds)


def _service_matrix_row(kind: str) -> dict | None:
    """Look the kind up by EXACT match.

    `reference.render_pack` substring-matches across every value of an entry, so
    it both over-matches and silently returns nothing for several real kinds.
    Never use it for this.
    """
    for entry in _load("services"):
        if str(entry.get("kind", "")).lower() == kind.lower():
            return entry
    return None


def _ai_attacks_for(kind: str) -> list[dict]:
    topic = {"chatbot": "prompt_injection", "rag": "rag_poisoning", "mcp": "mcp_attack",
             "a2a": "a2a_attack", "vectordb": "vector_db"}.get(kind.lower())
    if not topic:
        return []
    return [e for e in _load("ai-attacks") if e.get("topic") in (topic, "owasp_llm_checklist")]


def _tag_notes(tags) -> list[dict]:
    want = {str(t).lower() for t in tags if t}
    if not want:
        return []
    return [e for e in _load("tags") if str(e.get("tag", "")).lower() in want]


def build(conn: sqlite3.Connection, engagement_id: int, host_ip: str) -> str:
    """Compose the dossier for one host. Returns markdown ('' if no such host)."""
    h = _host(conn, engagement_id, host_ip)
    if h is None:
        return ""
    stage = h["stage"]
    want = _SECTIONS.get(stage, _DEFAULT_SECTIONS)
    out: list[str] = []

    surfaces = conn.execute(
        "SELECT u.kind, COALESCE(u.auth,'unknown') auth, COALESCE(s.port,0) port "
        "FROM surface u LEFT JOIN service s ON s.id=u.service_id "
        "WHERE u.host_id=? ORDER BY s.port, u.kind",
        (h["id"],),
    ).fetchall()
    kinds = _kinds_for_host(conn, h["id"])

    # ---- identity ---------------------------------------------------------
    if "identity" in want:
        bits = [f"`{md(h['ip'])}`"]
        if h["hostname"]:
            bits.append(md(h["hostname"]))
        if h["os"]:
            bits.append(md(h["os"]))
        if h["role"]:
            bits.append(md(h["role"]))
        out += ["## What this box is", "- " + " · ".join(bits),
                f"- Stage **{stage}**"
                + (f", discovered via `{md(h['discovery_source'])}`" if h["discovery_source"] else "")]
        tags = yhdb.tags_for_hosts(conn, engagement_id).get(h["id"], [])
        if tags:
            out.append("- Tagged " + ", ".join(f"`{md(t)}`" for t in tags))
        out.append("")

    # ---- services ---------------------------------------------------------
    if "services" in want:
        svc = conn.execute(
            "SELECT s.port, COALESCE(s.proto,'tcp') proto, COALESCE(s.product,'') product, "
            "COALESCE(s.version,'') version, "
            "(SELECT sw.version FROM software sw WHERE sw.service_id=s.id "
            "   AND COALESCE(sw.version,'')<>'' LIMIT 1) sw_version "
            "FROM service s WHERE s.host_id=? ORDER BY s.port",
            (h["id"],),
        ).fetchall()
        out.append("## What is listening")
        if svc:
            for r in svc:
                ver = r["version"] or r["sw_version"] or ""
                out.append(f"- `{md(r['port'])}/{md(r['proto'])}` {md(r['product']) or '(unidentified)'}"
                           + (f" {md(ver)}" if ver else " — no version recovered"))
        else:
            out.append("- nothing recorded")
        out.append("")

    # ---- what each surface kind IS ---------------------------------------
    if "kinds" in want and kinds:
        out.append("## What these surfaces are")
        if not surfaces:
            out.append("*(classified from the open ports — no probe has run on this host yet)*")
        for kind in kinds:
            row = _service_matrix_row(kind)
            if row is None:
                out.append(f"- **{md(kind)}** — no service-matrix row for this kind")
                continue
            line = f"- **{md(kind)}**"
            if row.get("taxonomy"):
                line += " (" + ", ".join(str(t) for t in row["taxonomy"]) + ")"
            out.append(line)
            if row.get("enum_ref"):
                out.append(f"  - {md(row['enum_ref'])}")
            if row.get("default_creds"):
                out.append("  - ships with default credentials worth checking")
            if row.get("cve_products"):
                out.append("  - version maps to CVEs for: "
                           + ", ".join(f"`{p}`" for p in row["cve_products"]))
            for entry in _ai_attacks_for(kind):
                if entry.get("summary"):
                    out.append(f"  - *{md(entry['topic'])}*: {md(entry['summary'])}")
        out.append("")

    # ---- web --------------------------------------------------------------
    if "web" in want:
        apps = conn.execute(
            "SELECT w.id, w.base_url, COALESCE(w.vhost,'') vhost, COALESCE(w.title,'') title, "
            "COALESCE(w.server,'') server, COALESCE(w.tech,'') tech "
            "FROM web_app w WHERE w.host_id=? ORDER BY w.base_url",
            (h["id"],),
        ).fetchall()
        if apps:
            out.append("## Web")
            for a in apps:
                meta = " · ".join(x for x in (a["title"], a["server"], a["tech"]) if x)
                out.append(f"- `{md(a['base_url'])}`" + (f" — {md(meta)}" if meta else ""))
                paths = conn.execute(
                    "SELECT path, status, COALESCE(kind,'') kind, COALESCE(params,'') params "
                    "FROM web_path WHERE web_app_id=? ORDER BY interesting DESC, path LIMIT 12",
                    (a["id"],),
                ).fetchall()
                for p in paths:
                    bit = f"  - `{md(p['path'])}` {md(p['status'])}"
                    if p["kind"]:
                        bit += f" [{md(p['kind'])}]"
                    if p["params"]:
                        bit += f" — params: `{md(p['params'])}`"
                    out.append(bit)
            out.append("")

    # ---- access -----------------------------------------------------------
    if "access" in want:
        creds = conn.execute(
            "SELECT identifier, kind FROM credential "
            "WHERE engagement_id=? AND validated_on_host_id=? ORDER BY identifier",
            (engagement_id, h["id"]),
        ).fetchall()
        privs = conn.execute(
            "SELECT COALESCE(p.name,'(unknown)') who, v.right, COALESCE(v.target,'') target "
            "FROM privilege v LEFT JOIN principal p ON p.id=v.principal_id "
            "WHERE v.host_id=? ORDER BY p.name, v.right",
            (h["id"],),
        ).fetchall()
        out.append("## What we hold here")
        if creds:
            for c in creds:
                out.append(f"- `{md(c['identifier'])}` ({md(c['kind'])}) proven on this host")
        if privs:
            for p in privs:
                out.append(f"- `{md(p['who'])}` holds `{md(p['right'])}`"
                           + (f" over {md(p['target'])}" if p["target"] else ""))
        if not creds and not privs:
            out.append("- no credential proven and no privilege recorded here")
        out.append("")

    # ---- open leads + what the tags mean ---------------------------------
    if "leads" in want:
        finds = conn.execute(
            "SELECT severity, title, COALESCE(tag,'') tag FROM finding "
            "WHERE host_id=? AND status IN ('open','confirmed','exploited') "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, id",
            (h["id"],),
        ).fetchall()
        out.append("## Open leads")
        if finds:
            for f in finds:
                out.append(f"- [{md(f['severity'])}] {md(f['title'])}"
                           + (f" `{md(f['tag'])}`" if f["tag"] else ""))
            for note in _tag_notes({f["tag"] for f in finds if f["tag"]}):
                out.append(f"  - `{md(note['tag'])}` — {md(note.get('note', ''))}")
        else:
            out.append("- none open")
        out.append("")

    # ---- past-lab lessons -------------------------------------------------
    if "lessons" in want:
        tagset = {r["kind"] for r in surfaces} | {
            r["tag"] for r in conn.execute(
                "SELECT COALESCE(tag,'') tag FROM finding WHERE host_id=? "
                "AND status IN ('open','confirmed','exploited')", (h["id"],))
            if r["tag"]}
        hits = lessons_for(tagset)
        if hits:
            out.append("## Past-lab lessons that match this host")
            for lesson in hits:
                maps = " (" + ", ".join(lesson.get("maps", [])) + ")" if lesson.get("maps") else ""
                out.append(f"- {md(lesson.get('lesson', ''))}{md(maps)}")
            out.append("")

    # ---- loot / creds / reach / proof -------------------------------------
    if "loot" in want:
        loot = conn.execute(
            "SELECT COALESCE(path,'') path, COALESCE(type,'') type, "
            "COALESCE(local_path,'') local_path, COALESCE(summary,'') summary "
            "FROM loot WHERE host_id=? ORDER BY id", (h["id"],)).fetchall()
        if loot:
            out.append("## Loot taken from here")
            for lo in loot:
                saved = "" if lo["local_path"] else "  *(not saved locally)*"
                out.append(f"- `{md(lo['path'])}` {md(lo['type'])}{saved}"
                           + (f" — {md(lo['summary'])}" if lo["summary"] else ""))
            out.append("")

    if "creds" in want:
        src = conn.execute(
            "SELECT identifier, kind FROM credential WHERE source_host_id=? ORDER BY identifier",
            (h["id"],)).fetchall()
        if src:
            out.append("## Credentials that came off this box")
            for c in src:
                tried = conn.execute(
                    "SELECT COUNT(*) n FROM credential_access ca JOIN credential c2 "
                    "ON c2.id=ca.credential_id WHERE c2.identifier=? AND c2.engagement_id=?",
                    (c["identifier"], engagement_id)).fetchone()["n"]
                out.append(f"- `{md(c['identifier'])}` ({md(c['kind'])}) — tried against {tried} host/port "
                           f"pair(s) so far")
            out.append("")

    if "reach" in want:
        tunnels = conn.execute(
            "SELECT subnet, COALESCE(kind,'') kind FROM tunnel "
            "WHERE engagement_id=? AND via_host_id=? ORDER BY subnet",
            (engagement_id, h["id"])).fetchall()
        ifaces = conn.execute(
            "SELECT ip, COALESCE(segment,'') segment FROM host_interface WHERE host_id=? "
            "ORDER BY ip", (h["id"],)).fetchall()
        if tunnels or ifaces:
            out.append("## What this host reaches")
            for t in tunnels:
                inside, _owned = yhdb.hosts_in_subnet(conn, engagement_id, t["subnet"])
                out.append(f"- `{md(t['subnet'])}` via {md(t['kind']) or 'tunnel'} — "
                           f"{inside} host(s) known inside")
            for i in ifaces:
                out.append(f"- interface `{md(i['ip'])}`"
                           + (f" on `{md(i['segment'])}`" if i["segment"] else ""))
            out.append("")

    if "proof" in want:
        objs = conn.execute(
            "SELECT label, captured, points FROM objective WHERE host_id=? ORDER BY label",
            (h["id"],)).fetchall()
        if objs:
            out.append("## Objectives on this host")
            for o in objs:
                mark = "captured" if o["captured"] else "outstanding"
                out.append(f"- {md(o['label'])} — {mark}"
                           + (f", {o['points']}pts" if o["points"] else ""))
            out.append("")

    # ---- what is still dark ----------------------------------------------
    if "coverage" in want or "dark" in want:
        try:
            gaps = [g for g in started_gaps(conn, engagement_id) if g.ip == h["ip"]]
        except Exception:  # noqa: BLE001 — a coverage error must not break the dossier
            gaps = []
        out.append("## What is still dark here")
        if gaps:
            for cov in gaps:
                for g in cov.gaps:
                    out.append(f"- {md(g.detail)}")
                    out.append(f"  - `{md(g.fix)}`")
        else:
            out.append("- enumeration of record is complete for this host")
        untriaged = [r["kind"] for r in surfaces if not conn.execute(
            "SELECT 1 FROM finding WHERE host_id=? AND COALESCE(tag,'')<>'' "
            "AND status IN ('open','confirmed','exploited') LIMIT 1",
            (h["id"],)).fetchone()]
        if untriaged:
            out.append("- no tagged finding on this host yet, so nothing has chained off it")
        out.append("")

    return "\n".join(out).rstrip() + "\n"
