"""Engagement notebook: record notes at every objective, render Obsidian Markdown.

Kapi's rule: take notes every time we reach the next objective. A note is not an
afterthought — it is the deliverable. Each note carries, where it applies:

  * the **attack chain** that led here (assembled from the event timeline),
  * reproducible **instructions**,
  * the exact **PoC** (command / payload),
  * **evidence** (captured output),
  * a **screenshot** reference.

Notes live in the `note` table (see schema.sql) and render to per-host Markdown
files plus an index + an attack-chains page, laid out for an Obsidian vault:

    <lab>/notes/
        INDEX.md            — scoreboard + wikilinks to every host note
        attack-chains.md    — the chained kill-path across hosts
        <HOSTNAME>.md       — one note file per host (frontmatter + sections)

The renderer is deterministic: it is a pure projection of the world model + the
`note` rows, so re-running `yhwach note render` always reproduces the notebook.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Categories a note can carry. Order here is the order sections render in.
CATEGORIES = ("attack_chain", "instructions", "poc", "evidence", "loot", "recon", "screenshot")

_SEV_ORDER = ("critical", "high", "medium", "low")
_SEV_SQL = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "note"


def ensure_note_table(conn: sqlite3.Connection) -> None:
    """Create the `note` table if the DB predates it (idempotent migration)."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS note (
            id              INTEGER PRIMARY KEY,
            engagement_id   INTEGER NOT NULL REFERENCES engagement(id),
            host_id         INTEGER REFERENCES host(id),
            objective       TEXT    NOT NULL,
            category        TEXT    NOT NULL,
            title           TEXT    NOT NULL,
            body            TEXT    NOT NULL DEFAULT '',
            command         TEXT,
            output          TEXT,
            screenshot_path TEXT,
            tags            TEXT,
            created_at      TEXT    NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_note_host "
                 "ON note(engagement_id, host_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_note_objective "
                 "ON note(engagement_id, objective)")


def host_id_for(conn: sqlite3.Connection, engagement_id: int, ip: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM host WHERE engagement_id = ? AND ip = ?", (engagement_id, ip)
    ).fetchone()
    return row["id"] if row else None


def record_note(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_id: int | None,
    objective: str,
    category: str,
    title: str,
    body: str = "",
    command: str | None = None,
    output: str | None = None,
    screenshot_path: str | None = None,
    tags: str | None = None,
    dedupe: bool = True,
) -> tuple[int, bool]:
    """Insert a note. Returns (note_id, created).

    With dedupe=True (default) a note with the same (host, objective, category,
    title) is updated in place rather than duplicated — so re-running an
    auto-note on the same milestone refreshes it instead of piling up.
    """
    ensure_note_table(conn)
    if category not in CATEGORIES:
        category = "evidence"
    # Trim oversized evidence so the notebook stays readable; full dumps belong in loot/.
    if output and len(output) > 6000:
        output = output[:6000] + "\n… [truncated — full capture in loot/]"

    if dedupe:
        existing = conn.execute(
            "SELECT id FROM note WHERE engagement_id = ? AND host_id IS ? "
            "AND objective = ? AND category = ? AND title = ?",
            (engagement_id, host_id, objective, category, title),
        ).fetchone()
        if existing is not None:
            conn.execute(
                "UPDATE note SET body = ?, command = ?, output = ?, "
                "screenshot_path = COALESCE(?, screenshot_path), tags = ?, created_at = ? "
                "WHERE id = ?",
                (body, command, output, screenshot_path, tags, _now(), existing["id"]),
            )
            return int(existing["id"]), False

    cur = conn.execute(
        "INSERT INTO note (engagement_id, host_id, objective, category, title, body, "
        "command, output, screenshot_path, tags, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, objective, category, title, body,
         command, output, screenshot_path, tags, _now()),
    )
    return int(cur.lastrowid), True


# ---------------------------------------------------------------------------
# Auto-note: assemble a milestone note from the world model when an objective
# is reached. Called from the `advance` CLI path.
# ---------------------------------------------------------------------------

_STAGE_HEADLINE = {
    "scanned": "Host discovered and scanned",
    "enumerated": "Services enumerated",
    "foothold": "Foothold established — code execution / access on the host",
    "looted": "Host looted — credentials / secrets / flags recovered",
    "pivoted": "Pivot established — using this host to reach a new segment",
    "done": "Host fully owned",
    "blocked": "Host blocked — no path found for now",
}


def _host_row(conn: sqlite3.Connection, host_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, ip, hostname, os, role, stage, tags FROM host WHERE id = ?", (host_id,)
    ).fetchone()


def _timeline(conn: sqlite3.Connection, engagement_id: int, ip: str) -> list[str]:
    """Build a human timeline for a host from the append-only event log."""
    rows = conn.execute(
        "SELECT ts, kind, payload_json FROM event WHERE engagement_id = ? ORDER BY ts, id",
        (engagement_id,),
    ).fetchall()
    line: list[str] = []
    for r in rows:
        try:
            payload = json.loads(r["payload_json"])
        except (ValueError, TypeError):
            payload = {}
        # Keep events that mention this host, plus credential/finding events.
        touches = payload.get("host") == ip or payload.get("ip") == ip
        if r["kind"] == "stage" and touches:
            line.append(f"- `{r['ts']}` **stage → {payload.get('stage','?')}**")
        elif r["kind"] == "credential" and (touches or not payload.get("host")):
            line.append(f"- `{r['ts']}` credential recovered: "
                        f"`{payload.get('id','?')}` ({payload.get('kind','?')}, {payload.get('source','?')})")
        elif r["kind"] == "finding" and touches:
            line.append(f"- `{r['ts']}` finding: {payload.get('title', payload.get('class','?'))}")
        elif r["kind"] == "note" and touches:
            line.append(f"- `{r['ts']}` note: {payload.get('title','?')}")
    return line


def auto_note_stage(
    conn: sqlite3.Connection,
    engagement_id: int,
    host_ip: str,
    stage: str,
) -> int | None:
    """Generate/refresh the milestone attack-chain note for a host reaching `stage`.

    Pulls the host's current findings, credentials sourced from it, services and
    surfaces, and the event timeline, into one Obsidian-ready attack_chain note.
    """
    ensure_note_table(conn)
    host_id = host_id_for(conn, engagement_id, host_ip)
    if host_id is None:
        return None
    h = _host_row(conn, host_id)
    label = h["hostname"] or host_ip

    findings = conn.execute(
        f"SELECT class, title, severity, evidence FROM finding "
        f"WHERE host_id = ? AND status = 'open' ORDER BY {_SEV_SQL}, id",
        (host_id,),
    ).fetchall()
    creds = conn.execute(
        "SELECT identifier, kind, source FROM credential "
        "WHERE source_host_id = ? ORDER BY id", (host_id,)
    ).fetchall()
    svcs = conn.execute(
        "SELECT port, proto, product, version FROM service WHERE host_id = ? ORDER BY port",
        (host_id,),
    ).fetchall()
    surfs = conn.execute(
        "SELECT kind, auth FROM surface WHERE host_id = ? ORDER BY kind", (host_id,)
    ).fetchall()

    b: list[str] = []
    b.append(f"**{_STAGE_HEADLINE.get(stage, stage)}**")
    b.append("")
    meta = [f"IP `{host_ip}`", f"OS {h['os'] or '?'}", f"stage `{stage}`"]
    if h["role"]:
        meta.append(f"role {h['role']}")
    b.append("  ·  ".join(meta))
    b.append("")

    tl = _timeline(conn, engagement_id, host_ip)
    if tl:
        b.append("### Attack chain (timeline)")
        b.extend(tl)
        b.append("")

    if findings:
        b.append("### Findings at this milestone")
        for f in findings:
            ev = f" — {f['evidence']}" if f["evidence"] else ""
            b.append(f"- **[{f['severity'].upper()}]** `{f['class']}` {f['title']}{ev}")
        b.append("")

    if creds:
        b.append("### Credentials recovered here")
        for c in creds:
            b.append(f"- `{c['identifier']}` ({c['kind']}, {c['source']})")
        b.append("")

    if svcs:
        b.append("### Services")
        b.append("- " + ", ".join(
            f"{s['port']}/{s['proto']} {s['product'] or ''}"
            f"{(' ' + s['version']) if s['version'] else ''}".strip() for s in svcs))
        b.append("")
    if surfs:
        b.append("### Surfaces")
        b.append("- " + ", ".join(f"{s['kind']}({s['auth'] or '?'})" for s in surfs))
        b.append("")

    note_id, _ = record_note(
        conn, engagement_id,
        host_id=host_id,
        objective=stage,
        category="attack_chain",
        title=f"{label} — {_STAGE_HEADLINE.get(stage, stage)}",
        body="\n".join(b),
        tags=f"milestone,{stage},{_slug(label)}",
    )
    return note_id


# ---------------------------------------------------------------------------
# Rendering — world model + notes -> Obsidian Markdown
# ---------------------------------------------------------------------------

def _frontmatter(fields: dict[str, str]) -> list[str]:
    out = ["---"]
    for k, v in fields.items():
        out.append(f"{k}: {v}")
    out.append("---")
    return out


def _notes_for_host(conn: sqlite3.Connection, engagement_id: int, host_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT objective, category, title, body, command, output, screenshot_path, "
        "tags, created_at FROM note WHERE engagement_id = ? AND host_id IS ? "
        "ORDER BY created_at, id",
        (engagement_id, host_id),
    ).fetchall()


_CATEGORY_HEADING = {
    "attack_chain": "Attack chain",
    "instructions": "Instructions (reproduce)",
    "poc": "Proof of concept",
    "evidence": "Evidence",
    "loot": "Loot",
    "recon": "Recon",
    "screenshot": "Screenshots",
}


def _render_note_block(n: sqlite3.Row) -> list[str]:
    out: list[str] = []
    out.append(f"#### {n['title']}")
    if n["body"]:
        out.append(n["body"])
    if n["command"]:
        out.append("")
        out.append("```bash")
        out.append(n["command"].rstrip())
        out.append("```")
    if n["output"]:
        out.append("")
        out.append("<details><summary>captured output</summary>")
        out.append("")
        out.append("```")
        out.append(n["output"].rstrip())
        out.append("```")
        out.append("")
        out.append("</details>")
    if n["screenshot_path"]:
        out.append("")
        out.append(f"![screenshot]({n['screenshot_path']})")
    out.append("")
    return out


def render_host_notebook(conn: sqlite3.Connection, engagement_id: int, host_id: int) -> str:
    """Render one host's full Obsidian note (frontmatter + grouped note sections)."""
    ensure_note_table(conn)
    h = _host_row(conn, host_id)
    if h is None:
        return ""
    label = h["hostname"] or h["ip"]
    notes = _notes_for_host(conn, engagement_id, host_id)

    out: list[str] = []
    out.extend(_frontmatter({
        "title": label,
        "ip": h["ip"],
        "hostname": h["hostname"] or "",
        "os": h["os"] or "unknown",
        "role": h["role"] or "",
        "stage": h["stage"],
        "tags": "[host, " + (h["stage"] or "") + "]",
        "updated": _now(),
    }))
    out.append("")
    out.append(f"# {label}  `{h['ip']}`")
    out.append("")
    out.append(f"> Stage: **{h['stage']}**  ·  OS: {h['os'] or '?'}"
               + (f"  ·  Role: {h['role']}" if h["role"] else ""))
    out.append("")

    if not notes:
        out.append("_No notes recorded yet for this host._")
        out.append("")
        return "\n".join(out)

    # Group by category, in CATEGORIES order.
    by_cat: dict[str, list[sqlite3.Row]] = {}
    for n in notes:
        by_cat.setdefault(n["category"], []).append(n)
    for cat in CATEGORIES:
        rows = by_cat.get(cat)
        if not rows:
            continue
        out.append(f"## {_CATEGORY_HEADING.get(cat, cat.title())}")
        out.append("")
        for n in rows:
            out.extend(_render_note_block(n))

    return "\n".join(out)


def render_attack_chains(conn: sqlite3.Connection, engagement_id: int) -> str:
    """Cross-host kill-path page: every attack_chain note, ordered by time."""
    ensure_note_table(conn)
    rows = conn.execute(
        "SELECT n.title, n.body, n.created_at, h.ip AS ip, h.hostname AS hostname "
        "FROM note n LEFT JOIN host h ON h.id = n.host_id "
        "WHERE n.engagement_id = ? AND n.category = 'attack_chain' "
        "ORDER BY n.created_at, n.id",
        (engagement_id,),
    ).fetchall()
    out: list[str] = ["# Attack chains", ""]
    if not rows:
        out.append("_No attack-chain milestones recorded yet._")
        return "\n".join(out) + "\n"
    for r in rows:
        label = r["hostname"] or r["ip"] or "?"
        out.append(f"## [[{label}]] — {r['title']}")
        out.append(f"`{r['created_at']}`")
        out.append("")
        if r["body"]:
            out.append(r["body"])
        out.append("")
        out.append("---")
        out.append("")
    return "\n".join(out)


def render_index(conn: sqlite3.Connection, engagement_id: int) -> str:
    """Notebook index: scoreboard + wikilinks to every host note."""
    ensure_note_table(conn)
    eng = conn.execute(
        "SELECT lab, scope, domain, dc_ip, started_at FROM engagement WHERE id = ?",
        (engagement_id,),
    ).fetchone()
    hosts = conn.execute(
        "SELECT id, ip, hostname, os, role, stage FROM host "
        "WHERE engagement_id = ? ORDER BY stage DESC, ip", (engagement_id,)
    ).fetchall()
    note_counts = dict(conn.execute(
        "SELECT host_id, COUNT(*) FROM note WHERE engagement_id = ? GROUP BY host_id",
        (engagement_id,),
    ).fetchall())

    out: list[str] = []
    out.extend(_frontmatter({
        "title": f"{eng['lab']} — engagement notebook",
        "tags": "[engagement, index]",
        "updated": _now(),
    }))
    out.append("")
    out.append(f"# {eng['lab']} — engagement notebook")
    out.append("")
    meta = [f"**Scope:** {eng['scope']}"]
    if eng["domain"]:
        meta.append(f"**Domain:** {eng['domain']}")
    if eng["dc_ip"]:
        meta.append(f"**DC:** {eng['dc_ip']}")
    meta.append(f"**Started:** {eng['started_at']}")
    out.append("  ·  ".join(meta))
    out.append("")
    out.append("See [[attack-chains]] for the chained kill-path.")
    out.append("")
    out.append("## Hosts")
    out.append("")
    out.append("| Host | IP | OS | Stage | Notes |")
    out.append("|---|---|---|---|---|")
    for h in hosts:
        label = h["hostname"] or h["ip"]
        n = note_counts.get(h["id"], 0)
        out.append(f"| [[{label}]] | `{h['ip']}` | {h['os'] or '?'} | "
                   f"**{h['stage']}** | {n} |")
    out.append("")
    return "\n".join(out)


def _safe_name(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", label) or "host"


def write_notebook(conn: sqlite3.Connection, engagement_id: int, notes_dir: Path) -> list[Path]:
    """Write the whole notebook to `notes_dir`. Returns the paths written.

    Layout: INDEX.md, attack-chains.md, and one <HOST>.md per host.
    """
    ensure_note_table(conn)
    notes_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    idx = notes_dir / "INDEX.md"
    idx.write_text(render_index(conn, engagement_id), encoding="utf-8")
    written.append(idx)

    chains = notes_dir / "attack-chains.md"
    chains.write_text(render_attack_chains(conn, engagement_id), encoding="utf-8")
    written.append(chains)

    hosts = conn.execute(
        "SELECT id, ip, hostname FROM host WHERE engagement_id = ? ORDER BY ip",
        (engagement_id,),
    ).fetchall()
    for h in hosts:
        label = h["hostname"] or h["ip"]
        md = render_host_notebook(conn, engagement_id, h["id"])
        if not md:
            continue
        p = notes_dir / f"{_safe_name(label)}.md"
        p.write_text(md, encoding="utf-8")
        written.append(p)

    return written
