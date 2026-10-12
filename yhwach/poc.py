"""Reproducible PoC-chain recorder — "how to recreate every PoC".

yhwach.db owns the ATOMS (findings, creds, surfaces). This module owns the
KILL-CHAIN NARRATIVE per objective: every step's verbatim command, its console
output, any script/payload used (saved to disk verbatim), the CVE/source and the
host — so a technically competent stranger reproduces the PoC by copy-paste.

Storage is the append-only `event` table (kind='poc_step'); no schema change.
Scripts/payloads are saved under <artifact>/scripts/<objective>/ and referenced
by path (and inlined in the render when small). `render_poc` reads the steps
back into chains/<objective>.md — the engagement deliverable.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from yhwach import db as yhdb
from yhwach.engine import artifact_dir

_OUTPUT_CAP = 6000          # store a key excerpt, never a whole dump
_INLINE_SCRIPT_MAX = 400    # lines: inline the script in the render below this


def slug(s: str) -> str:
    """A filesystem/link-safe objective slug."""
    out = "".join(c if (c.isalnum() or c in "-_") else "-" for c in (s or "").lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-") or "objective"


def save_script(db_path: Path | str, objective: str, name: str, content: str) -> Path:
    """Persist a script/payload verbatim under <artifact>/scripts/<objective>/."""
    d = artifact_dir(db_path, "scripts") / slug(objective)
    d.mkdir(parents=True, exist_ok=True)
    safe_name = Path(name).name or "script.txt"
    p = d / safe_name
    p.write_text(content)
    return p


def add_step(
    conn: sqlite3.Connection,
    engagement_id: int,
    objective: str,
    *,
    title: str,
    command: str = "",
    output: str = "",
    script_path: str | None = None,
    cve: str | None = None,
    source: str | None = None,
    host: str | None = None,
    finding_id: int | None = None,
) -> int:
    """Append one reproducible step to an objective's PoC chain. Returns its seq.

    `finding_id` keys the step to the finding it proves (I12), so a write-up can
    be assembled per finding, not only per objective."""
    seq = len(steps_for(conn, engagement_id, objective)) + 1
    excerpt = output if len(output) <= _OUTPUT_CAP else output[:_OUTPUT_CAP] + "\n...[truncated]"
    payload = {
        "objective": slug(objective), "objective_label": objective, "seq": seq,
        "title": title, "command": command, "output": excerpt,
        "script": str(script_path) if script_path else None,
        "cve": cve, "source": source, "host": host, "finding_id": finding_id,
    }
    yhdb.log_event(conn, engagement_id, "poc_step", payload)
    return seq


def steps_for(conn: sqlite3.Connection, engagement_id: int, objective: str) -> list[dict]:
    """All recorded steps for an objective, in insertion order."""
    want = slug(objective)
    rows = conn.execute(
        "SELECT ts, payload_json FROM event WHERE engagement_id=? AND kind='poc_step' ORDER BY id",
        (engagement_id,),
    ).fetchall()
    steps = []
    for r in rows:
        p = json.loads(r["payload_json"])
        if p.get("objective") == want:
            p["_ts"] = r["ts"]
            steps.append(p)
    return steps


def list_objectives(conn: sqlite3.Connection, engagement_id: int) -> list[tuple[str, int]]:
    """(objective_label, step_count) for every objective with recorded steps."""
    rows = conn.execute(
        "SELECT payload_json FROM event WHERE engagement_id=? AND kind='poc_step' ORDER BY id",
        (engagement_id,),
    ).fetchall()
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}
    for r in rows:
        p = json.loads(r["payload_json"])
        o = p.get("objective", "?")
        counts[o] = counts.get(o, 0) + 1
        labels[o] = p.get("objective_label", o)
    return [(labels[o], counts[o]) for o in counts]


def scaffold_from_attempts(conn: sqlite3.Connection, engagement_id: int) -> list[str]:
    """Auto-seed a PoC chain stub for every SUCCESSFUL attempt that has no chain yet.

    Enumeration/exploitation wins live in the attempt ledger with their reason +
    evidence; this turns each into a first reproducible step (objective = the
    technique) so no result-yielding finding is left without a chain note. Idempotent:
    an objective that already has steps is skipped. Returns the objectives seeded.
    """
    have = {o for o, _ in ((slug(lbl), n) for lbl, n in list_objectives(conn, engagement_id))}
    seeded: list[str] = []
    # oldest-first so step ordering matches the engagement timeline
    for a in reversed(yhdb.list_attempts(conn, engagement_id, result="success")):
        objective = a["playbook_rule_id"] or a["technique_id"] or f"attempt-{a['id']}"
        if slug(objective) in have:
            continue
        add_step(
            conn, engagement_id, objective,
            title=f"{objective} succeeded",
            command="# TODO: paste the verbatim command(s) that produced this win",
            output=(a["evidence"] or a["reason"] or "").strip(),
            host=a["host_ip"],
        )
        have.add(slug(objective))
        seeded.append(objective)
    return seeded


def _vault_secrets(conn: sqlite3.Connection, engagement_id: int) -> list[str]:
    """Non-trivial secret values held for the engagement, longest first (so a
    longer secret is masked before a shorter substring of it)."""
    out = []
    for r in conn.execute(
        "SELECT secret FROM credential WHERE engagement_id = ? AND secret IS NOT NULL",
        (engagement_id,),
    ):
        s = (r["secret"] or "").strip()
        if len(s) >= 4:            # don't mask tiny/empty values — too noisy
            out.append(s)
    return sorted(set(out), key=len, reverse=True)


def _redact(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s in text:
            text = text.replace(s, "[REDACTED]")
    return text


def render_poc(conn: sqlite3.Connection, engagement_id: int, objective: str,
               *, lab: str = "", write: bool = True, db_path: Path | str | None = None,
               redact: bool = False) -> str:
    """Render an objective's reproducible PoC chain as Markdown (and write it to
    chains/<slug>.md when write=True).

    `redact=True` produces the submission template: every vault secret is masked
    to [REDACTED] so the same chain is safe to paste into a bounty report or a
    client write-up. A redacted render is NOT written to disk (it is a transient
    export, and the on-disk chain keeps the real values for reproduction)."""
    steps = steps_for(conn, engagement_id, objective)
    secrets = _vault_secrets(conn, engagement_id) if redact else []
    label = steps[0].get("objective_label", objective) if steps else objective
    cves = sorted({s["cve"] for s in steps if s.get("cve")})
    hosts = sorted({s["host"] for s in steps if s.get("host")})
    lines = [
        f"# PoC — {label}" + (f"  ·  lab: {lab}" if lab else ""),
        "",
        "> Reproducible kill-chain. Every command runs top-to-bottom with real "
        "values inline; the output under each is the proof.",
        "",
        f"- Target host(s): {', '.join(hosts) if hosts else '(engagement-wide)'}",
        f"- CVE / technique: {', '.join(cves) if cves else '(see steps)'}",
        f"- Steps: {len(steps)}",
        "",
        "## Steps",
    ]
    if not steps:
        lines.append("\n_(no steps recorded yet)_")
    for s in steps:
        lines.append(f"\n### {s['seq']}. {s['title']}")
        meta = [x for x in (
            f"CVE: {s['cve']}" if s.get("cve") else "",
            f"source: {s['source']}" if s.get("source") else "",
            f"host: {s['host']}" if s.get("host") else "",
            f"finding: #{s['finding_id']}" if s.get("finding_id") else "",
        ) if x]
        if meta:
            lines.append("- " + " · ".join(meta))
        if s.get("command"):
            lines += ["", "```bash", _redact(s["command"].rstrip(), secrets), "```"]
        if s.get("output"):
            lines += ["", "Output:", "```", _redact(s["output"].rstrip(), secrets), "```"]
        if s.get("script"):
            lines.append(f"\nScript / payload: `{s['script']}`")
            content = _read_script(s["script"])
            if content is not None and content.count("\n") <= _INLINE_SCRIPT_MAX:
                lines += ["", "```", _redact(content.rstrip(), secrets), "```"]
    md = "\n".join(lines) + "\n"
    if write and not redact:
        base = db_path if db_path is not None else _db_path_from_conn(conn)
        if base is not None:
            d = artifact_dir(base, "chains")
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{slug(objective)}.md").write_text(md)
    return md


def _read_script(path: str) -> str | None:
    try:
        return Path(path).read_text()
    except OSError:
        return None


def _db_path_from_conn(conn: sqlite3.Connection) -> str | None:
    try:
        for _id, name, file in conn.execute("PRAGMA database_list"):
            if name == "main" and file:
                return file
    except sqlite3.Error:
        return None
    return None
