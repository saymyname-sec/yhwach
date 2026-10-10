"""Reference knowledge packs — offline lookup tables the operator queries.

default-creds / esc / gtfobins live as YAML in data/ and are rendered on demand
by `yhwach ref` (and the yhwach_ref MCP tool). Pure lookup: no engagement, no DB.
"""
from __future__ import annotations

from functools import lru_cache

import yaml

from yhwach import data_path

_FILES = {
    "default-creds": "default_creds.yaml",
    "esc": "adcs_esc.yaml",
    "gtfobins": "gtfobins.yaml",
    "lessons": "lessons.yaml",
    "services": "service_matrix.yaml",
    "tags": "tags.yaml",
    "lolbas": "lolbas.yaml",
    "wadcoms": "wadcoms.yaml",
    "arsenal": "arsenal_ref.yaml",
    "ai-attacks": "ai_attacks.yaml",
}


@lru_cache(maxsize=16)
def _load(pack: str) -> list[dict]:
    data = yaml.safe_load(data_path(_FILES[pack]).read_text(encoding="utf-8")) or []
    return [e for e in data if isinstance(e, dict)]


def _matches(entry: dict, query: str) -> bool:
    q = query.lower()
    return any(q in str(v).lower() for v in entry.values())


def lessons_for(tags) -> list[dict]:
    """Lessons whose `trigger_tag` intersects `tags` — the join key that pulls
    past-lab knowledge into the brief when a host carries a matching finding tag
    or surface kind. Read-only; case-insensitive."""
    want = {str(t).lower() for t in tags if t}
    if not want:
        return []
    out: list[dict] = []
    for e in _load("lessons"):
        trig = {str(t).lower() for t in (e.get("trigger_tag") or [])}
        if trig & want:
            out.append(e)
    return out


def render_pack(pack: str, query: str | None = None) -> str:
    if pack not in _FILES:
        raise ValueError(f"unknown pack '{pack}' (use {', '.join(_FILES)})")
    entries = _load(pack)
    if query:
        entries = [e for e in entries if _matches(e, query)]
    if not entries:
        return ""
    return {"default-creds": _render_creds, "esc": _render_esc,
            "gtfobins": _render_gtfo, "lessons": _render_lessons,
            "services": _render_services, "tags": _render_tags,
            "lolbas": _render_lolbas, "wadcoms": _render_wadcoms,
            "arsenal": _render_arsenal,
            "ai-attacks": _render_ai_attacks}[pack](entries)


def _render_creds(entries: list[dict]) -> str:
    lines = ["# Default / well-known credentials (try before spraying)"]
    for e in entries:
        lines.append(f"\n## {e.get('product', '?')}")
        for c in e.get("creds", []):
            lines.append(f"  - {c}")
        if e.get("note"):
            lines.append(f"  note: {e['note']}")
    return "\n".join(lines)


def _render_esc(entries: list[dict]) -> str:
    lines = ["# AD CS ESC catalog"]
    for e in entries:
        lines.append(f"\n## {e.get('id', '?')} — {e.get('title', '')}")
        lines.append(f"  requirement: {e.get('requirement', '')}")
        if e.get("signal"):
            lines.append(f"  find-signal:  {e['signal']}")
        lines.append(f"  abuse:       {e.get('abuse', '')}")
        if e.get("chain"):
            lines.append(f"  chain:       {e['chain']}")
    return "\n".join(lines)


def _render_gtfo(entries: list[dict]) -> str:
    lines = ["# GTFObins privesc quick reference"]
    for e in entries:
        lines.append(f"\n## {e.get('bin', '?')}")
        if e.get("sudo"):
            lines.append(f"  sudo: {e['sudo']}")
        if e.get("suid"):
            lines.append(f"  suid: {e['suid']}")
        if e.get("note"):
            lines.append(f"  note: {e['note']}")
    return "\n".join(lines)


def _render_lessons(entries: list[dict]) -> str:
    lines = ["# Lessons memory — knowledge won in past labs (join key: trigger_tag)"]
    for e in entries:
        tags = ", ".join(e.get("trigger_tag", []) or [])
        lines.append(f"\n## {e.get('id', '?')}  [{tags}]")
        lines.append(f"  {e.get('lesson', '')}")
        if e.get("maps"):
            lines.append(f"  maps: {', '.join(e['maps'])}")
    return "\n".join(lines)


def _render_services(entries: list[dict]) -> str:
    lines = ["# Service matrix — identity -> ports -> triage"]
    for e in entries:
        tcp = ",".join(str(p) for p in e.get("tcp_ports", []) or [])
        lines.append(f"\n## {e.get('kind', '?')}"
                     + (f"  (tcp {tcp})" if tcp else ""))
        if e.get("classify"):
            lines.append(f"  classify: {', '.join(e['classify'])}")
        if e.get("enum_ref"):
            lines.append(f"  triage:   {e['enum_ref']}")
        if e.get("ref_pack"):
            lines.append(f"  ref pack: yhwach ref {e['ref_pack']}")
    return "\n".join(lines)


def _render_tags(entries: list[dict]) -> str:
    lines = ["# Chaining-tag registry (state axis)"]
    for e in entries:
        status = e.get("status", "?")
        lines.append(f"\n## {e.get('tag', '?')}  [{status}]")
        if e.get("producer"):
            lines.append(f"  producer:  {', '.join(e['producer'])}")
        if e.get("consumers"):
            lines.append(f"  consumers: {', '.join(e['consumers'])}")
        if e.get("implies"):
            lines.append(f"  implies:   {', '.join(e['implies'])}")
        if e.get("note"):
            lines.append(f"  note: {e['note']}")
    return "\n".join(lines)


def _render_lolbas(entries: list[dict]) -> str:
    lines = ["# LOLBAS — signed Windows binaries abused (the Windows gtfobins)"]
    for e in entries:
        cat = e.get("category", "?")
        lines.append(f"\n## {e.get('bin', '?')}  [{cat}]"
                     + (f"  {e['mitre']}" if e.get("mitre") else ""))
        if e.get("function"):
            lines.append(f"  {e['function']}")
        if e.get("ref"):
            lines.append(f"  $ {e['ref']}")
        if e.get("note"):
            lines.append(f"  note: {e['note']}")
    return "\n".join(lines)


def _render_ai_attacks(entries: list[dict]) -> str:
    lines = ["# AI-attack technique packs (OWASP-LLM / MITRE ATLAS) — offline recall"]
    for e in entries:
        head = f"\n## {e.get('topic', '?')}"
        if e.get("surface"):
            head += f"  ({e['surface']})"
        lines.append(head)
        std = []
        if e.get("owasp"):
            std.append("OWASP " + ", ".join(e["owasp"]))
        if e.get("atlas"):
            std.append("ATLAS " + ", ".join(e["atlas"]))
        if std:
            lines.append("  " + " · ".join(std))
        if e.get("summary"):
            lines.append(f"  {e['summary']}")
        for step in e.get("chain", []) or []:
            lines.append(f"  - {step}")
        if e.get("fold_back"):
            lines.append(f"  fold-back: {e['fold_back']}")
        if e.get("refs"):
            lines.append(f"  refs: {e['refs']}")
    return "\n".join(lines)


def _render_arsenal(entries: list[dict]) -> str:
    lines = ["# Arsenal — vendored offensive tooling "
             "(canonical > quick-win > deep; scripts are shortcuts, not a "
             "substitute for full-Kali manual enumeration)"]
    order = {"canonical": 0, "quick-win": 1, "deep": 2}
    for e in sorted(entries, key=lambda x: order.get(x.get("tier", ""), 3)):
        tier = e.get("tier", "?")
        os_ = e.get("os", "")
        lines.append(f"\n## {e.get('name', '?')}  [{tier}]"
                     + (f"  ({os_})" if os_ else ""))
        if e.get("surface"):
            lines.append(f"  surface: {e['surface']}")
        if e.get("purpose"):
            lines.append(f"  {e['purpose']}")
        if e.get("path"):
            lines.append(f"  path:    {e['path']}")
        if e.get("invoke"):
            lines.append(f"  invoke:  {e['invoke']}")
        if e.get("deps"):
            lines.append(f"  deps:    {e['deps']}")
        if e.get("note"):
            lines.append(f"  note:    {e['note']}")
    return "\n".join(lines)


def _render_wadcoms(entries: list[dict]) -> str:
    lines = ["# WADComs — Windows/AD command matrix (synthetic placeholders)"]
    for e in entries:
        lines.append(f"\n## [{e.get('phase', '?')}] {e.get('id', '?')}"
                     + (f"  ({e['tool']})" if e.get("tool") else ""))
        if e.get("cmd"):
            lines.append(f"  $ {e['cmd']}")
        meta = []
        if e.get("tag"):
            meta.append(f"tag={e['tag']}")
        if e.get("maps"):
            meta.append("maps=" + ",".join(e["maps"]))
        if meta:
            lines.append("  " + " · ".join(meta))
    return "\n".join(lines)
