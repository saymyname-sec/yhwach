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
}


@lru_cache(maxsize=8)
def _load(pack: str) -> list[dict]:
    data = yaml.safe_load(data_path(_FILES[pack]).read_text(encoding="utf-8")) or []
    return [e for e in data if isinstance(e, dict)]


def _matches(entry: dict, query: str) -> bool:
    q = query.lower()
    return any(q in str(v).lower() for v in entry.values())


def render_pack(pack: str, query: str | None = None) -> str:
    if pack not in _FILES:
        raise ValueError(f"unknown pack '{pack}' (use {', '.join(_FILES)})")
    entries = _load(pack)
    if query:
        entries = [e for e in entries if _matches(e, query)]
    if not entries:
        return ""
    return {"default-creds": _render_creds, "esc": _render_esc,
            "gtfobins": _render_gtfo}[pack](entries)


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
        lines.append(f"  abuse:       {e.get('abuse', '')}")
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
