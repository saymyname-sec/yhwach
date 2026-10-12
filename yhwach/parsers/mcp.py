"""MCP server enumeration -> tools / resources / prompts (I55).

Parses the JSON-RPC results of tools/list, resources/list and prompts/list (one
object per method, or several concatenated/newline-delimited). These feed the
I52 asset model (ai_tool / ai_data_source). Tool-list DRIFT between probes is
reported as an event with a diff; it is promoted to a finding only after review.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class McpSurface:
    tools: list[dict] = field(default_factory=list)       # {name, description}
    resources: list[dict] = field(default_factory=list)   # {name, uri, mime}
    prompts: list[dict] = field(default_factory=list)      # {name, description}


def _objects(text: str):
    """Yield each top-level JSON object (whole-doc, or one per line)."""
    t = text.strip()
    if not t:
        return
    try:
        yield json.loads(t)
        return
    except json.JSONDecodeError:
        pass
    for line in t.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_mcp(text: str) -> McpSurface:
    out = McpSurface()
    for d in _objects(text):
        result = d.get("result", d) if isinstance(d, dict) else {}
        for t in result.get("tools", []) or []:
            if isinstance(t, dict) and t.get("name"):
                out.tools.append({"name": t["name"], "description": t.get("description") or ""})
        for r in result.get("resources", []) or []:
            if isinstance(r, dict) and (r.get("name") or r.get("uri")):
                out.resources.append({"name": r.get("name") or r.get("uri"),
                                      "uri": r.get("uri"), "mime": r.get("mimeType")})
        for p in result.get("prompts", []) or []:
            if isinstance(p, dict) and p.get("name"):
                out.prompts.append({"name": p["name"], "description": p.get("description") or ""})
    return out
