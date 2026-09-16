"""Deterministic finding extraction from action output.

This is the *deterministic* half of INTERPRET: high-signal, unambiguous outputs
(an Ollama model list, an exposed MCP tool list, a Jenkins unauth API) become
`finding` rows with zero model involvement. Ambiguous output (does this chatbot
reply leak the system prompt?) stays the operator's judgment via the contract —
we do not guess here.

Each extractor: (output, context) -> ExtractedFinding | None. Registered per
action id. Silence (None) is always safe.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class ExtractedFinding:
    cls: str        # LLM01..LLM10 | CWE-... | CVE-... | ATLAS-...
    title: str
    severity: str   # critical | high | medium | low
    evidence: str


def _first_json(output: str) -> Any:
    """Parse the first JSON object/array embedded in output, or None."""
    if not output:
        return None
    m = re.search(r"[\[{]", output)
    if not m:
        return None
    frag = output[m.start():]
    for end in range(len(frag), max(len(frag) - 200000, 0), -1):
        try:
            return json.loads(frag[:end])
        except ValueError:
            continue
    try:
        return json.loads(frag)
    except ValueError:
        return None


def _ollama_models(output: str, ctx: dict) -> ExtractedFinding | None:
    data = _first_json(output)
    if isinstance(data, dict) and data.get("models"):
        names = [m.get("name") for m in data["models"] if isinstance(m, dict) and m.get("name")]
        return ExtractedFinding(
            "LLM06", "Unauthenticated Ollama API exposes models", "high",
            f"{len(names)} models on {ctx.get('URL','?')}: {', '.join(names)[:140]}",
        )
    return None


def _openai_models(output: str, ctx: dict) -> ExtractedFinding | None:
    data = _first_json(output)
    if isinstance(data, dict) and isinstance(data.get("data"), list) and data["data"]:
        ids = [m.get("id") for m in data["data"] if isinstance(m, dict) and m.get("id")]
        return ExtractedFinding(
            "LLM02", "Unauthenticated OpenAI-compatible API", "high",
            f"{len(ids)} models on {ctx.get('URL','?')}: {', '.join(ids)[:140]}",
        )
    return None


def _mcp_tools(output: str, ctx: dict) -> ExtractedFinding | None:
    data = _first_json(output)
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        tools = [t.get("name") for t in data["result"].get("tools", []) if isinstance(t, dict)]
        if tools:
            return ExtractedFinding(
                "LLM06", "MCP server exposes tools unauthenticated", "critical",
                f"{len(tools)} tools on {ctx.get('URL','?')}: {', '.join(filter(None, tools))[:140]}",
            )
    return None


def _jenkins_api(output: str, ctx: dict) -> ExtractedFinding | None:
    if "hudson.model.Hudson" in output or '"jobs"' in output:
        return ExtractedFinding(
            "CWE-200", "Jenkins REST API reachable without auth", "medium",
            f"{ctx.get('URL','?')}/api/json returns instance metadata",
        )
    return None


def _smb_null(output: str, ctx: dict) -> ExtractedFinding | None:
    if "Pwn3d" in output:
        return ExtractedFinding(
            "CWE-287", "SMB admin access via null/guest session", "critical",
            f"netexec reports (Pwn3d!) on {ctx.get('IP','?')}",
        )
    if re.search(r"READ|WRITE", output) and "\\" in output:
        return ExtractedFinding(
            "CWE-200", "SMB shares readable via null session", "high",
            f"readable shares enumerated on {ctx.get('IP','?')}",
        )
    return None


def _rag_upload(output: str, ctx: dict) -> ExtractedFinding | None:
    hits = re.findall(r"FOUND (\S+)", output)
    if hits:
        return ExtractedFinding(
            "LLM04", "RAG/document upload endpoint discovered", "high",
            f"upload paths on {ctx.get('URL','?')}: {', '.join(hits)[:140]}",
        )
    return None


_SQL_ERROR_SIGNATURES = (
    "unrecognized token", "sql error", "sqlite3.", "sqlite_error",            # sqlite
    "you have an error in your sql syntax", "mysql_fetch", "mysqlsyntaxerror",  # mysql
    "unclosed quotation mark", "microsoft ole db", "odbc sql server",          # mssql
    "postgresql query failed", "pg::syntaxerror",                             # postgres
    "ora-01756", "ora-00933",                                                 # oracle
    "[sqli]",                                                                 # our probe marker
)


def _sqli_error(output: str, ctx: dict) -> ExtractedFinding | None:
    low = (output or "").lower()
    for sig in _SQL_ERROR_SIGNATURES:
        if sig in low:
            hit = re.search(r"\[SQLi\]\s*(\S+)", output)
            where = hit.group(1) if hit else ctx.get("URL", "?")
            return ExtractedFinding(
                "CWE-89", "SQL injection (error-based)", "critical",
                f"SQL error reflected from {where} on a single-quote payload")
    return None


_EXTRACTORS: dict[str, Callable[[str, dict], ExtractedFinding | None]] = {
    "sqli_error_probe": _sqli_error,
    "probe_ollama_models": _ollama_models,
    "enumerate_models": _openai_models,
    "mcp_tools_list": _mcp_tools,
    "jenkins_auth_check": _jenkins_api,
    "netexec_smb_null": _smb_null,
    "probe_writable_smb_share": _smb_null,
    "probe_rag_upload_paths": _rag_upload,
}


def interpret_output(action_id: str, output: str, context: dict) -> ExtractedFinding | None:
    """Extract a finding from an action's output, or None if nothing definitive."""
    fn = _EXTRACTORS.get(action_id)
    return fn(output, context) if fn else None
