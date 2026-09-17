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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class ExtractedFinding:
    cls: str        # LLM01..LLM10 | CWE-... | CVE-... | ATLAS-...
    title: str
    severity: str   # critical | high | medium | low
    evidence: str
    tag: str | None = None   # chaining key a rule's `findings_include` matches on


def _first_json(output: str) -> Any:
    """Parse the first JSON object/array embedded in output, or None.

    Uses raw_decode from each `[`/`{` candidate so trailing text after the JSON
    is tolerated in a single pass (no quadratic substring scan, no size cap)."""
    if not output:
        return None
    decoder = json.JSONDecoder()
    for m in re.finditer(r"[\[{]", output):
        try:
            obj, _ = decoder.raw_decode(output, m.start())
            return obj
        except ValueError:
            continue
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


def _smb_null(output: str, ctx: dict) -> list[ExtractedFinding]:
    """netexec/smbmap SMB output — one run yields several AD signals at once."""
    ip = ctx.get("IP", "?")
    out: list[ExtractedFinding] = []
    if "Pwn3d" in output:  # keep first: back-compat with interpret_output's single-value callers
        out.append(ExtractedFinding(
            "CWE-287", "SMB admin access via null/guest session", "critical",
            f"netexec reports (Pwn3d!) on {ip}"))
    if re.search(r"signing:\s*False", output, re.I):
        out.append(ExtractedFinding(
            "CWE-326", "SMB signing not required", "medium",
            f"{ip} signing:False — NTLM relay candidate", tag="smb_signing_off"))
    if re.search(r"READ|WRITE", output) and "\\" in output:
        out.append(ExtractedFinding(
            "CWE-200", "SMB shares readable via null session", "high",
            f"readable shares enumerated on {ip}", tag="null_session"))
    return out


def _ldap_anon(output: str, ctx: dict) -> list[ExtractedFinding]:
    """Anonymous LDAP bind / naming-context leak -> tag ldap_anon (+ the domain)."""
    ip = ctx.get("IP", "?")
    m = re.search(r"(?:namingContexts|defaultNamingContext):\s*(DC=\S+)", output, re.I)
    if m:
        domain = ".".join(re.findall(r"DC=([^,]+)", m.group(1), re.I))
        return [ExtractedFinding(
            "CWE-200", "Anonymous LDAP bind exposes the directory", "high",
            f"anon LDAP on {ip} leaks {domain or m.group(1)}", tag="ldap_anon")]
    if re.search(r"\bLDAP\b.*\[\+\]", output):  # netexec anon bind succeeded
        return [ExtractedFinding(
            "CWE-200", "Anonymous LDAP bind allowed", "high",
            f"anonymous bind accepted on {ip}", tag="ldap_anon")]
    return []


def _ad_users(output: str, ctx: dict) -> list[ExtractedFinding]:
    """A domain user list was enumerated (netexec --users / enum4linux / kerbrute)
    -> tag domain_users, which unlocks AS-REP roast and spraying."""
    users = set(re.findall(r"(?:VALID USERNAME:|\[\+\] Valid user:)\s*(\S+)", output))
    users |= set(re.findall(r"user:\s*(\S+)", output, re.I))
    if len(users) >= 2:
        return [ExtractedFinding(
            "CWE-200", "Domain user list enumerated", "medium",
            f"{len(users)} domain users on {ctx.get('IP','?')}", tag="domain_users")]
    return []


def _kerberos_roast(output: str, ctx: dict) -> list[ExtractedFinding]:
    """Kerberoast / AS-REP roast hashes captured -> tag for the crack follow-up."""
    out: list[ExtractedFinding] = []
    if "$krb5tgs$" in output:
        out.append(ExtractedFinding(
            "CWE-522", "Kerberoastable service account (TGS captured)", "high",
            "crack $krb5tgs$ offline (hashcat -m 13100)", tag="kerberoastable"))
    if "$krb5asrep$" in output:
        out.append(ExtractedFinding(
            "CWE-522", "AS-REP roastable account (no preauth)", "high",
            "crack $krb5asrep$ offline (hashcat -m 18200)", tag="asreproastable"))
    return out


def _rag_upload(output: str, ctx: dict) -> ExtractedFinding | None:
    hits = re.findall(r"FOUND (\S+)", output)
    if hits:
        return ExtractedFinding(
            "LLM04", "RAG/document upload endpoint discovered", "high",
            f"upload paths on {ctx.get('URL','?')}: {', '.join(hits)[:140]}",
            tag="rag_upload",  # unlocks rag_kb_advanced_poisoning / embedding_collision_attack
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


# An extractor returns a single finding, None, or a list — `interpret_all`
# normalises all three. AD tools (netexec/ldapsearch) emit several signals per
# run, so their extractors return lists.
_Extractor = Callable[[str, dict], "ExtractedFinding | list[ExtractedFinding] | None"]

_EXTRACTORS: dict[str, _Extractor] = {
    "sqli_error_probe": _sqli_error,
    "probe_ollama_models": _ollama_models,
    "enumerate_models": _openai_models,
    "mcp_tools_list": _mcp_tools,
    "jenkins_auth_check": _jenkins_api,
    "netexec_smb_null": _smb_null,
    "probe_writable_smb_share": _smb_null,
    "enum4linux_ng": _smb_null,
    "smbmap_shares": _smb_null,
    "probe_rag_upload_paths": _rag_upload,
    # --- AD enumeration ---
    "netexec_ldap": _ldap_anon,
    "ldapsearch_anon": _ldap_anon,
    "ldap_anon_dump": _ad_users,
    "kerbrute_userenum": _ad_users,
    "asreproast_users": _kerberos_roast,
    "kerberoast_getuserspns": _kerberos_roast,
}


def interpret_all(action_id: str, output: str, context: dict) -> list[ExtractedFinding]:
    """All findings an action's output yields (may be several for AD tools)."""
    fn = _EXTRACTORS.get(action_id)
    if fn is None:
        return []
    res = fn(output, context)
    if res is None:
        return []
    return res if isinstance(res, list) else [res]


def interpret_output(action_id: str, output: str, context: dict) -> ExtractedFinding | None:
    """The first finding from an action's output, or None. Back-compat single-value
    view over `interpret_all` (used where only one finding is expected)."""
    res = interpret_all(action_id, output, context)
    return res[0] if res else None
