"""CI/CD scanner output -> gha_* tagged findings (I34).

Parses SARIF (zizmor and any SARIF-emitting tool) and poutine JSON into findings
on the pipeline chaining tags. yhwach does not hand-roll a GitHub Actions
analyzer — it ingests what the tools found and owns the 'what next'.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

_SARIF_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

# rule/title keyword -> chaining tag (most specific first).
_GHA_TAGS: list[tuple[tuple[str, ...], str]] = [
    (("pwn-request", "pwn_request", "untrusted-checkout", "dangerous-checkout"), "gha_pwn_request"),
    (("template-injection", "injection", "expression"), "gha_injection"),
    (("self-hosted", "self_hosted", "runner"), "gha_self_hosted_runner"),
    (("cache-poison", "cache_poison"), "gha_cache_poisoning"),
    (("excessive", "permission", "write-all", "token"), "gha_excessive_perms"),
    (("secret", "credential", "hardcoded"), "gha_secret"),
    (("artifact", "upload"), "gha_artifact"),
]


@dataclass
class CicdFinding:
    rule: str
    title: str
    severity: str
    path: str
    tag: str
    tool: str


def _tag_for(rule: str, title: str) -> str:
    blob = f"{rule} {title}".lower()
    for needles, tag in _GHA_TAGS:
        if any(n in blob for n in needles):
            return tag
    return "gha_misc"


def parse_sarif(text: str) -> list[CicdFinding]:
    """SARIF 2.1.0 (zizmor et al.)."""
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[CicdFinding] = []
    for run in (d.get("runs") or []) if isinstance(d, dict) else []:
        tool = (((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif")
        for r in run.get("results") or []:
            rule = r.get("ruleId") or r.get("rule", {}).get("id") or "rule"
            msg = (r.get("message") or {}).get("text") or ""
            path = ""
            locs = r.get("locations") or []
            if locs:
                art = ((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {})
                path = art.get("uri") or ""
            out.append(CicdFinding(
                rule=rule, title=msg[:160] or rule,
                severity=_SARIF_SEV.get((r.get("level") or "warning").lower(), "medium"),
                path=path, tag=_tag_for(rule, msg), tool=tool))
    return out


def parse_poutine(text: str) -> list[CicdFinding]:
    """poutine JSON ({"findings":[{rule_id,title,level,meta.path}]})."""
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = d.get("findings") if isinstance(d, dict) else d
    out: list[CicdFinding] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        rule = r.get("rule_id") or r.get("ruleId") or r.get("rule") or "rule"
        title = r.get("title") or r.get("message") or rule
        meta = r.get("meta") or {}
        path = meta.get("path") or r.get("path") or r.get("purl") or ""
        lvl = (r.get("level") or r.get("severity") or "warning").lower()
        out.append(CicdFinding(
            rule=rule, title=str(title)[:160],
            severity=_SARIF_SEV.get(lvl, lvl if lvl in
                                    ("critical", "high", "medium", "low", "info") else "medium"),
            path=str(path), tag=_tag_for(rule, str(title)), tool="poutine"))
    return out
