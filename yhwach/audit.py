"""Audit / methodology lens over memory.

The taxonomy axis (`finding.class`: ATT&CK T#### / OWASP LLM## / ATLAS / CWE / CVE)
turns the engagement memory into a standards-aligned, auditable record. Two views,
both pure reads:

- `findings_by_standard` — coverage BY taxonomy family, not by host: which
  standards we have proven findings against (feeds a report section).
- `methodology_audit` — the self-assessment: what paths exist that we did NOT
  check (the service_enum / scan-coverage gaps) alongside the standards coverage.

This is the "audit and everywhere" use of the knowledge: the same rows that drive
recall also answer "which tactics did we exercise, and what did we skip?".
"""
from __future__ import annotations

import re
import sqlite3

from yhwach.coverage import enum_gaps, render_gaps

# finding.class value -> the standards family it belongs to. Ordered: the first
# predicate that matches wins (ATLAS before the bare-T ATT&CK check).
_FAMILIES: list[tuple[str, re.Pattern[str]]] = [
    ("ATLAS", re.compile(r"^(ATLAS-|AML\.)", re.I)),
    ("OWASP-LLM", re.compile(r"^LLM\d", re.I)),
    ("OWASP-ML", re.compile(r"^ML\d", re.I)),
    ("ATT&CK", re.compile(r"^T\d{4}")),
    ("CWE", re.compile(r"^CWE-", re.I)),
    ("CVE", re.compile(r"^CVE-", re.I)),
]


def _family(cls: str) -> str:
    for name, pat in _FAMILIES:
        if pat.match(cls):
            return name
    return "other"


def findings_by_standard(conn: sqlite3.Connection, engagement_id: int) -> dict[str, dict]:
    """{family: {"count": n, "ids": sorted[str]}} over open findings' `class`."""
    rows = conn.execute(
        "SELECT class, COUNT(*) n FROM finding "
        "WHERE engagement_id = ? AND COALESCE(class, '') <> '' AND status IN ('open','confirmed','exploited') "
        "GROUP BY class",
        (engagement_id,),
    ).fetchall()
    fam: dict[str, dict] = {}
    for r in rows:
        f = _family(str(r["class"]))
        bucket = fam.setdefault(f, {"count": 0, "ids": set()})
        bucket["count"] += r["n"]
        bucket["ids"].add(str(r["class"]))
    # freeze ids to a sorted list for stable rendering / JSON
    for b in fam.values():
        b["ids"] = sorted(b["ids"])
    return fam


# Family render order (most methodology-relevant first).
_ORDER = ["ATT&CK", "ATLAS", "OWASP-LLM", "OWASP-ML", "CWE", "CVE", "other"]


def render_findings_by_standard(fam: dict[str, dict]) -> list[str]:
    if not fam:
        return ["- (no classified findings yet)"]
    lines: list[str] = []
    for name in _ORDER:
        if name in fam:
            b = fam[name]
            lines.append(f"- **{name}** ({b['count']}): " + " · ".join(b["ids"]))
    return lines


# The OWASP LLM Top-10 (2025) reference set. The methodology matrix diffs the
# engagement's classified findings against THIS, so "which class did I never test"
# becomes an actionable gap rather than a guess.
OWASP_LLM_TOP10: list[tuple[str, str]] = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
]


def _has_ai_surface(conn: sqlite3.Connection, engagement_id: int) -> bool:
    """True if the engagement has any AI attack surface — the difference between
    ABSENT (a testable class we never exercised) and UNKNOWN (no AI surface at
    all, so the class is not assessable here)."""
    from yhwach.brief import AI_KINDS

    ph = ",".join("?" * len(AI_KINDS))
    row = conn.execute(
        f"SELECT 1 FROM surface s JOIN host h ON h.id=s.host_id "
        f"WHERE h.engagement_id=? AND s.kind IN ({ph}) LIMIT 1",
        (engagement_id, *AI_KINDS),
    ).fetchone()
    return row is not None


def _tested_llm_classes(conn: sqlite3.Connection, engagement_id: int) -> set[str]:
    """Normalised LLM numbers (LLM01..LLM10) with >=1 open finding classed to them."""
    rows = conn.execute(
        "SELECT DISTINCT class FROM finding WHERE engagement_id=? AND status IN ('open','confirmed','exploited') "
        "AND UPPER(COALESCE(class,'')) LIKE 'LLM%'",
        (engagement_id,),
    ).fetchall()
    seen: set[str] = set()
    for r in rows:
        m = re.match(r"LLM(\d{1,2})", str(r["class"]).upper())
        if m:
            seen.add(f"LLM{int(m.group(1)):02d}")
    return seen


def llm_coverage(conn: sqlite3.Connection, engagement_id: int) -> list[dict]:
    """PRESENT / ABSENT / UNKNOWN per OWASP-LLM Top-10 class.

    PRESENT = a proven finding of that class; ABSENT = an AI surface exists but no
    finding of that class (a methodology gap on a testable surface); UNKNOWN = no
    AI surface in scope, so the class is not assessable here."""
    tested = _tested_llm_classes(conn, engagement_id)
    has_ai = _has_ai_surface(conn, engagement_id)
    out: list[dict] = []
    for lid, title in OWASP_LLM_TOP10:
        status = "PRESENT" if lid in tested else ("ABSENT" if has_ai else "UNKNOWN")
        out.append({"id": lid, "title": title, "status": status})
    return out


_LLM_MARK = {"PRESENT": "[x]", "ABSENT": "[ ]", "UNKNOWN": "[?]"}


def render_llm_coverage(rows: list[dict]) -> list[str]:
    return [f"- {_LLM_MARK[r['status']]} {r['id']} {r['title']} — {r['status']}" for r in rows]


def _untriaged_surface_count(conn: sqlite3.Connection, engagement_id: int) -> int:
    """service_enum gaps across active hosts — surfaces seen but not checked."""
    return sum(
        1
        for hc in enum_gaps(conn, engagement_id)
        for g in hc.gaps
        if g.kind == "service_enum"
    )


def methodology_audit(conn: sqlite3.Connection, engagement_id: int) -> str:
    """The self-assessment report: standards coverage + what wasn't checked."""
    out: list[str] = ["# METHODOLOGY AUDIT", ""]

    fam = findings_by_standard(conn, engagement_id)
    out += ["## Coverage by standard (proven findings)"]
    out += render_findings_by_standard(fam)
    out.append("")

    # OWASP-LLM Top-10 methodology matrix — only when there is an AI surface (or a
    # classified AI finding), else it is 10 lines of UNKNOWN noise on a pure-AD lab.
    llm = llm_coverage(conn, engagement_id)
    if any(r["status"] != "UNKNOWN" for r in llm):
        tested = sum(1 for r in llm if r["status"] == "PRESENT")
        out += [f"## OWASP-LLM Top-10 coverage ({tested}/{len(llm)} exercised)"]
        out += render_llm_coverage(llm)
        out.append("")

    gaps = enum_gaps(conn, engagement_id)
    untriaged = _untriaged_surface_count(conn, engagement_id)
    out += ["## Paths not yet checked"]
    out.append(f"- {untriaged} discovered surface(s) with no triage (service_enum gap)")
    out.append(f"- {len(gaps)} active host(s) with an open enumeration gap")
    out.append("")
    out += ["## Gap detail (worst first)"]
    out += render_gaps(gaps, limit=15)

    return "\n".join(out).rstrip() + "\n"


def audit_as_dict(conn: sqlite3.Connection, engagement_id: int) -> dict:
    """JSON-shaped view for `--json`."""
    fam = findings_by_standard(conn, engagement_id)
    return {
        "by_standard": {k: {"count": v["count"], "ids": v["ids"]} for k, v in fam.items()},
        "owasp_llm": llm_coverage(conn, engagement_id),
        "untriaged_surfaces": _untriaged_surface_count(conn, engagement_id),
        "hosts_with_gaps": len(enum_gaps(conn, engagement_id)),
    }
