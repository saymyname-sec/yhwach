"""Version -> CVE enrichment — the software-knowledge brain.

Matches each `software` row against the bundled CVE knowledge base
(data/cve_map.yaml) and records `vulnerability` rows. Entries whose version
predicate matches AND that carry an `exploit` also emit an `exploitable_cve`
finding, so the `exploit_known_cve` playbook rule chains straight to the exploit.

Fully offline and deterministic — no NVD lookup, no network. The map is curated,
so a match is high-signal, not the noise a blanket CPE feed would produce.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from functools import lru_cache

import yaml

from yhwach import cve_map_path
from yhwach import db as yhdb


@dataclass
class CveEntry:
    product: str
    cpe: str | None
    affected: str
    cve: str
    cvss: float | None
    title: str
    exploit: str | None


@lru_cache(maxsize=1)
def load_cve_map() -> list[CveEntry]:
    raw = yaml.safe_load(cve_map_path().read_text(encoding="utf-8")) or []
    out: list[CveEntry] = []
    for e in raw:
        if not isinstance(e, dict) or not e.get("cve"):
            continue
        out.append(CveEntry(
            product=str(e.get("product", "")).lower(),
            cpe=(str(e["cpe"]).lower() if e.get("cpe") else None),
            affected=str(e.get("affected", "*")),
            cve=str(e["cve"]),
            cvss=e.get("cvss"),
            title=str(e.get("title", "")),
            exploit=(str(e["exploit"]) if e.get("exploit") else None),
        ))
    return out


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Leading dotted-numeric prefix as an int tuple: '5.17.4p2' -> (5,17,4).

    A trailing patch letter/suffix ('1.9.5p2', '2.4.50-ubuntu') is dropped — good
    enough for the coarse ranges the curated map uses."""
    nums = re.findall(r"\d+", v.split("-")[0])
    return tuple(int(n) for n in nums[:4]) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    # pad to equal length so (5,17) vs (5,17,0) compare equal
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


_OPS = [("<=", lambda c: c <= 0), (">=", lambda c: c >= 0),
        ("<", lambda c: c < 0), (">", lambda c: c > 0),
        ("==", lambda c: c == 0)]


def version_matches(version: str, predicate: str) -> bool:
    """True if `version` satisfies a comma-AND predicate ('>=2.0,<2.17.1', '<0.1.34', '*')."""
    predicate = predicate.strip()
    if predicate in ("*", ""):
        return True
    for clause in predicate.split(","):
        clause = clause.strip()
        for op, test in _OPS:
            if clause.startswith(op):
                target = clause[len(op):].strip()
                if not test(_cmp(version, target)):
                    return False
                break
        else:
            # bare version means exact match
            if _cmp(version, clause) != 0:
                return False
    return True


def _entry_matches_software(entry: CveEntry, name: str, cpe: str | None) -> bool:
    name = (name or "").lower()
    cpe = (cpe or "").lower()
    if entry.product and entry.product in name:
        return True
    return bool(entry.cpe and cpe and entry.cpe in cpe)


def enrich(conn: sqlite3.Connection, engagement_id: int) -> dict:
    """Match every versioned software row against the CVE map; record vulns +
    exploitable_cve findings. Returns a summary. Idempotent (helpers dedupe)."""
    cmap = load_cve_map()
    rows = conn.execute(
        "SELECT s.id AS sid, s.host_id AS hid, s.name AS name, s.version AS version, "
        "s.service_id AS service_id, s.cpe AS cpe FROM software s "
        "JOIN host h ON h.id = s.host_id WHERE h.engagement_id = ? AND s.version IS NOT NULL",
        (engagement_id,),
    ).fetchall()

    matched = 0
    exploitable = 0
    hits: list[str] = []
    for r in rows:
        for entry in cmap:
            if not _entry_matches_software(entry, r["name"], r["cpe"]):
                continue
            if not version_matches(r["version"], entry.affected):
                continue
            has_exploit = bool(entry.exploit)
            yhdb.add_vulnerability(
                conn, engagement_id, r["hid"], entry.cve,
                software_id=r["sid"], service_id=r["service_id"], title=entry.title,
                cvss=entry.cvss, state="confirmed", exploit_ref=entry.exploit,
                exploit_available=has_exploit, source="version_match")
            matched += 1
            tag = "exploitable_cve" if has_exploit else "cve_match"
            sev = "critical" if (entry.cvss or 0) >= 9 else "high"
            yhdb.add_finding(
                conn, r["hid"], None, entry.cve, f"{entry.cve} — {entry.title}", sev,
                f"{r['name']} {r['version']} matches {entry.affected}", tag=tag)
            if has_exploit:
                exploitable += 1
            hits.append(f"{r['name']} {r['version']} -> {entry.cve} ({entry.title})")

    return {"software_checked": len(rows), "matched": matched,
            "exploitable": exploitable, "hits": hits}
