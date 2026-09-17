"""Cross-cutting primitives: lore denylist + technique exhaustion.

Both are invariants the planner enforces (see playbooks/_primitives.yaml):

  * lore_denylist    — OffSec dev artifacts (cloudbase-init, placeholders) are
    tagged on the host and filtered out of ranking. `check_denylist` matches
    arbitrary text (a banner, enum output) against the entries in
    playbooks/lore_denylist.yaml.
  * technique_exhaustion — a technique that has landed is marked consumed for the
    engagement; the planner never re-ranks it. OSAI labs don't reuse infra flaws.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Lore denylist
# --------------------------------------------------------------------------
@dataclass
class DenylistEntry:
    artifact: str
    needles: list[str]  # lowercased substrings; any hit tags the artifact


def load_denylist(playbook_dir: Path | str) -> list[DenylistEntry]:
    path = Path(playbook_dir) / "lore_denylist.yaml"
    if not path.exists():
        return []
    docs = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    entries: list[DenylistEntry] = []
    for d in docs:
        if not isinstance(d, dict) or "artifact" not in d:
            continue
        needles: list[str] = []
        for m in d.get("match", []):
            if isinstance(m, dict):
                needles += [str(v).lower() for v in m.values()]
            elif isinstance(m, str):
                needles.append(m.lower())
        # Normalize glob-ish noise so 'C:\...\**' still matches a real path fragment.
        needles = [n.replace("**", "").strip() for n in needles if n and n.strip("*/\\ ")]
        entries.append(DenylistEntry(d["artifact"], needles))
    return entries


def check_denylist(text: str, entries: list[DenylistEntry]) -> str | None:
    """Return the first matching artifact name, or None."""
    low = (text or "").lower()
    if not low:
        return None
    for e in entries:
        for n in e.needles:
            frag = n.strip("*/\\ ")
            if frag and frag in low:
                return e.artifact
    return None


def record_denylist_hit(
    conn: sqlite3.Connection,
    engagement_id: int,
    host_id: int | None,
    artifact: str,
) -> bool:
    """Record a denylist hit and tag the host `dev_artifact`. Returns True if new."""
    existing = conn.execute(
        "SELECT id FROM lore_denylist_hit WHERE engagement_id = ? AND host_id IS ? "
        "AND artifact = ?",
        (engagement_id, host_id, artifact),
    ).fetchone()
    if existing is not None:
        return False
    conn.execute(
        "INSERT INTO lore_denylist_hit (engagement_id, host_id, artifact, seen_at) "
        "VALUES (?, ?, ?, ?)",
        (engagement_id, host_id, artifact, _now()),
    )
    if host_id is not None:
        row = conn.execute("SELECT tags FROM host WHERE id = ?", (host_id,)).fetchone()
        tags = {t for t in (row["tags"] or "").split(",") if t}
        tags.add("dev_artifact")
        conn.execute("UPDATE host SET tags = ? WHERE id = ?", (",".join(sorted(tags)), host_id))
    return True


def denylisted_host_ids(conn: sqlite3.Connection, engagement_id: int) -> set[int]:
    rows = conn.execute(
        "SELECT DISTINCT host_id FROM lore_denylist_hit "
        "WHERE engagement_id = ? AND host_id IS NOT NULL",
        (engagement_id,),
    ).fetchall()
    return {r["host_id"] for r in rows}


# --------------------------------------------------------------------------
# Technique exhaustion
# --------------------------------------------------------------------------
def mark_technique_consumed(
    conn: sqlite3.Connection,
    engagement_id: int,
    technique_id: str,
    host_id: int | None = None,
) -> bool:
    """Mark a technique consumed for the engagement. Returns True if newly created."""
    existing = conn.execute(
        "SELECT id FROM technique_state WHERE engagement_id = ? AND technique_id = ?",
        (engagement_id, technique_id),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE technique_state SET status = 'consumed', consumed_on_host_id = ?, "
            "consumed_at = ? WHERE id = ?",
            (host_id, _now(), existing["id"]),
        )
        return False
    conn.execute(
        "INSERT INTO technique_state (engagement_id, technique_id, status, "
        "consumed_on_host_id, consumed_at) VALUES (?, ?, 'consumed', ?, ?)",
        (engagement_id, technique_id, host_id, _now()),
    )
    return True


def consumed_techniques(conn: sqlite3.Connection, engagement_id: int) -> set[str]:
    rows = conn.execute(
        "SELECT technique_id FROM technique_state "
        "WHERE engagement_id = ? AND status = 'consumed'",
        (engagement_id,),
    ).fetchall()
    return {r["technique_id"] for r in rows}


# --------------------------------------------------------------------------
# high_ev_leads — auto-P0
# --------------------------------------------------------------------------
# Finding tags that historically produce a credential/DA path in OSAI-style labs.
# When present, the operator handoff surfaces them as P0 so they're attacked
# before lower-value work (see playbooks/_primitives.yaml: high_ev_leads).
P0_LEAD_TAGS = frozenset({
    "dcsync", "kerberoastable", "asreproastable", "adcs_vuln",
    "unconstrained_delegation", "chrome_login_data", "dpapi_master_key",
    "gpp_password", "aws_credentials",
})


def p0_leads(conn: sqlite3.Connection, engagement_id: int) -> list[sqlite3.Row]:
    """Open findings whose tag is a high-EV lead, most severe first."""
    tags = sorted(P0_LEAD_TAGS)
    placeholders = ",".join("?" * len(tags))
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 ELSE 3 END")
    return conn.execute(
        "SELECT f.tag AS tag, f.title AS title, f.severity AS severity, h.ip AS ip "
        "FROM finding f LEFT JOIN host h ON h.id = f.host_id "
        "WHERE (h.engagement_id = ? OR f.host_id IS NULL) AND f.status = 'open' "
        f"AND f.tag IN ({placeholders}) ORDER BY {order}, f.id",
        (engagement_id, *tags),
    ).fetchall()
