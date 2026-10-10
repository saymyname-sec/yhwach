"""Knowledge: the technique catalog as an AI recall menu.

This is the deterministic *candidate generator* — not a ranker. It loads the
restored playbook catalog (`playbooks/*.yaml`) and matches each technique's
`when` clause against the world model to answer one question per host:

    "Which catalog techniques apply here?"

The AI (the doer brain) reads the returned candidates and decides which to run
and in what order. This module deliberately does **not**:

  * score or rank (no EV, no `points`-as-sort-order — `points` survives only as
    a hint the brain may read and ignore),
  * write to the `task` table, or
  * call a model.

The one thing it does that the AI cannot do reliably is *recall*: it emits every
applicable technique, so the brain selects from a complete menu instead of
remembering the catalog. See AGENT.md § "Knowledge".

The EV ranker (`planner.py`) that used to sit on top of this matching was
removed in 7ebc4e0 and is intentionally not restored.

Supported `when` keys: surface, auth, product, os, findings_include, vault.
A rule with an unsupported key is skipped (forward-compatibility), so new keys
can live in the catalog before the matcher understands them.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from yhwach.policy import ActionClass

# Rule `risk` vocabulary -> (normalized task risk, autonomy tier). Kept from the
# old playbook loader: the read_only/exploit/destructive split is the safety
# classification the orchestrator gates on — it stays deterministic, never the
# brain's judgment.
_RISK_NORMALIZE = {
    "read_only": ("read_only", "proceed"),
    "propose": ("exploit", "propose"),
    "exploit": ("exploit", "propose"),
    "destructive": ("destructive", "ask"),
}

# `when` keys the matcher understands. A rule naming any other key is skipped.
# `stage:` is the FSM gate for post-foothold rules (e.g. pivots) — it matches
# hosts by their `host.stage` value (foothold|looted|pivoted|…) without
# requiring the operator to invent a `findings_include` tag for it.
SUPPORTED_WHEN_KEYS = {"surface", "auth", "product", "os", "stage", "findings_include", "vault"}


class KnowledgeError(ValueError):
    """Raised on a malformed technique rule or a duplicate technique id."""


@dataclass
class Technique:
    """One catalog entry: a technique the brain may choose, plus the metadata it
    reads as hints. No EV fields — `points` is a plain hint, never a sort key."""

    id: str
    when: dict[str, Any]
    emits: list[dict]
    risk: str
    autonomy: str
    points: int = 0
    maps: list[str] = field(default_factory=list)
    routes: str | None = None
    source: str | None = None
    action_class: str | None = None  # high-consequence class gated by policy.class_gate
    _class: str | None = None
    _technique: str | None = None

    @property
    def technique(self) -> str:
        """Exhaustion key. Explicit `technique:` wins, else the rule id. Rules
        sharing a `technique:` retire as a family when one is consumed."""
        return self._technique or self.id

    @property
    def technique_class(self) -> str:
        """ai | traditional | ad — a hint the brief surfaces (AI-first
        doctrine). Explicit `class:` wins; else any OWASP-LLM map => ai."""
        if self._class:
            return self._class
        if any(str(m).upper().startswith("LLM") for m in self.maps):
            return "ai"
        return "traditional"


@dataclass(frozen=True)
class Candidate:
    """An applicable technique bound to a concrete target. The unit the brief
    hands the brain. No score — ordering is the brain's job."""

    technique_id: str
    technique: str
    host_id: int
    host_ip: str
    surface_id: int | None
    surface_kind: str | None
    risk: str
    autonomy: str
    technique_class: str
    points: int
    maps: list[str]
    routes: str | None
    source: str | None
    chained_from: str | None  # the findings_include tag that lit this up, if any
    rationale: str
    action_class: str | None = None  # high-consequence class (push/listener/…) or None


def default_playbook_dir() -> Path:
    """Packaged `_playbooks` for an installed wheel, else repo `playbooks/`."""
    pkg = Path(__file__).resolve().parent / "_playbooks"
    if pkg.is_dir():
        return pkg
    return Path(__file__).resolve().parent.parent / "playbooks"


def _is_technique_rule(entry: Any) -> bool:
    """Technique rules have both `when` and `emits`. Meta entries
    (`_primitives.yaml`, `lore_denylist.yaml`) lack them and are ignored."""
    return isinstance(entry, dict) and "when" in entry and "emits" in entry


def _catalog_fingerprint(playbook_dir: Path) -> tuple:
    """Cheap, exact staleness key: name + mtime + size of every catalog file.

    Stat-ing 13 files costs microseconds; parsing them costs ~95 ms. Any edit,
    addition or removal changes the tuple, so the cache can never serve a stale
    catalog to a running engagement.
    """
    out = []
    for p in sorted(playbook_dir.glob("*.yaml")):
        try:
            st = p.stat()
        except OSError:          # vanished between glob and stat — treat as changed
            out.append((p.name, -1, -1))
        else:
            out.append((p.name, st.st_mtime_ns, st.st_size))
    return tuple(out)


@lru_cache(maxsize=4)
def _load_techniques_cached(dir_key: str, fingerprint: tuple) -> tuple[Technique, ...]:
    return tuple(_load_techniques_uncached(Path(dir_key)))


def load_techniques(playbook_dir: Path | str | None = None) -> list[Technique]:
    """Load and validate every technique from the catalog YAML files.

    Skips meta entries (no `when`/`emits`). Raises KnowledgeError on a malformed
    technique or a duplicate id.

    Cached on the catalog's own mtimes. The board re-rendered this twice every
    three seconds, and parsing the YAMLs was ~90% of a board render; the catalog
    does not change during an engagement. A fresh list is returned each call so a
    caller that mutates it cannot corrupt the cache.
    """
    playbook_dir = Path(playbook_dir) if playbook_dir else default_playbook_dir()
    return list(_load_techniques_cached(str(playbook_dir),
                                        _catalog_fingerprint(playbook_dir)))


def _load_techniques_uncached(playbook_dir: Path) -> list[Technique]:
    techniques: list[Technique] = []
    seen: set[str] = set()

    for path in sorted(playbook_dir.glob("*.yaml")):
        with path.open(encoding="utf-8") as f:
            docs = yaml.safe_load(f)
        if not isinstance(docs, list):
            continue
        for entry in docs:
            if not _is_technique_rule(entry):
                continue
            tech = _build_technique(entry, source_file=path.name)
            if tech.id in seen:
                raise KnowledgeError(f"duplicate technique id '{tech.id}' (in {path.name})")
            seen.add(tech.id)
            techniques.append(tech)

    return techniques


def _build_technique(entry: dict, *, source_file: str) -> Technique:
    tid = entry.get("id")
    if not tid:
        raise KnowledgeError(f"technique without id in {source_file}: {entry!r}")

    # Every technique in the catalog is an authorized-engagement move.
    if not entry.get("authorized_only", False):
        raise KnowledgeError(f"technique '{tid}' must set authorized_only: true")

    points = entry.get("points", 0)
    if not isinstance(points, int) or not (0 <= points <= 15):
        raise KnowledgeError(f"technique '{tid}' points must be an int in 0..15")

    raw_risk = entry.get("risk", "read_only")
    if raw_risk not in _RISK_NORMALIZE:
        raise KnowledgeError(f"technique '{tid}' has unknown risk '{raw_risk}'")
    risk, autonomy = _RISK_NORMALIZE[raw_risk]

    emits = entry.get("emits", [])
    if not isinstance(emits, list) or not emits:
        raise KnowledgeError(f"technique '{tid}' must have a non-empty emits list")

    when = entry.get("when") or {}
    if not isinstance(when, dict):
        raise KnowledgeError(f"technique '{tid}' when clause must be a mapping")

    klass = entry.get("class")
    if klass is not None and klass not in ("ai", "traditional", "ad"):
        raise KnowledgeError(f"technique '{tid}' class must be ai/traditional/ad")

    action_class = entry.get("action_class")
    if action_class is not None and action_class not in {c.value for c in ActionClass}:
        allowed = ", ".join(sorted(c.value for c in ActionClass))
        raise KnowledgeError(
            f"technique '{tid}' action_class '{action_class}' must be one of: {allowed}"
        )

    return Technique(
        id=tid,
        when=when,
        emits=emits,
        risk=risk,
        autonomy=autonomy,
        points=points,
        maps=entry.get("maps") or [],
        routes=entry.get("routes"),
        source=entry.get("source"),
        action_class=action_class,
        _class=klass,
        _technique=entry.get("technique"),
    )


def _consumed_technique_ids(conn: sqlite3.Connection, engagement_id: int) -> set[str]:
    """Technique ids (or aliases) marked consumed — the exhaustion primitive.
    A consumed technique is never resurfaced; engagements rarely reuse one infra flaw twice."""
    rows = conn.execute(
        "SELECT technique_id FROM technique_state "
        "WHERE engagement_id = ? AND status = 'consumed'",
        (engagement_id,),
    ).fetchall()
    return {r["technique_id"] for r in rows}


def _denylisted_host_ids(conn: sqlite3.Connection, engagement_id: int) -> set[int]:
    """Hosts flagged as environment dev-artifacts / known-noise (lore denylist) — filtered out so the
    brain never burns turns on a known-noise host."""
    rows = conn.execute(
        "SELECT DISTINCT host_id FROM lore_denylist_hit "
        "WHERE engagement_id = ? AND host_id IS NOT NULL",
        (engagement_id,),
    ).fetchall()
    return {r["host_id"] for r in rows}


def candidates_for(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    include_consumed: bool = False,
    techniques: list[Technique] | None = None,
) -> list[Candidate]:
    """Every applicable technique for the engagement (or one host), as a flat
    candidate list. Pure read: no scoring, no ranking, no DB writes.

    Exhausted (consumed) techniques and denylisted hosts are filtered unless
    `include_consumed` is set. Pass `techniques` to reuse an already-loaded
    catalog; otherwise it is loaded from the default dir.
    """
    if techniques is None:
        techniques = load_techniques()

    consumed = set() if include_consumed else _consumed_technique_ids(conn, engagement_id)
    denylisted = _denylisted_host_ids(conn, engagement_id)

    out: list[Candidate] = []
    for tech in techniques:
        if set(tech.when) - SUPPORTED_WHEN_KEYS:
            continue  # forward-compat: unknown when-key, skip
        if tech.technique in consumed or tech.id in consumed:
            continue
        for row in _match_targets(conn, engagement_id, tech, host_ip=host_ip):
            if row["host_id"] in denylisted:
                continue
            out.append(_to_candidate(tech, row))
    return out


def _match_targets(
    conn: sqlite3.Connection,
    engagement_id: int,
    tech: Technique,
    *,
    host_ip: str | None,
) -> list[dict]:
    """Target rows for a technique.

    Three scopings, checked in order:
      * ``surface`` — match surface rows (the traditional matcher path)
      * ``findings_include`` — match hosts carrying a chaining-tag finding
      * ``stage`` — match hosts by their FSM stage (post-foothold rules)

    All three return the same dict shape so callers treat them uniformly.
    """
    if "surface" in tech.when:
        return _match_surfaces(conn, engagement_id, tech, host_ip=host_ip)
    if "findings_include" in tech.when:
        return _match_hosts(conn, engagement_id, tech, host_ip=host_ip)
    if "stage" in tech.when:
        return _match_hosts_by_stage(conn, engagement_id, tech, host_ip=host_ip)
    if "os" in tech.when:
        # os-only rules (e.g. revshell generators) match every host of that OS —
        # they are payload-producing hints available at any stage.
        return _match_hosts_by_os(conn, engagement_id, tech, host_ip=host_ip)
    return []


def _match_surfaces(
    conn: sqlite3.Connection,
    engagement_id: int,
    tech: Technique,
    *,
    host_ip: str | None,
) -> list[dict]:
    when = tech.when
    clauses = ["h.engagement_id = ?"]
    params: list = [engagement_id]

    clauses.append("s.kind = ?")
    params.append(when["surface"])
    if "auth" in when:
        clauses.append("s.auth = ?")
        params.append(when["auth"])
    if "os" in when:
        clauses.append("h.os = ?")
        params.append(when["os"])
    if "stage" in when:
        clauses.append("h.stage = ?")
        params.append(when["stage"])
    if "product" in when:
        clauses.append("svc.product LIKE ?")
        params.append(f"%{when['product']}%")
    if "findings_include" in when:
        clauses.append(
            "EXISTS (SELECT 1 FROM finding f WHERE f.host_id = h.id "
            "AND f.tag = ? AND f.status = 'open')"
        )
        params.append(when["findings_include"])
    if "vault" in when:  # `vault: nonempty` — engagement has recovered credentials
        clauses.append(
            "EXISTS (SELECT 1 FROM credential c WHERE c.engagement_id = h.engagement_id)"
        )
    if host_ip is not None:
        clauses.append("h.ip = ?")
        params.append(host_ip)

    sql = (
        "SELECT s.id AS surface_id, s.host_id AS host_id, h.ip AS host_ip, "
        "s.kind AS kind FROM surface s "
        "JOIN host h ON h.id = s.host_id "
        "LEFT JOIN service svc ON svc.id = s.service_id "
        f"WHERE {' AND '.join(clauses)}"
    )
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _match_hosts(
    conn: sqlite3.Connection,
    engagement_id: int,
    tech: Technique,
    *,
    host_ip: str | None,
) -> list[dict]:
    """Hosts carrying the `findings_include` tag (surface-less rules). surface_id
    is None so callers treat these uniformly with surface rows."""
    when = tech.when
    clauses = ["h.engagement_id = ?"]
    params: list = [engagement_id]
    if "os" in when:
        clauses.append("h.os = ?")
        params.append(when["os"])
    clauses.append(
        "EXISTS (SELECT 1 FROM finding f WHERE f.host_id = h.id "
        "AND f.tag = ? AND f.status = 'open')"
    )
    params.append(when["findings_include"])
    if "vault" in when:
        clauses.append(
            "EXISTS (SELECT 1 FROM credential c WHERE c.engagement_id = h.engagement_id)"
        )
    if host_ip is not None:
        clauses.append("h.ip = ?")
        params.append(host_ip)
    sql = f"SELECT h.id AS host_id, h.ip AS host_ip FROM host h WHERE {' AND '.join(clauses)}"
    return [
        {"surface_id": None, "host_id": r["host_id"], "host_ip": r["host_ip"], "kind": None}
        for r in conn.execute(sql, params).fetchall()
    ]


def _match_hosts_by_os(
    conn: sqlite3.Connection,
    engagement_id: int,
    tech: Technique,
    *,
    host_ip: str | None,
) -> list[dict]:
    """Every host of a given ``os`` in the engagement (os-only rules).

    Revshell-generator rules use this branch — the payload is picked once you
    know the target's OS, regardless of stage. ``host_ip`` narrows to a single
    host when the caller has scoped the brief that way.
    """
    when = tech.when
    clauses = ["h.engagement_id = ?", "h.os = ?"]
    params: list = [engagement_id, when["os"]]
    if host_ip is not None:
        clauses.append("h.ip = ?")
        params.append(host_ip)
    sql = f"SELECT h.id AS host_id, h.ip AS host_ip FROM host h WHERE {' AND '.join(clauses)}"
    return [
        {"surface_id": None, "host_id": r["host_id"], "host_ip": r["host_ip"], "kind": None}
        for r in conn.execute(sql, params).fetchall()
    ]


def _match_hosts_by_stage(
    conn: sqlite3.Connection,
    engagement_id: int,
    tech: Technique,
    *,
    host_ip: str | None,
) -> list[dict]:
    """Hosts filtered by their FSM ``stage`` (surface-less post-foothold rules).

    Pivot / persistence / privesc rules light up when the target has crossed
    ``foothold`` (or ``looted``/``pivoted``). ``os`` / ``vault`` further
    narrow the match. Same dict shape as :func:`_match_hosts` so downstream
    treats stage-gated candidates uniformly.
    """
    when = tech.when
    clauses = ["h.engagement_id = ?", "h.stage = ?"]
    params: list = [engagement_id, when["stage"]]
    if "os" in when:
        clauses.append("h.os = ?")
        params.append(when["os"])
    if "vault" in when:
        clauses.append(
            "EXISTS (SELECT 1 FROM credential c WHERE c.engagement_id = h.engagement_id)"
        )
    if host_ip is not None:
        clauses.append("h.ip = ?")
        params.append(host_ip)
    sql = f"SELECT h.id AS host_id, h.ip AS host_ip FROM host h WHERE {' AND '.join(clauses)}"
    return [
        {"surface_id": None, "host_id": r["host_id"], "host_ip": r["host_ip"], "kind": None}
        for r in conn.execute(sql, params).fetchall()
    ]


def _to_candidate(tech: Technique, row: dict) -> Candidate:
    chained_from = tech.when.get("findings_include")
    if row["kind"]:
        rationale = f"technique {tech.id} applies to {row['kind']} surface"
    elif chained_from:
        rationale = f"technique {tech.id} chains from finding '{chained_from}'"
    else:
        rationale = f"technique {tech.id} applies"
    return Candidate(
        technique_id=tech.id,
        technique=tech.technique,
        host_id=row["host_id"],
        host_ip=row["host_ip"],
        surface_id=row["surface_id"],
        surface_kind=row["kind"],
        risk=tech.risk,
        autonomy=tech.autonomy,
        technique_class=tech.technique_class,
        points=tech.points,
        maps=list(tech.maps),
        routes=tech.routes,
        source=tech.source,
        chained_from=chained_from,
        rationale=rationale,
        action_class=tech.action_class,
    )
