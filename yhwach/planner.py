"""Deterministic planner: match playbook rules against the world model and
populate the task queue with EV-scored candidate actions. No LLM in this layer.

Supported `when` keys: surface, auth, product, os, findings_include, vault. A rule
that names a `surface` produces surface-scoped tasks; a rule with only
`findings_include` (no surface) produces finding-gated, host-scoped tasks. Any
other key is unsupported: the rule is skipped and reported so forward-compatible
rules can live in the playbooks without breaking the matcher.

`findings_include: <tag>` matches only when the target host has an open finding
carrying that `tag` (set by the interpret extractors / ingest) — this is the
post-foothold chaining mechanism. `vault: nonempty` matches only when the
engagement has recovered credentials (creds-aware rules, e.g. kerberoast).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime

from yhwach.playbooks import Rule
from yhwach.primitives import consumed_techniques, denylisted_host_ids

SUPPORTED_WHEN_KEYS = {"surface", "auth", "product", "os", "findings_include", "vault"}


@dataclass
class MatchReport:
    tasks_created: int = 0
    tasks_updated: int = 0
    rules_matched: int = 0
    rules_skipped_unsupported: list[str] = field(default_factory=list)
    rules_skipped_consumed: list[str] = field(default_factory=list)
    surfaces_filtered_denylist: int = 0
    rules_ev_decayed: list[str] = field(default_factory=list)


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _task_kind_for(rule: Rule) -> str:
    if rule.risk == "read_only":
        return "probe"
    if rule.risk == "exploit":
        return "craft_injection"
    return "exploit"


def match_rules(
    conn: sqlite3.Connection,
    engagement_id: int,
    rules: list[Rule],
) -> MatchReport:
    """Match every rule against current surfaces; upsert a task per matching surface.

    Applies the cross-cutting primitives: consumed techniques are skipped, and
    surfaces on denylisted (dev-artifact) hosts are filtered out.
    """
    from yhwach.memory import decayed_ev, failure_counts

    report = MatchReport()
    consumed = consumed_techniques(conn, engagement_id)
    denylisted = denylisted_host_ids(conn, engagement_id)
    # Attempts the operator reported as fail/blocked decay that rule's EV on
    # that host. Recomputed here every plan (never a persisted mutation), so the
    # ranking stays a pure function of rules + world model + attempt ledger.
    fails = failure_counts(conn, engagement_id)

    for rule in rules:
        unsupported = set(rule.when.keys()) - SUPPORTED_WHEN_KEYS
        if unsupported:
            report.rules_skipped_unsupported.append(rule.id)
            continue

        # A technique is consumed if either its alias (`technique:`) or its rule
        # id was marked — `yhwach consume` accepts either, so match both.
        if rule.technique in consumed or rule.id in consumed:
            report.rules_skipped_consumed.append(rule.id)
            # Retire any pending tasks already queued for this rule.
            conn.execute(
                "UPDATE task SET status = 'abandoned', updated_at = ? "
                "WHERE engagement_id = ? AND playbook_rule_id = ? AND status = 'pending'",
                (_now_utc(), engagement_id, rule.id),
            )
            continue

        targets = _match_targets(conn, engagement_id, rule)
        kept = [t for t in targets if t["host_id"] not in denylisted]
        report.surfaces_filtered_denylist += len(targets) - len(kept)
        if kept:
            report.rules_matched += 1
        for surf in kept:
            n = fails.get((rule.id, surf["host_id"]), 0)
            ev = decayed_ev(rule.ev_score, n)
            if n:
                report.rules_ev_decayed.append(f"{rule.id}({n})")
            created, updated = _upsert_task(conn, engagement_id, rule, surf, ev_score=ev)
            report.tasks_created += created
            report.tasks_updated += updated

    return report


def _match_targets(conn: sqlite3.Connection, engagement_id: int, rule: Rule) -> list:
    """Rows to build tasks from: surface rows when the rule scopes a `surface`,
    else finding-gated host rows (surface_id = None) for a `findings_include`-only
    rule. Each row exposes host_id / surface_id / kind."""
    if "surface" in rule.when:
        return _matching_surfaces(conn, engagement_id, rule)
    if "findings_include" in rule.when:
        return _matching_hosts(conn, engagement_id, rule)
    return []


def _matching_surfaces(
    conn: sqlite3.Connection,
    engagement_id: int,
    rule: Rule,
) -> list[sqlite3.Row]:
    clauses = ["h.engagement_id = ?"]
    params: list = [engagement_id]

    when = rule.when
    if "surface" in when:
        clauses.append("s.kind = ?")
        params.append(when["surface"])
    if "auth" in when:
        clauses.append("s.auth = ?")
        params.append(when["auth"])
    if "os" in when:
        clauses.append("h.os = ?")
        params.append(when["os"])
    if "product" in when:
        clauses.append("svc.product LIKE ?")
        params.append(f"%{when['product']}%")
    if "findings_include" in when:
        clauses.append(
            "EXISTS (SELECT 1 FROM finding f WHERE f.host_id = h.id "
            "AND f.tag = ? AND f.status = 'open')"
        )
        params.append(when["findings_include"])
    if "vault" in when:  # `vault: nonempty` — the engagement has recovered credentials
        clauses.append("EXISTS (SELECT 1 FROM credential c WHERE c.engagement_id = h.engagement_id)")

    sql = (
        "SELECT s.id AS surface_id, s.host_id AS host_id, s.kind AS kind "
        "FROM surface s "
        "JOIN host h ON h.id = s.host_id "
        "LEFT JOIN service svc ON svc.id = s.service_id "
        f"WHERE {' AND '.join(clauses)}"
    )
    return conn.execute(sql, params).fetchall()


def _matching_hosts(
    conn: sqlite3.Connection,
    engagement_id: int,
    rule: Rule,
) -> list[dict]:
    """Hosts that carry the rule's `findings_include` tag (surface-less rules).

    Returns surface-shaped dicts with surface_id = None so the task upsert can
    treat them uniformly with surface rows."""
    when = rule.when
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
        clauses.append("EXISTS (SELECT 1 FROM credential c WHERE c.engagement_id = h.engagement_id)")
    sql = f"SELECT h.id AS host_id FROM host h WHERE {' AND '.join(clauses)}"
    return [{"surface_id": None, "host_id": r["host_id"], "kind": None}
            for r in conn.execute(sql, params).fetchall()]


def _upsert_task(
    conn: sqlite3.Connection,
    engagement_id: int,
    rule: Rule,
    surf: sqlite3.Row,
    *,
    ev_score: float | None = None,
) -> tuple[int, int]:
    now = _now_utc()
    if ev_score is None:
        ev_score = rule.ev_score
    rationale = (f"rule {rule.id} matched {surf['kind']} surface" if surf["kind"]
                 else f"rule {rule.id} matched finding-gated host")

    if surf["surface_id"] is not None:
        existing = conn.execute(
            "SELECT id FROM task WHERE playbook_rule_id = ? AND target_surface_id = ?",
            (rule.id, surf["surface_id"]),
        ).fetchone()
    else:
        # Host-scoped task (findings_include-only rule): dedupe by (rule, host).
        existing = conn.execute(
            "SELECT id FROM task WHERE playbook_rule_id = ? AND target_host_id = ? "
            "AND target_surface_id IS NULL",
            (rule.id, surf["host_id"]),
        ).fetchone()

    if existing is not None:
        conn.execute(
            "UPDATE task SET ev_score = ?, rationale = ?, risk = ?, autonomy = ?, "
            "kind = ?, technique_class = ?, updated_at = ? WHERE id = ?",
            (
                ev_score,
                rationale,
                rule.risk,
                rule.autonomy,
                _task_kind_for(rule),
                rule.technique_class,
                now,
                existing["id"],
            ),
        )
        return 0, 1

    conn.execute(
        "INSERT INTO task (engagement_id, target_host_id, target_surface_id, kind, "
        "playbook_rule_id, technique_class, rationale, risk, autonomy, ev_score, "
        "status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
        (
            engagement_id,
            surf["host_id"],
            surf["surface_id"],
            _task_kind_for(rule),
            rule.id,
            rule.technique_class,
            rationale,
            rule.risk,
            rule.autonomy,
            ev_score,
            now,
        ),
    )
    return 1, 0


def top_tasks(
    conn: sqlite3.Connection,
    engagement_id: int,
    limit: int = 5,
    *,
    host_ip: str | None = None,
) -> list[sqlite3.Row]:
    """Pending tasks, AI-first then EV descending (id as stable tie-break).

    The `technique_class` tier enforces the OSAI doctrine — AI hosts before
    traditional — regardless of raw EV, so a low-EV AI move still outranks a
    high-EV traditional one. Within a tier, EV decides.

    `host_ip` filters BEFORE the limit (a per-host focus must not lose that
    host's lower-ranked tasks to globally higher-ranked ones on other hosts).
    """
    clauses = ["t.engagement_id = ?", "t.status = 'pending'"]
    params: list = [engagement_id]
    if host_ip is not None:
        clauses.append("h.ip = ?")
        params.append(host_ip)
    params.append(limit)
    return conn.execute(
        "SELECT t.id, t.kind, t.playbook_rule_id, t.technique_class, t.rationale, "
        "t.risk, t.autonomy, t.ev_score, t.status, h.ip AS host_ip, "
        "s.kind AS surface_kind, s.meta_json AS surface_meta, svc.port AS surface_port "
        "FROM task t "
        "JOIN host h ON h.id = t.target_host_id "
        "LEFT JOIN surface s ON s.id = t.target_surface_id "
        "LEFT JOIN service svc ON svc.id = s.service_id "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY CASE t.technique_class WHEN 'ai' THEN 0 ELSE 1 END ASC, "
        "t.ev_score DESC, t.id ASC "
        "LIMIT ?",
        params,
    ).fetchall()
