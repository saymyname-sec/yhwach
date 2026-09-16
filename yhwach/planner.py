"""Deterministic planner: match playbook rules against the world model and
populate the task queue with EV-scored candidate actions. No LLM in this layer.

Phase 1.3 supports a subset of `when` keys: surface, auth, product, os. Rules
that use unsupported keys (e.g. findings_include) are skipped and reported, so
forward-compatible rules can live in the playbooks without breaking the matcher.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

from yhwach.playbooks import Rule
from yhwach.primitives import consumed_techniques, denylisted_host_ids

SUPPORTED_WHEN_KEYS = {"surface", "auth", "product", "os"}


@dataclass
class MatchReport:
    tasks_created: int = 0
    tasks_updated: int = 0
    rules_matched: int = 0
    rules_skipped_unsupported: list[str] = field(default_factory=list)
    rules_skipped_consumed: list[str] = field(default_factory=list)
    surfaces_filtered_denylist: int = 0


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    report = MatchReport()
    consumed = consumed_techniques(conn, engagement_id)
    denylisted = denylisted_host_ids(conn, engagement_id)

    for rule in rules:
        unsupported = set(rule.when.keys()) - SUPPORTED_WHEN_KEYS
        if unsupported:
            report.rules_skipped_unsupported.append(rule.id)
            continue

        if rule.technique in consumed:
            report.rules_skipped_consumed.append(rule.id)
            # Retire any pending tasks already queued for this rule.
            conn.execute(
                "UPDATE task SET status = 'abandoned', updated_at = ? "
                "WHERE engagement_id = ? AND playbook_rule_id = ? AND status = 'pending'",
                (_now_utc(), engagement_id, rule.id),
            )
            continue

        surfaces = _matching_surfaces(conn, engagement_id, rule)
        kept = [s for s in surfaces if s["host_id"] not in denylisted]
        report.surfaces_filtered_denylist += len(surfaces) - len(kept)
        if kept:
            report.rules_matched += 1
        for surf in kept:
            created, updated = _upsert_task(conn, engagement_id, rule, surf)
            report.tasks_created += created
            report.tasks_updated += updated

    return report


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

    sql = (
        "SELECT s.id AS surface_id, s.host_id AS host_id, s.kind AS kind "
        "FROM surface s "
        "JOIN host h ON h.id = s.host_id "
        "LEFT JOIN service svc ON svc.id = s.service_id "
        f"WHERE {' AND '.join(clauses)}"
    )
    return conn.execute(sql, params).fetchall()


def _upsert_task(
    conn: sqlite3.Connection,
    engagement_id: int,
    rule: Rule,
    surf: sqlite3.Row,
) -> tuple[int, int]:
    now = _now_utc()
    rationale = f"rule {rule.id} matched {surf['kind']} surface"

    existing = conn.execute(
        "SELECT id FROM task WHERE playbook_rule_id = ? AND target_surface_id = ?",
        (rule.id, surf["surface_id"]),
    ).fetchone()

    if existing is not None:
        conn.execute(
            "UPDATE task SET ev_score = ?, rationale = ?, risk = ?, autonomy = ?, "
            "kind = ?, technique_class = ?, updated_at = ? WHERE id = ?",
            (
                rule.ev_score,
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
            rule.ev_score,
            now,
        ),
    )
    return 1, 0


def top_tasks(
    conn: sqlite3.Connection,
    engagement_id: int,
    limit: int = 5,
) -> list[sqlite3.Row]:
    """Pending tasks, AI-first then EV descending (id as stable tie-break).

    The `technique_class` tier enforces the OSAI doctrine — AI hosts before
    traditional — regardless of raw EV, so a low-EV AI move still outranks a
    high-EV traditional one. Within a tier, EV decides.
    """
    return conn.execute(
        "SELECT t.id, t.kind, t.playbook_rule_id, t.technique_class, t.rationale, "
        "t.risk, t.autonomy, t.ev_score, t.status, h.ip AS host_ip, "
        "s.kind AS surface_kind, s.meta_json AS surface_meta, svc.port AS surface_port "
        "FROM task t "
        "JOIN host h ON h.id = t.target_host_id "
        "LEFT JOIN surface s ON s.id = t.target_surface_id "
        "LEFT JOIN service svc ON svc.id = s.service_id "
        "WHERE t.engagement_id = ? AND t.status = 'pending' "
        "ORDER BY CASE t.technique_class WHEN 'ai' THEN 0 ELSE 1 END ASC, "
        "t.ev_score DESC, t.id ASC "
        "LIMIT ?",
        (engagement_id, limit),
    ).fetchall()
