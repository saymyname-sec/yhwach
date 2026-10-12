"""yhwach query — named, read-only views over the world model.

The model's real questions on a live estate are attribute lookups: "hosts with
445 open and no share listing", "findings tagged idor on web_app 7", "what
happened to DC01 since 14:00". Without this they are answered by re-reading a
full brief/dossier and re-parsing prose, which burns context and invents rows.

Design (reviewer-approved): views are CODE-DEFINED (never free SQL from the
model); `where` keys name an allowlisted column plus an operator; values are
bound parameters; `q` is a LIKE across a view's search columns. Read-only; the
model cannot write SQL. Secrets are masked unless `reveal=True`.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

_OPS = {
    "=": "= ?",
    "!=": "!= ?",
    ">=": ">= ?",
    "<=": "<= ?",
    ">": "> ?",
    "<": "< ?",
    "like": "LIKE ?",
    "in": None,        # expands to IN (?, ?, …)
    "is_null": None,   # no value
}


@dataclass
class View:
    # FROM clause including any joins; must expose the columns below.
    frm: str
    # public column name -> SQL expression
    cols: dict[str, str]
    # WHERE fragment scoping to one engagement (uses a single ? bound to eid)
    scope: str
    order: str
    search: list[str] = field(default_factory=list)   # SQL exprs for `q`
    mask: list[str] = field(default_factory=list)      # public cols masked unless reveal


_H = "host h"
VIEWS: dict[str, View] = {
    "hosts": View(
        _H, {"id": "h.id", "ip": "h.ip", "hostname": "h.hostname", "os": "h.os",
             "stage": "h.stage", "tags": "h.tags", "scan_needed": "h.scan_needed",
             "discovery_source": "h.discovery_source"},
        "h.engagement_id = ?", "h.ip", ["h.ip", "h.hostname"]),
    "services": View(
        "service s JOIN host h ON h.id = s.host_id",
        {"id": "s.id", "host_ip": "h.ip", "port": "s.port", "proto": "s.proto",
         "product": "s.product", "version": "s.version"},
        "h.engagement_id = ?", "h.ip, s.port", ["s.product", "s.version"]),
    "surfaces": View(
        "surface su JOIN host h ON h.id = su.host_id LEFT JOIN service s ON s.id = su.service_id",
        {"id": "su.id", "host_ip": "h.ip", "kind": "su.kind", "auth": "su.auth",
         "port": "s.port"},
        "h.engagement_id = ?", "h.ip, su.kind", ["su.kind"]),
    "findings": View(
        "finding f LEFT JOIN host h ON h.id = f.host_id",
        {"id": "f.id", "host_ip": "h.ip", "class": "f.class", "title": "f.title",
         "severity": "f.severity", "tag": "f.tag", "status": "f.status",
         "location": "f.location", "group_key": "f.group_key", "curated": "f.curated",
         "author": "f.author", "evidence": "f.evidence"},
        "f.engagement_id = ?", "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' "
        "THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id",
        ["f.title", "f.tag", "f.evidence"], mask=["evidence"]),
    "creds": View(
        "credential c LEFT JOIN host vh ON vh.id = c.validated_on_host_id",
        {"id": "c.id", "identifier": "c.identifier", "kind": "c.kind",
         "source": "c.source", "provenance": "c.provenance", "secret": "c.secret",
         "validated_on": "vh.ip"},
        "c.engagement_id = ?", "c.id", ["c.identifier"], mask=["secret"]),
    "principals": View(
        "principal p",
        {"id": "p.id", "name": "p.name", "domain": "p.domain", "type": "p.type",
         "sid": "p.sid", "enabled": "p.enabled", "spn": "p.spn"},
        "p.engagement_id = ?", "p.name", ["p.name", "p.domain"]),
    "shares": View(
        "share sh JOIN host h ON h.id = sh.host_id",
        {"id": "sh.id", "host_ip": "h.ip", "name": "sh.name", "access": "sh.access",
         "remark": "sh.remark"},
        "h.engagement_id = ?", "h.ip, sh.name", ["sh.name", "sh.remark"]),
    "loot": View(
        "loot l LEFT JOIN host h ON h.id = l.host_id",
        {"id": "l.id", "host_ip": "h.ip", "type": "l.type", "summary": "l.summary",
         "local_path": "l.local_path", "contains_secret": "l.contains_secret"},
        "l.engagement_id = ?", "l.id DESC", ["l.summary", "l.type"]),
    "objectives": View(
        "objective o LEFT JOIN host h ON h.id = o.host_id",
        {"id": "o.id", "host_ip": "h.ip", "kind": "o.kind", "label": "o.label",
         "points": "o.points", "captured": "o.captured"},
        "o.engagement_id = ?", "o.id", ["o.label"]),
    "attempts": View(
        "attempt a LEFT JOIN host h ON h.id = a.host_id",
        {"id": "a.id", "host_ip": "h.ip", "rule": "a.playbook_rule_id",
         "technique": "a.technique_id", "result": "a.result", "reason": "a.reason",
         "at": "a.attempted_at"},
        "a.engagement_id = ?", "a.id DESC", ["a.playbook_rule_id", "a.reason"]),
    "events": View(
        "event e",
        {"id": "e.id", "ts": "e.ts", "kind": "e.kind",
         "host": "json_extract(e.payload_json, '$.host')", "payload": "e.payload_json"},
        "e.engagement_id = ?", "e.id DESC", ["e.kind", "e.payload_json"]),
    "software": View(
        "software sw JOIN host h ON h.id = sw.host_id",
        {"id": "sw.id", "host_ip": "h.ip", "name": "sw.name", "version": "sw.version",
         "kind": "sw.kind", "cpe": "sw.cpe"},
        "h.engagement_id = ?", "h.ip, sw.name", ["sw.name", "sw.cpe"]),
    "vulns": View(
        "vulnerability v LEFT JOIN host h ON h.id = v.host_id",
        {"id": "v.id", "host_ip": "h.ip", "cve": "v.cve", "title": "v.title",
         "cvss": "v.cvss", "state": "v.state", "source": "v.source"},
        "v.engagement_id = ?", "v.cvss DESC", ["v.cve", "v.title"]),
    "web_paths": View(
        "web_path wp JOIN web_app wa ON wa.id = wp.web_app_id JOIN host h ON h.id = wa.host_id",
        {"id": "wp.id", "host_ip": "h.ip", "base_url": "wa.base_url", "path": "wp.path",
         "method": "wp.method", "status": "wp.status", "kind": "wp.kind",
         "params": "wp.params", "auth_required": "wp.auth_required"},
        "h.engagement_id = ?", "wa.base_url, wp.path", ["wp.path", "wp.params"]),
    "scan_coverage": View(
        "scan_coverage sc JOIN host h ON h.id = sc.host_id",
        {"id": "sc.id", "host_ip": "h.ip", "proto": "sc.proto", "ports": "sc.ports",
         "full_range": "sc.full_range", "version_scan": "sc.version_scan",
         "source": "sc.source", "at": "sc.scanned_at"},
        "h.engagement_id = ?", "h.ip", ["sc.source"]),
    "probe_runs": View(
        "probe_run pr JOIN host h ON h.id = pr.host_id",
        {"id": "pr.id", "host_ip": "h.ip", "port": "pr.port", "probe": "pr.probe",
         "result": "pr.result", "kind": "pr.kind", "at": "pr.ran_at"},
        "pr.engagement_id = ?", "pr.id DESC", ["pr.probe"]),
    "evidence": View(
        "evidence e LEFT JOIN evidence_link l ON l.evidence_id = e.id",
        {"id": "e.id", "kind": "e.kind", "finding_id": "l.finding_id",
         "objective": "l.objective", "caption": "e.caption", "sha256": "e.sha256",
         "path": "e.path", "contains_secret": "e.contains_secret", "at": "e.captured_at"},
        "e.engagement_id = ?", "e.id DESC", ["e.kind", "e.caption"]),
}


def _as_bool(v: object) -> bool:
    """Coerce a where-value to a boolean. A string 'false'/'0'/'no'/'' is False
    so `is_null=false` (from the CLI or a stringly-typed wire call) means IS NOT
    NULL, not the Python-truthy IS NULL."""
    if isinstance(v, str):
        return v.strip().lower() not in ("", "false", "0", "no", "off", "null", "none")
    return bool(v)


def _split_op(key: str) -> tuple[str, str]:
    """A where-key is a column plus an optional trailing operator token:
    'ts>=' -> ('ts','>='); 'tag' -> ('tag','='); 'kind in' -> ('kind','in')."""
    k = key.strip()
    for op in (">=", "<=", "!=", ">", "<"):
        if k.endswith(op):
            return k[: -len(op)].strip(), op
    for word in ("is_null", "like", "in"):
        if k.lower().endswith(" " + word):
            return k[: -(len(word) + 1)].strip(), word
    return k, "="


def query(
    conn: sqlite3.Connection,
    engagement_id: int,
    view: str,
    *,
    where: dict | None = None,
    q: str | None = None,
    fields: list[str] | None = None,
    order: str | None = None,
    limit: int = 25,
    offset: int = 0,
    reveal: bool = False,
) -> tuple[list[str], list[sqlite3.Row], int]:
    """Run a named view. Returns (column_names, rows, total_before_limit).

    Raises ValueError on an unknown view/column/operator — never silently drops
    a filter (that would mislead the model about what it searched)."""
    v = VIEWS.get(view)
    if v is None:
        raise ValueError(f"unknown view '{view}' — one of: {', '.join(sorted(VIEWS))}")
    out_cols = list(v.cols) if not fields else [f for f in fields if f in v.cols]
    if fields and not out_cols:
        raise ValueError(f"no known fields for view '{view}' (cols: {', '.join(v.cols)})")

    sel = ", ".join(f"{v.cols[c]} AS \"{c}\"" for c in out_cols)
    clauses = [v.scope]
    params: list = [engagement_id]

    for raw_key, val in (where or {}).items():
        col, op = _split_op(raw_key)
        if col not in v.cols:
            raise ValueError(f"unknown column '{col}' for view '{view}' (cols: {', '.join(v.cols)})")
        if op not in _OPS:
            raise ValueError(f"unknown operator in '{raw_key}'")
        expr = v.cols[col]
        if op == "is_null":
            clauses.append(f"{expr} IS NULL" if _as_bool(val) else f"{expr} IS NOT NULL")
        elif op == "in":
            vals = val if isinstance(val, (list, tuple)) else [val]
            if not vals:
                clauses.append("0")
            else:
                clauses.append(f"{expr} IN ({', '.join('?' * len(vals))})")
                params.extend(vals)
        else:
            clauses.append(f"{expr} {_OPS[op]}")
            params.append(val)

    if q and v.search:
        ors = " OR ".join(f"{e} LIKE ?" for e in v.search)
        clauses.append(f"({ors})")
        params.extend([f"%{q}%"] * len(v.search))

    where_sql = " AND ".join(clauses)
    total = conn.execute(
        f"SELECT COUNT(*) FROM {v.frm} WHERE {where_sql}", params
    ).fetchone()[0]

    order_sql = v.order
    if order:
        oc = order.lstrip("+-")
        if oc not in v.cols:
            raise ValueError(f"unknown order column '{oc}'")
        order_sql = f"{v.cols[oc]} {'DESC' if order.startswith('-') else 'ASC'}"

    sql = (f"SELECT {sel} FROM {v.frm} WHERE {where_sql} "
           f"ORDER BY {order_sql} LIMIT ? OFFSET ?")
    rows = conn.execute(sql, [*params, max(1, limit), max(0, offset)]).fetchall()

    if not reveal:
        masked = [c for c in out_cols if c in v.mask]
        if masked:
            rows = [_mask_row(r, out_cols, masked) for r in rows]
    return out_cols, rows, int(total)


def _mask_row(row: sqlite3.Row, cols: list[str], masked: list[str]) -> dict:
    d = {c: row[c] for c in cols}
    for c in masked:
        if d.get(c):
            # Fixed token — leaks neither a prefix nor the exact length (it is a
            # "this field is set" signal only). Pass reveal=True for the value.
            d[c] = "••••••"
    return d


def render(cols: list[str], rows, total: int, view: str, limit: int, offset: int) -> str:
    """Compact text rendering for the MCP/CLI text surface."""
    if not rows:
        return f"{view}: 0 rows"
    head = " | ".join(cols)
    lines = [head, "-" * len(head)]
    for r in rows:
        d = {c: r[c] for c in cols} if isinstance(r, sqlite3.Row) else r
        lines.append(" | ".join("" if d.get(c) is None else str(d.get(c)) for c in cols))
    shown = offset + len(rows)
    if total > shown:
        lines.append(f"… showing {offset + 1}-{shown} of {total} — "
                     f"query(view='{view}', offset={shown})")
    return "\n".join(lines)
