"""SQLite bootstrap and connection helpers for Yhwach's world model.

The world model is one SQLite DB per lab. This module owns:
  * schema application (`init`)
  * connection with sane pragmas (`connect`)
  * a transactional context manager (`transaction`)
  * engagement upsert (the only mutation `yhwach engage` needs)

Everything else is a plain SQL query in the caller — Yhwach never wraps SQLite
in an ORM. The schema is the contract.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from yhwach import schema_sql_path


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection with row-dict access and foreign keys on."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init(db_path: Path | str, *, if_exists: str = "keep") -> None:
    """Create the DB (if needed) and apply schema.sql.

    if_exists:
      * "keep"    — do not touch an existing DB (default; schema is idempotent).
      * "replace" — delete and recreate.
      * "error"   — raise if the file already exists.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        if if_exists == "error":
            raise FileExistsError(f"{path} already exists")
        if if_exists == "replace":
            path.unlink()

    schema = schema_sql_path().read_text(encoding="utf-8")
    conn = connect(path)
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def transaction(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a connection, yield it, commit on success, rollback on error, always close."""
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def engagement_id_for(conn: sqlite3.Connection, lab: str) -> int | None:
    row = conn.execute("SELECT id FROM engagement WHERE lab = ?", (lab,)).fetchone()
    return row["id"] if row else None


def upsert_engagement(
    conn: sqlite3.Connection,
    lab: str,
    scope: str,
    domain: str | None = None,
    dc_ip: str | None = None,
    started_at: str | None = None,
) -> int:
    """Create or update an engagement row and return its id."""
    if started_at is None:
        started_at = _now_utc()

    existing = engagement_id_for(conn, lab)
    if existing is not None:
        conn.execute(
            "UPDATE engagement SET scope = ?, domain = COALESCE(?, domain), "
            "dc_ip = COALESCE(?, dc_ip) WHERE id = ?",
            (scope, domain, dc_ip, existing),
        )
        return existing

    cur = conn.execute(
        "INSERT INTO engagement (lab, domain, dc_ip, scope, started_at) VALUES (?, ?, ?, ?, ?)",
        (lab, domain, dc_ip, scope, started_at),
    )
    return int(cur.lastrowid)


def upsert_surface(
    conn: sqlite3.Connection,
    host_id: int,
    service_id: int | None,
    kind: str,
    auth: str,
    meta_json: str,
) -> tuple[int, bool]:
    """Insert or update a `surface` row keyed by (host, service, kind).

    Returns (surface_id, created) where `created` is True on first insert,
    False on update. Idempotent per the partial unique indexes in schema.sql.
    """
    if service_id is None:
        row = conn.execute(
            "SELECT id FROM surface WHERE host_id = ? AND service_id IS NULL AND kind = ?",
            (host_id, kind),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM surface WHERE host_id = ? AND service_id = ? AND kind = ?",
            (host_id, service_id, kind),
        ).fetchone()

    if row is not None:
        conn.execute(
            "UPDATE surface SET auth = ?, meta_json = ? WHERE id = ?",
            (auth, meta_json, row["id"]),
        )
        return int(row["id"]), False

    now = _now_utc()
    cur = conn.execute(
        "INSERT INTO surface (host_id, service_id, kind, auth, meta_json, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, service_id, kind, auth, meta_json, now),
    )
    return int(cur.lastrowid), True


def scanned_hosts_with_ports(
    conn: sqlite3.Connection,
    engagement_id: int,
    ports: list[int],
) -> list[dict]:
    """Return [{host_id, ip, port, service_id}, ...] for scanned hosts whose
    services match any of `ports`. Used by the probe subcommand.
    """
    if not ports:
        return []
    placeholders = ",".join("?" for _ in ports)
    rows = conn.execute(
        f"""
        SELECT h.id AS host_id, h.ip AS ip, s.id AS service_id, s.port AS port
          FROM host h
          JOIN service s ON s.host_id = h.id
         WHERE h.engagement_id = ?
           AND h.stage IN ('scanned', 'enumerated')
           AND s.port IN ({placeholders})
         ORDER BY h.ip, s.port
        """,
        (engagement_id, *ports),
    ).fetchall()
    return [dict(r) for r in rows]


STAGES = ["undiscovered", "scanned", "enumerated", "foothold", "looted", "pivoted", "done"]


def set_host_stage(
    conn: sqlite3.Connection,
    engagement_id: int,
    ip: str,
    stage: str,
    *,
    monotonic: bool = True,
) -> tuple[bool, str | None]:
    """Set a host's FSM stage. With monotonic=True, refuse to move backwards
    (except to 'blocked'). Returns (changed, message)."""
    if stage not in STAGES and stage != "blocked":
        return False, (f"unknown stage '{stage}' — must be one of "
                       f"{', '.join(STAGES + ['blocked'])}")
    row = conn.execute(
        "SELECT id, stage FROM host WHERE engagement_id = ? AND ip = ?",
        (engagement_id, ip),
    ).fetchone()
    if row is None:
        return False, f"host {ip} not found"
    cur_stage = row["stage"]
    if monotonic and stage != "blocked" and cur_stage in STAGES and stage in STAGES:
        if STAGES.index(stage) < STAGES.index(cur_stage):
            return False, f"{ip} is already at '{cur_stage}'; refusing to move back to '{stage}'"
    # foothold -> looted requires evidence: a proof row with a screenshot.
    if monotonic and stage == "looted":
        has_proof = conn.execute(
            "SELECT 1 FROM proof WHERE host_id = ? AND screenshot_path != '' LIMIT 1",
            (row["id"],),
        ).fetchone()
        if has_proof is None:
            return False, (f"{ip}: 'looted' needs a proof (flag + screenshot) — run "
                           "`yhwach proof` first (or advance --force to override)")
    conn.execute(
        "UPDATE host SET stage = ?, last_updated = ? WHERE id = ?",
        (stage, _now_utc(), row["id"]),
    )
    return True, None


def add_proof(
    conn: sqlite3.Connection,
    host_id: int,
    flag_path: str,
    screenshot_path: str,
    *,
    flag_content: str | None = None,
    obsidian_ref: str | None = None,
) -> int:
    """Record a proof (flag + screenshot) for a host and return its id.

    The screenshot is what gates `foothold -> looted` (see set_host_stage). The
    caller verifies the screenshot file exists before calling; the vault mirror
    (obsidian_ref) is optional and filled in when the operator syncs it.
    """
    cur = conn.execute(
        "INSERT INTO proof (host_id, flag_path, flag_content, screenshot_path, "
        "obsidian_ref, scored, captured_at) VALUES (?, ?, ?, ?, ?, 0, ?)",
        (host_id, flag_path, flag_content, screenshot_path, obsidian_ref, _now_utc()),
    )
    return int(cur.lastrowid)


def add_credential(
    conn: sqlite3.Connection,
    engagement_id: int,
    identifier: str,
    secret: str | None,
    kind: str,
    source: str,
    source_host_id: int | None = None,
) -> tuple[int, bool]:
    """Add/update a credential (deduped by engagement+identifier+kind).

    Creds are never exhausted — the spray primitive keeps them in play against
    every host. On update, `source` is APPENDED (comma-joined) rather than
    overwritten, so a cred rediscovered via a new channel keeps its full
    provenance chain (e.g. `sqli_app_config,jenkins_credentials.xml`).
    `source_host_id`, when supplied on an update, is only filled in if the
    row didn't already carry one — the original discovery host wins.
    """
    existing = conn.execute(
        "SELECT id, source, source_host_id FROM credential "
        "WHERE engagement_id = ? AND identifier = ? AND kind = ?",
        (engagement_id, identifier, kind),
    ).fetchone()
    if existing is not None:
        merged_source = existing["source"]
        if source and source not in [s.strip() for s in (existing["source"] or "").split(",")]:
            merged_source = f"{existing['source']},{source}" if existing["source"] else source
        conn.execute(
            "UPDATE credential SET secret = COALESCE(?, secret), source = ?, "
            "source_host_id = COALESCE(source_host_id, ?) WHERE id = ?",
            (secret, merged_source, source_host_id, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO credential (engagement_id, identifier, secret, kind, source, "
        "source_host_id, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, identifier, secret, kind, source, source_host_id, _now_utc()),
    )
    return int(cur.lastrowid), True


def list_credentials(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    kind: str | None = None,
) -> list[sqlite3.Row]:
    """Return every credential for the engagement, with source-host IP joined in.

    `kind`, if given, filters to one kind (`password`, `ntlm`, `ssh_key`,
    `api_key`, `token`, `dpapi`, `kerberos`). Secrets are returned in full —
    the vault is the operator's authoritative access ledger and downstream
    tools (spray, MCP surface) rely on it being readable.
    """
    q = (
        "SELECT c.identifier, c.secret, c.kind, c.source, c.discovered_at, "
        "sh.ip AS source_host_ip, vh.ip AS validated_on_host_ip "
        "FROM credential c "
        "LEFT JOIN host sh ON sh.id = c.source_host_id "
        "LEFT JOIN host vh ON vh.id = c.validated_on_host_id "
        "WHERE c.engagement_id = ?"
    )
    params: tuple = (engagement_id,)
    if kind is not None:
        q += " AND c.kind = ?"
        params = (engagement_id, kind)
    q += " ORDER BY c.id"
    return conn.execute(q, params).fetchall()


def log_event(
    conn: sqlite3.Connection,
    engagement_id: int,
    kind: str,
    payload: dict,
) -> int:
    """Append an audit event (drives the report + replay)."""
    import json as _json

    cur = conn.execute(
        "INSERT INTO event (engagement_id, ts, kind, payload_json) VALUES (?, ?, ?, ?)",
        (engagement_id, _now_utc(), kind, _json.dumps(payload, sort_keys=True)),
    )
    return int(cur.lastrowid)


def add_finding(
    conn: sqlite3.Connection,
    host_id: int | None,
    surface_id: int | None,
    cls: str,
    title: str,
    severity: str,
    evidence: str,
    playbook_rule_id: str | None = None,
    tag: str | None = None,
) -> tuple[int, bool]:
    """Insert or update a finding, deduped by (host_id, class, title).

    `tag` is the chaining key a rule's `findings_include` matches on; on update
    it is only (re)set when a non-null tag is supplied, so a later untagged
    re-detection never clears an existing tag.
    """
    now = _now_utc()
    existing = conn.execute(
        "SELECT id FROM finding WHERE host_id IS ? AND class = ? AND title = ?",
        (host_id, cls, title),
    ).fetchone()
    if existing is not None:
        if tag is not None:
            conn.execute(
                "UPDATE finding SET evidence = ?, tag = ?, updated_at = ? WHERE id = ?",
                (evidence, tag, now, existing["id"]),
            )
        else:
            conn.execute(
                "UPDATE finding SET evidence = ?, updated_at = ? WHERE id = ?",
                (evidence, now, existing["id"]),
            )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO finding (host_id, surface_id, class, title, severity, evidence, "
        "tag, playbook_rule_id, status, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
        (host_id, surface_id, cls, title, severity, evidence, tag, playbook_rule_id, now),
    )
    return int(cur.lastrowid), True


def all_services_for_scanned_hosts(
    conn: sqlite3.Connection,
    engagement_id: int,
) -> list[dict]:
    """Every service on scanned/enumerated hosts. Used for traditional detection
    (which, unlike the AI probes, is not restricted to a fixed port list)."""
    rows = conn.execute(
        "SELECT h.id AS host_id, h.ip AS ip, s.id AS service_id, s.port AS port, "
        "s.product AS product "
        "FROM host h JOIN service s ON s.host_id = h.id "
        "WHERE h.engagement_id = ? AND h.stage IN ('scanned', 'enumerated') "
        "ORDER BY h.ip, s.port",
        (engagement_id,),
    ).fetchall()
    return [dict(r) for r in rows]
