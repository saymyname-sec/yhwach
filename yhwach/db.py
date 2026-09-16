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


def add_finding(
    conn: sqlite3.Connection,
    host_id: int | None,
    surface_id: int | None,
    cls: str,
    title: str,
    severity: str,
    evidence: str,
    playbook_rule_id: str | None = None,
) -> tuple[int, bool]:
    """Insert or update a finding, deduped by (host_id, class, title)."""
    now = _now_utc()
    existing = conn.execute(
        "SELECT id FROM finding WHERE host_id IS ? AND class = ? AND title = ?",
        (host_id, cls, title),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE finding SET evidence = ?, updated_at = ? WHERE id = ?",
            (evidence, now, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO finding (host_id, surface_id, class, title, severity, evidence, "
        "playbook_rule_id, status, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)",
        (host_id, surface_id, cls, title, severity, evidence, playbook_rule_id, now),
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
