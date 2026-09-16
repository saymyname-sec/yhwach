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
