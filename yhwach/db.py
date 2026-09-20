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
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from yhwach import schema_sql_path

# Schema additions made after the original v0 (columns + whole tables). Applied
# idempotently on every open so a DB created by an older Yhwach self-heals — no
# more "no such column: f.tag / engagement_id" on an upgraded engagement.
_ADDED_COLUMNS = [
    ("finding", "tag", "TEXT"),
    ("finding", "engagement_id", "INTEGER"),
    ("credential", "source_host_id", "INTEGER"),
    # schema v1 — attack-surface enrichment
    ("service", "cpe", "TEXT"),
    ("credential", "principal_id", "INTEGER"),
]
_ADDED_TABLES = {
    "tunnel": (
        "CREATE TABLE IF NOT EXISTS tunnel ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER REFERENCES engagement(id),"
        "  via_host_id INTEGER REFERENCES host(id),"
        "  subnet TEXT NOT NULL,"
        "  kind TEXT NOT NULL DEFAULT 'ligolo',"
        "  created_at TEXT NOT NULL,"
        "  UNIQUE(engagement_id, via_host_id, subnet))"
    ),
    "attempt": (
        "CREATE TABLE IF NOT EXISTS attempt ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  task_id INTEGER REFERENCES task(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  playbook_rule_id TEXT,"
        "  technique_id TEXT,"
        "  result TEXT NOT NULL,"
        "  reason TEXT,"
        "  evidence TEXT,"
        "  attempted_at TEXT NOT NULL)"
    ),
    "scan_coverage": (
        "CREATE TABLE IF NOT EXISTS scan_coverage ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  proto TEXT NOT NULL,"
        "  ports TEXT NOT NULL,"
        "  port_count INTEGER NOT NULL DEFAULT 0,"
        "  full_range INTEGER NOT NULL DEFAULT 0,"
        "  version_scan INTEGER NOT NULL DEFAULT 0,"
        "  source TEXT,"
        "  scanned_at TEXT NOT NULL,"
        "  UNIQUE(host_id, proto, ports))"
    ),
    # -- schema v1 — attack-surface enrichment ---------------------------------
    # These mirror db/schema.sql exactly so a DB created by an older Yhwach
    # self-heals on open. Keep the two in lockstep when either changes.
    "software": (
        "CREATE TABLE IF NOT EXISTS software ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  service_id INTEGER REFERENCES service(id),"
        "  name TEXT NOT NULL,"
        "  version TEXT,"
        "  cpe TEXT,"
        "  kind TEXT NOT NULL DEFAULT 'service',"
        "  source TEXT,"
        "  evidence TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  updated_at TEXT,"
        "  UNIQUE(host_id, name, version))"
    ),
    "vulnerability": (
        "CREATE TABLE IF NOT EXISTS vulnerability ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  software_id INTEGER REFERENCES software(id),"
        "  service_id INTEGER REFERENCES service(id),"
        "  cve TEXT,"
        "  title TEXT,"
        "  cvss REAL,"
        "  state TEXT NOT NULL DEFAULT 'potential',"
        "  exploit_ref TEXT,"
        "  exploit_available INTEGER DEFAULT 0,"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  updated_at TEXT)"
    ),
    "principal": (
        "CREATE TABLE IF NOT EXISTS principal ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  name TEXT NOT NULL,"
        "  domain TEXT,"
        "  type TEXT NOT NULL DEFAULT 'user',"
        "  sid TEXT,"
        "  rid INTEGER,"
        "  enabled INTEGER DEFAULT 1,"
        "  flags TEXT,"
        "  spn TEXT,"
        "  description TEXT,"
        "  home_host_id INTEGER REFERENCES host(id),"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  updated_at TEXT,"
        "  UNIQUE(engagement_id, name, domain, type))"
    ),
    "membership": (
        "CREATE TABLE IF NOT EXISTS membership ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  member_id INTEGER NOT NULL REFERENCES principal(id),"
        "  group_id INTEGER NOT NULL REFERENCES principal(id),"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(member_id, group_id))"
    ),
    "privilege": (
        "CREATE TABLE IF NOT EXISTS privilege ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  principal_id INTEGER REFERENCES principal(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  right TEXT NOT NULL,"
        "  target TEXT,"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(engagement_id, principal_id, host_id, right, target))"
    ),
    "edge": (
        "CREATE TABLE IF NOT EXISTS edge ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  src TEXT NOT NULL,"
        "  dst TEXT NOT NULL,"
        "  kind TEXT NOT NULL,"
        "  confidence TEXT DEFAULT 'confirmed',"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(engagement_id, src, dst, kind))"
    ),
    "web_app": (
        "CREATE TABLE IF NOT EXISTS web_app ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  service_id INTEGER REFERENCES service(id),"
        "  surface_id INTEGER REFERENCES surface(id),"
        "  base_url TEXT NOT NULL,"
        "  vhost TEXT,"
        "  scheme TEXT,"
        "  title TEXT,"
        "  server TEXT,"
        "  tech TEXT,"
        "  waf TEXT,"
        "  favicon_hash TEXT,"
        "  notes TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  updated_at TEXT,"
        "  UNIQUE(host_id, base_url, vhost))"
    ),
    "web_path": (
        "CREATE TABLE IF NOT EXISTS web_path ("
        "  id INTEGER PRIMARY KEY,"
        "  web_app_id INTEGER NOT NULL REFERENCES web_app(id),"
        "  path TEXT NOT NULL,"
        "  method TEXT DEFAULT 'GET',"
        "  status INTEGER,"
        "  length INTEGER,"
        "  kind TEXT,"
        "  auth_required INTEGER DEFAULT 0,"
        "  params TEXT,"
        "  interesting INTEGER DEFAULT 0,"
        "  source TEXT,"
        "  notes TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(web_app_id, path, method))"
    ),
    "domain": (
        "CREATE TABLE IF NOT EXISTS domain ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  name TEXT NOT NULL,"
        "  type TEXT NOT NULL DEFAULT 'vhost',"
        "  ip TEXT,"
        "  host_id INTEGER REFERENCES host(id),"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(engagement_id, name, type))"
    ),
    "host_interface": (
        "CREATE TABLE IF NOT EXISTS host_interface ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  ip TEXT NOT NULL,"
        "  mac TEXT,"
        "  segment TEXT,"
        "  is_primary INTEGER DEFAULT 0,"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(host_id, ip))"
    ),
    "loot": (
        "CREATE TABLE IF NOT EXISTS loot ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  path TEXT,"
        "  local_path TEXT,"
        "  type TEXT,"
        "  contains_secret INTEGER DEFAULT 0,"
        "  credential_id INTEGER REFERENCES credential(id),"
        "  summary TEXT,"
        "  discovered_at TEXT NOT NULL)"
    ),
    "password_policy": (
        "CREATE TABLE IF NOT EXISTS password_policy ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  domain TEXT,"
        "  host_id INTEGER REFERENCES host(id),"
        "  min_length INTEGER,"
        "  lockout_threshold INTEGER,"
        "  lockout_window_min INTEGER,"
        "  complexity INTEGER,"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL)"
    ),
    "objective": (
        "CREATE TABLE IF NOT EXISTS objective ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  kind TEXT NOT NULL DEFAULT 'flag',"
        "  label TEXT NOT NULL,"
        "  points INTEGER DEFAULT 0,"
        "  captured INTEGER DEFAULT 0,"
        "  notes TEXT,"
        "  discovered_at TEXT NOT NULL)"
    ),
    "share": (
        "CREATE TABLE IF NOT EXISTS share ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  name TEXT NOT NULL,"
        "  proto TEXT NOT NULL DEFAULT 'smb',"
        "  access TEXT,"
        "  remark TEXT,"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(host_id, name, proto))"
    ),
}


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring an existing DB up to the current schema (added columns/tables).

    Safe on a fresh/empty DB: with no base tables yet there's nothing to migrate,
    and init()'s full schema then creates everything current."""
    tables = {r["name"] for r in
              conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "engagement" not in tables:
        return  # empty DB — init() will apply the full, current schema
    changed = False
    for tname, ddl in _ADDED_TABLES.items():
        if tname not in tables:
            conn.execute(ddl)
            changed = True
    for tname, col, decl in _ADDED_COLUMNS:
        if tname in tables:
            cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({tname})")}
            if col not in cols:
                conn.execute(f"ALTER TABLE {tname} ADD COLUMN {col} {decl}")
                changed = True
    if changed:
        conn.commit()


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection with row-dict access, foreign keys on, and schema self-heal."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _migrate(conn)
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
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    if (monotonic and stage != "blocked" and cur_stage in STAGES and stage in STAGES
            and STAGES.index(stage) < STAGES.index(cur_stage)):
        return False, f"{ip} is already at '{cur_stage}'; refusing to move back to '{stage}'"
    # looted -> pivoted requires a route out: a tunnel / reachable subnet via this host.
    if monotonic and stage == "pivoted":
        has_tunnel = conn.execute(
            "SELECT 1 FROM tunnel WHERE via_host_id = ? LIMIT 1", (row["id"],)
        ).fetchone()
        if has_tunnel is None:
            return False, (f"{ip}: 'pivoted' needs a tunnel/reachable subnet via this host — "
                           "run `yhwach pivot` first (or advance --force to override)")
    conn.execute(
        "UPDATE host SET stage = ?, last_updated = ? WHERE id = ?",
        (stage, _now_utc(), row["id"]),
    )
    return True, None


def add_tunnel(
    conn: sqlite3.Connection,
    engagement_id: int,
    via_host_id: int | None,
    subnet: str,
    kind: str = "ligolo",
) -> tuple[int, bool]:
    """Record a pivot tunnel (a subnet reachable via a host). Deduped by
    (engagement, via_host, subnet). Returns (id, created)."""
    existing = conn.execute(
        "SELECT id FROM tunnel WHERE engagement_id = ? AND via_host_id IS ? AND subnet = ?",
        (engagement_id, via_host_id, subnet),
    ).fetchone()
    if existing is not None:
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO tunnel (engagement_id, via_host_id, subnet, kind, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (engagement_id, via_host_id, subnet, kind, _now_utc()),
    )
    return int(cur.lastrowid), True


def list_tunnels(conn: sqlite3.Connection, engagement_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT t.subnet, t.kind, t.created_at, h.ip AS via_ip "
        "FROM tunnel t LEFT JOIN host h ON h.id = t.via_host_id "
        "WHERE t.engagement_id = ? ORDER BY t.created_at",
        (engagement_id,),
    ).fetchall()


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
    engagement_id: int | None = None,
) -> tuple[int, bool]:
    """Insert or update a finding, deduped by (engagement, host_id, class, title).

    `engagement_id` scopes the finding so host-less findings never leak across
    labs; when omitted it is derived from `host_id`. `tag` is the chaining key a
    rule's `findings_include` matches on; on update it is only (re)set when a
    non-null tag is supplied, so a later untagged re-detection never clears it.
    """
    now = _now_utc()
    if engagement_id is None and host_id is not None:
        hrow = conn.execute("SELECT engagement_id FROM host WHERE id = ?", (host_id,)).fetchone()
        engagement_id = hrow["engagement_id"] if hrow else None
    existing = conn.execute(
        "SELECT id FROM finding WHERE engagement_id IS ? AND host_id IS ? "
        "AND class = ? AND title = ?",
        (engagement_id, host_id, cls, title),
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
        "INSERT INTO finding (engagement_id, host_id, surface_id, class, title, severity, "
        "evidence, tag, playbook_rule_id, status, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
        (engagement_id, host_id, surface_id, cls, title, severity, evidence, tag,
         playbook_rule_id, now),
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

# ---------------------------------------------------------------------------
# Attempt ledger — the negative half of technique_exhaustion.
# ---------------------------------------------------------------------------
ATTEMPT_RESULTS = ("success", "fail", "blocked", "partial")


def add_attempt(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    result: str,
    task_id: int | None = None,
    host_id: int | None = None,
    playbook_rule_id: str | None = None,
    technique_id: str | None = None,
    reason: str | None = None,
    evidence: str | None = None,
) -> int:
    """Append an attempt row (append-only: re-trying a move adds a row, never
    overwrites one — the ledger is the operator's memory of what it burned)."""
    if result not in ATTEMPT_RESULTS:
        raise ValueError(
            f"unknown result '{result}' — use one of {', '.join(ATTEMPT_RESULTS)}")
    cur = conn.execute(
        "INSERT INTO attempt (engagement_id, task_id, host_id, playbook_rule_id, "
        "technique_id, result, reason, evidence, attempted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, task_id, host_id, playbook_rule_id, technique_id, result,
         reason, evidence, _now_utc()),
    )
    return int(cur.lastrowid)


def list_attempts(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    result: str | None = None,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    """Attempts newest-first, with the target host IP joined in."""
    clauses = ["a.engagement_id = ?"]
    params: list = [engagement_id]
    if result is not None:
        clauses.append("a.result = ?")
        params.append(result)
    sql = (
        "SELECT a.id, a.task_id, a.playbook_rule_id, a.technique_id, a.result, "
        "a.reason, a.evidence, a.attempted_at, h.ip AS host_ip "
        "FROM attempt a LEFT JOIN host h ON h.id = a.host_id "
        f"WHERE {' AND '.join(clauses)} ORDER BY a.id DESC"
    )
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


# ---------------------------------------------------------------------------
# Scan coverage — what was scanned, so under-enumeration becomes queryable.
# ---------------------------------------------------------------------------
def record_coverage(
    conn: sqlite3.Connection,
    host_id: int,
    *,
    proto: str,
    ports: str,
    port_count: int = 0,
    full_range: bool = False,
    version_scan: bool = False,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record (host, proto, port-range) coverage. Deduped on that triple; a
    re-ingest only ever ADDS capability (version_scan never regresses to 0).
    Returns (id, created)."""
    existing = conn.execute(
        "SELECT id, version_scan FROM scan_coverage WHERE host_id = ? AND proto = ? "
        "AND ports = ?",
        (host_id, proto, ports),
    ).fetchone()
    if existing is not None:
        if version_scan and not existing["version_scan"]:
            conn.execute(
                "UPDATE scan_coverage SET version_scan = 1, scanned_at = ?, "
                "source = COALESCE(?, source) WHERE id = ?",
                (_now_utc(), source, existing["id"]),
            )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO scan_coverage (host_id, proto, ports, port_count, full_range, "
        "version_scan, source, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (host_id, proto, ports, int(port_count), int(bool(full_range)),
         int(bool(version_scan)), source, _now_utc()),
    )
    return int(cur.lastrowid), True


def coverage_for_engagement(
    conn: sqlite3.Connection,
    engagement_id: int,
) -> list[sqlite3.Row]:
    """Every coverage row in the engagement, host IP joined in."""
    return conn.execute(
        "SELECT c.host_id, c.proto, c.ports, c.port_count, c.full_range, "
        "c.version_scan, c.scanned_at, h.ip AS host_ip, h.stage AS stage "
        "FROM scan_coverage c JOIN host h ON h.id = c.host_id "
        "WHERE h.engagement_id = ? ORDER BY h.ip, c.proto, c.port_count DESC",
        (engagement_id,),
    ).fetchall()

# ===========================================================================
# Attack-surface enrichment helpers (schema v1)
# Same plain-SQL, dedupe-in-helper pattern as add_credential / add_finding.
# Each returns (id, created): created is True on first insert, False on update.
# ===========================================================================


def _merge_csv(existing: str | None, new: str | None) -> str | None:
    """Union two comma-separated lists, preserving first-seen order."""
    seen: list[str] = []
    for chunk in (existing, new):
        for item in (chunk or "").split(","):
            item = item.strip()
            if item and item not in seen:
                seen.append(item)
    return ",".join(seen) if seen else None


def add_software(
    conn: sqlite3.Connection,
    host_id: int,
    name: str,
    version: str | None,
    *,
    service_id: int | None = None,
    cpe: str | None = None,
    kind: str = "service",
    source: str | None = None,
    evidence: str | None = None,
) -> tuple[int, bool]:
    """Record versioned software on a host (deduped by host+name+version)."""
    now = _now_utc()
    existing = conn.execute(
        "SELECT id FROM software WHERE host_id = ? AND name = ? AND version IS ?",
        (host_id, name, version),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE software SET cpe = COALESCE(?, cpe), service_id = COALESCE(?, service_id), "
            "kind = ?, source = COALESCE(?, source), evidence = COALESCE(?, evidence), "
            "updated_at = ? WHERE id = ?",
            (cpe, service_id, kind, source, evidence, now, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO software (host_id, service_id, name, version, cpe, kind, source, "
        "evidence, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (host_id, service_id, name, version, cpe, kind, source, evidence, now),
    )
    return int(cur.lastrowid), True


def add_vulnerability(
    conn: sqlite3.Connection,
    engagement_id: int,
    host_id: int,
    cve: str | None,
    *,
    software_id: int | None = None,
    service_id: int | None = None,
    title: str | None = None,
    cvss: float | None = None,
    state: str = "potential",
    exploit_ref: str | None = None,
    exploit_available: bool = False,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record a version->CVE hypothesis (deduped by host+cve+software)."""
    now = _now_utc()
    existing = conn.execute(
        "SELECT id FROM vulnerability WHERE host_id = ? AND cve IS ? AND software_id IS ?",
        (host_id, cve, software_id),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE vulnerability SET state = ?, cvss = COALESCE(?, cvss), "
            "title = COALESCE(?, title), exploit_ref = COALESCE(?, exploit_ref), "
            "exploit_available = ?, source = COALESCE(?, source), updated_at = ? WHERE id = ?",
            (state, cvss, title, exploit_ref, 1 if exploit_available else 0, source, now,
             existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO vulnerability (engagement_id, host_id, software_id, service_id, cve, "
        "title, cvss, state, exploit_ref, exploit_available, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, software_id, service_id, cve, title, cvss, state,
         exploit_ref, 1 if exploit_available else 0, source, now),
    )
    return int(cur.lastrowid), True


def add_principal(
    conn: sqlite3.Connection,
    engagement_id: int,
    name: str,
    *,
    domain: str | None = None,
    type: str = "user",
    sid: str | None = None,
    rid: int | None = None,
    enabled: bool = True,
    flags: str | None = None,
    spn: str | None = None,
    description: str | None = None,
    home_host_id: int | None = None,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record an account/group/computer (deduped by engagement+name+domain+type).

    On update, flags are UNION-merged (comma list) so a flag learned from one
    source is never dropped by a later source that didn't observe it."""
    now = _now_utc()
    existing = conn.execute(
        "SELECT id, flags FROM principal WHERE engagement_id = ? AND name = ? "
        "AND domain IS ? AND type = ?",
        (engagement_id, name, domain, type),
    ).fetchone()
    if existing is not None:
        merged = _merge_csv(existing["flags"], flags)
        conn.execute(
            "UPDATE principal SET sid = COALESCE(?, sid), rid = COALESCE(?, rid), "
            "enabled = ?, flags = ?, spn = COALESCE(?, spn), "
            "description = COALESCE(?, description), home_host_id = COALESCE(?, home_host_id), "
            "source = COALESCE(?, source), updated_at = ? WHERE id = ?",
            (sid, rid, 1 if enabled else 0, merged, spn, description, home_host_id, source,
             now, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO principal (engagement_id, name, domain, type, sid, rid, enabled, flags, "
        "spn, description, home_host_id, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, name, domain, type, sid, rid, 1 if enabled else 0, flags, spn,
         description, home_host_id, source, now),
    )
    return int(cur.lastrowid), True


def add_membership(
    conn: sqlite3.Connection,
    engagement_id: int,
    member_id: int,
    group_id: int,
    *,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record a group membership edge (deduped by member+group)."""
    existing = conn.execute(
        "SELECT id FROM membership WHERE member_id = ? AND group_id = ?",
        (member_id, group_id),
    ).fetchone()
    if existing is not None:
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO membership (engagement_id, member_id, group_id, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (engagement_id, member_id, group_id, source, _now_utc()),
    )
    return int(cur.lastrowid), True


def add_privilege(
    conn: sqlite3.Connection,
    engagement_id: int,
    right: str,
    *,
    principal_id: int | None = None,
    host_id: int | None = None,
    target: str | None = None,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record a right a principal holds (deduped by principal+host+right+target)."""
    existing = conn.execute(
        "SELECT id FROM privilege WHERE engagement_id = ? AND principal_id IS ? "
        "AND host_id IS ? AND right = ? AND target IS ?",
        (engagement_id, principal_id, host_id, right, target),
    ).fetchone()
    if existing is not None:
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO privilege (engagement_id, principal_id, host_id, right, target, source, "
        "discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, principal_id, host_id, right, target, source, _now_utc()),
    )
    return int(cur.lastrowid), True


def add_edge(
    conn: sqlite3.Connection,
    engagement_id: int,
    src: str,
    dst: str,
    kind: str,
    *,
    confidence: str = "confirmed",
    source: str | None = None,
) -> tuple[int, bool]:
    """Record an attack-graph edge (deduped by src+dst+kind).

    Nodes are addressed 'principal:<id>' or 'host:<id>'."""
    existing = conn.execute(
        "SELECT id FROM edge WHERE engagement_id = ? AND src = ? AND dst = ? AND kind = ?",
        (engagement_id, src, dst, kind),
    ).fetchone()
    if existing is not None:
        conn.execute("UPDATE edge SET confidence = ?, source = COALESCE(?, source) WHERE id = ?",
                     (confidence, source, existing["id"]))
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO edge (engagement_id, src, dst, kind, confidence, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, src, dst, kind, confidence, source, _now_utc()),
    )
    return int(cur.lastrowid), True


def shortest_path(
    conn: sqlite3.Connection,
    engagement_id: int,
    src: str,
    dst: str,
    *,
    max_hops: int = 8,
) -> list[str] | None:
    """BFS over `edge` from node src to node dst (nodes 'principal:<id>' /
    'host:<id>'). Returns the node path (inclusive) or None if unreachable.

    Deterministic: neighbours are visited in id order. Plain-Python BFS keeps the
    logic testable and avoids relying on SQLite recursive-CTE support."""
    if src == dst:
        return [src]
    adj: dict[str, list[str]] = {}
    for r in conn.execute(
        "SELECT src, dst FROM edge WHERE engagement_id = ? ORDER BY id",
        (engagement_id,),
    ):
        adj.setdefault(r["src"], []).append(r["dst"])
    from collections import deque
    q: deque[tuple[str, list[str]]] = deque([(src, [src])])
    seen = {src}
    while q:
        node, path = q.popleft()
        if len(path) > max_hops + 1:
            continue
        for nxt in adj.get(node, []):
            if nxt == dst:
                return path + [nxt]
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, path + [nxt]))
    return None


def add_web_app(
    conn: sqlite3.Connection,
    host_id: int,
    base_url: str,
    *,
    service_id: int | None = None,
    surface_id: int | None = None,
    vhost: str | None = None,
    scheme: str | None = None,
    title: str | None = None,
    server: str | None = None,
    tech: str | None = None,
    waf: str | None = None,
    favicon_hash: str | None = None,
    notes: str | None = None,
) -> tuple[int, bool]:
    """Record a web application (deduped by host+base_url+vhost)."""
    now = _now_utc()
    existing = conn.execute(
        "SELECT id FROM web_app WHERE host_id = ? AND base_url = ? AND vhost IS ?",
        (host_id, base_url, vhost),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE web_app SET service_id = COALESCE(?, service_id), "
            "surface_id = COALESCE(?, surface_id), scheme = COALESCE(?, scheme), "
            "title = COALESCE(?, title), server = COALESCE(?, server), "
            "tech = COALESCE(?, tech), waf = COALESCE(?, waf), "
            "favicon_hash = COALESCE(?, favicon_hash), notes = COALESCE(?, notes), "
            "updated_at = ? WHERE id = ?",
            (service_id, surface_id, scheme, title, server, tech, waf, favicon_hash, notes,
             now, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO web_app (host_id, service_id, surface_id, base_url, vhost, scheme, title, "
        "server, tech, waf, favicon_hash, notes, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (host_id, service_id, surface_id, base_url, vhost, scheme, title, server, tech, waf,
         favicon_hash, notes, now),
    )
    return int(cur.lastrowid), True


def add_web_path(
    conn: sqlite3.Connection,
    web_app_id: int,
    path: str,
    *,
    method: str = "GET",
    status: int | None = None,
    length: int | None = None,
    kind: str | None = None,
    auth_required: bool = False,
    params: str | None = None,
    interesting: bool = False,
    source: str | None = None,
    notes: str | None = None,
) -> tuple[int, bool]:
    """Record a discovered web path/route (deduped by app+path+method)."""
    existing = conn.execute(
        "SELECT id FROM web_path WHERE web_app_id = ? AND path = ? AND method = ?",
        (web_app_id, path, method),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE web_path SET status = COALESCE(?, status), length = COALESCE(?, length), "
            "kind = COALESCE(?, kind), auth_required = ?, params = COALESCE(?, params), "
            "interesting = ?, source = COALESCE(?, source), notes = COALESCE(?, notes) WHERE id = ?",
            (status, length, kind, 1 if auth_required else 0, params, 1 if interesting else 0,
             source, notes, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO web_path (web_app_id, path, method, status, length, kind, auth_required, "
        "params, interesting, source, notes, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (web_app_id, path, method, status, length, kind, 1 if auth_required else 0, params,
         1 if interesting else 0, source, notes, _now_utc()),
    )
    return int(cur.lastrowid), True


def add_domain(
    conn: sqlite3.Connection,
    engagement_id: int,
    name: str,
    *,
    type: str = "vhost",
    ip: str | None = None,
    host_id: int | None = None,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record a domain/vhost/subdomain (deduped by engagement+name+type)."""
    existing = conn.execute(
        "SELECT id FROM domain WHERE engagement_id = ? AND name = ? AND type = ?",
        (engagement_id, name, type),
    ).fetchone()
    if existing is not None:
        conn.execute("UPDATE domain SET ip = COALESCE(?, ip), host_id = COALESCE(?, host_id) "
                     "WHERE id = ?", (ip, host_id, existing["id"]))
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO domain (engagement_id, name, type, ip, host_id, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, name, type, ip, host_id, source, _now_utc()),
    )
    return int(cur.lastrowid), True


def add_host_interface(
    conn: sqlite3.Connection,
    host_id: int,
    ip: str,
    *,
    mac: str | None = None,
    segment: str | None = None,
    is_primary: bool = False,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record a host interface/IP (deduped by host+ip)."""
    existing = conn.execute(
        "SELECT id FROM host_interface WHERE host_id = ? AND ip = ?", (host_id, ip),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE host_interface SET mac = COALESCE(?, mac), segment = COALESCE(?, segment), "
            "is_primary = ?, source = COALESCE(?, source) WHERE id = ?",
            (mac, segment, 1 if is_primary else 0, source, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO host_interface (host_id, ip, mac, segment, is_primary, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (host_id, ip, mac, segment, 1 if is_primary else 0, source, _now_utc()),
    )
    return int(cur.lastrowid), True


def add_loot(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_id: int | None = None,
    path: str | None = None,
    local_path: str | None = None,
    type: str | None = None,
    contains_secret: bool = False,
    credential_id: int | None = None,
    summary: str | None = None,
) -> int:
    """Record a loot artifact. Append-only (no natural dedupe key)."""
    cur = conn.execute(
        "INSERT INTO loot (engagement_id, host_id, path, local_path, type, contains_secret, "
        "credential_id, summary, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, path, local_path, type, 1 if contains_secret else 0,
         credential_id, summary, _now_utc()),
    )
    return int(cur.lastrowid)


def add_password_policy(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    domain: str | None = None,
    host_id: int | None = None,
    min_length: int | None = None,
    lockout_threshold: int | None = None,
    lockout_window_min: int | None = None,
    complexity: int | None = None,
    source: str | None = None,
) -> int:
    """Record an observed password policy (gates safe spraying)."""
    cur = conn.execute(
        "INSERT INTO password_policy (engagement_id, domain, host_id, min_length, "
        "lockout_threshold, lockout_window_min, complexity, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, domain, host_id, min_length, lockout_threshold, lockout_window_min,
         complexity, source, _now_utc()),
    )
    return int(cur.lastrowid)


def add_objective(
    conn: sqlite3.Connection,
    engagement_id: int,
    label: str,
    *,
    host_id: int | None = None,
    kind: str = "flag",
    points: int = 0,
    captured: bool = False,
    notes: str | None = None,
) -> tuple[int, bool]:
    """Record a point-bearing objective (deduped by engagement+host+label)."""
    existing = conn.execute(
        "SELECT id FROM objective WHERE engagement_id = ? AND host_id IS ? AND label = ?",
        (engagement_id, host_id, label),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE objective SET kind = ?, points = ?, captured = ?, "
            "notes = COALESCE(?, notes) WHERE id = ?",
            (kind, points, 1 if captured else 0, notes, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO objective (engagement_id, host_id, kind, label, points, captured, "
        "notes, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, kind, label, points, 1 if captured else 0, notes,
         _now_utc()),
    )
    return int(cur.lastrowid), True


def add_share(
    conn: sqlite3.Connection,
    host_id: int,
    name: str,
    *,
    proto: str = "smb",
    access: str | None = None,
    remark: str | None = None,
    source: str | None = None,
) -> tuple[int, bool]:
    """Record an SMB/NFS share (deduped by host+name+proto).

    On update, `access` is overwritten (it reflects the CURRENT principal's rights,
    which legitimately change as we gain creds) but `remark` is only filled if the
    row lacked one."""
    existing = conn.execute(
        "SELECT id FROM share WHERE host_id = ? AND name = ? AND proto = ?",
        (host_id, name, proto),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE share SET access = COALESCE(?, access), remark = COALESCE(remark, ?), "
            "source = COALESCE(?, source) WHERE id = ?",
            (access, remark, source, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO share (host_id, name, proto, access, remark, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (host_id, name, proto, access, remark, source, _now_utc()),
    )
    return int(cur.lastrowid), True
