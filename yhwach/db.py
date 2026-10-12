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

import contextlib
import hashlib
import ipaddress
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from yhwach import data_path, persona_path, schema_sql_path

# Schema additions made after the original v0 (columns + whole tables). Applied
# idempotently on every open so a DB created by an older Yhwach self-heals — no
# more "no such column: f.tag / engagement_id" on an upgraded engagement.
# Bumped when the additive self-heal below gains a column/table. Stamped into
# PRAGMA user_version so a future rebuild-style migration (e.g. relaxing a NOT
# NULL) has a version anchor to branch on. The additive path stays idempotent.
SCHEMA_VERSION = 10

_ADDED_COLUMNS = [
    ("finding", "tag", "TEXT"),
    ("finding", "engagement_id", "INTEGER"),
    ("credential", "source_host_id", "INTEGER"),
    # schema v1 — attack-surface enrichment
    ("service", "cpe", "TEXT"),
    ("credential", "principal_id", "INTEGER"),
    # arsenal wiring: record WHICH binary shipped for a tunnel so the DB
    # remembers ground truth even when the arsenal moves. See yhwach.arsenal.
    ("tunnel", "agent_path", "TEXT"),
    # schema v2 — world-model auto-materialisation (see yhwach.discovery).
    # `discovery_source` records HOW a host first became known
    # (scope | nmap | finding | cred | cert_san | operator | ...), so the
    # audit trail survives even after a host advances past 'undiscovered'.
    # `scan_needed` is the queue flag PR-2's scanner reads to decide which
    # hosts still owe a full-port + -sV pass.
    ("host", "discovery_source", "TEXT"),
    ("host", "scan_needed", "INTEGER DEFAULT 1"),
    # schema v3 — engagement profile (real engagements, not just scored labs)
    # and credential provenance. All nullable/defaulted so an older DB
    # self-heals and the lab behaviour is unchanged (NULL kind == lab).
    ("engagement", "kind", "TEXT"),
    ("engagement", "client", "TEXT"),
    ("engagement", "active_mode", "TEXT"),
    ("engagement", "status", "TEXT"),
    ("engagement", "ended_at", "TEXT"),
    ("credential", "provenance", "TEXT"),
    # schema v3 — finding lifecycle (memory only; report fields are out of scope)
    ("finding", "location", "TEXT"),
    ("finding", "group_key", "TEXT"),
    ("finding", "curated", "INTEGER NOT NULL DEFAULT 0"),
    ("finding", "author", "TEXT"),
    # schema v5 — dumped hashes / cracked passwords are kept but NEVER auto-sprayed
    # (spraying a dumped domain hash across the estate is the loud, dangerous move).
    ("credential", "spray_policy", "TEXT"),
    # schema v6 — reachability tri-state. A ping miss is 'unanswered', never 'dead'
    # (Windows hosts drop ICMP); scope-only hosts are 'unseen' until confirmed up.
    ("host", "alive", "TEXT"),
    # schema v8 (G2a) — scanner-vuln columns so a Nessus/OpenVAS row is keyed and
    # carries its remediation + output excerpt, not just a CVE.
    ("vulnerability", "plugin_id", "TEXT"),
    ("vulnerability", "port", "INTEGER"),
    ("vulnerability", "solution", "TEXT"),
    ("vulnerability", "plugin_output", "TEXT"),
    # schema v9 (I46) — operator-asserted principal ownership (out-of-band access
    # yhwach cannot observe). Ownership otherwise comes ONLY from validated access.
    ("principal", "owned", "INTEGER DEFAULT 0"),
]

# A finding is LIVE (feeds recall, the brief, the register) in these states;
# any other status (false_positive|duplicate|remediated|dead) is closed — it
# stays queryable via yhwach_query but drops out of recall and the open register.
LIVE_FINDING_STATUSES = ("open", "confirmed", "exploited")
FINDING_STATUSES = (*LIVE_FINDING_STATUSES, "false_positive", "duplicate", "remediated", "dead")
FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info")
_ADDED_TABLES = {
    # schema v3 — evidence (proof artefacts bound to findings/objectives).
    "evidence": (
        "CREATE TABLE IF NOT EXISTS evidence ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  kind TEXT NOT NULL,"
        "  path TEXT,"
        "  sha256 TEXT NOT NULL,"
        "  size INTEGER,"
        "  mime TEXT,"
        "  caption TEXT,"
        "  contains_secret INTEGER NOT NULL DEFAULT 0,"
        "  captured_at TEXT NOT NULL,"
        "  captured_by TEXT,"
        "  UNIQUE(engagement_id, sha256))"
    ),
    "evidence_link": (
        "CREATE TABLE IF NOT EXISTS evidence_link ("
        "  id INTEGER PRIMARY KEY,"
        "  evidence_id INTEGER NOT NULL REFERENCES evidence(id),"
        "  finding_id INTEGER REFERENCES finding(id),"
        "  objective TEXT,"
        "  UNIQUE(evidence_id, finding_id, objective))"
    ),
    # schema v3 — typed scope list (see db/schema.sql + yhwach.scope). Kept in
    # lockstep with schema.sql so an older DB self-heals on open.
    "scope_entry": (
        "CREATE TABLE IF NOT EXISTS scope_entry ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  kind TEXT NOT NULL,"
        "  value TEXT NOT NULL,"
        "  include INTEGER NOT NULL DEFAULT 1,"
        "  note TEXT,"
        "  source TEXT,"
        "  added_at TEXT NOT NULL,"
        "  removed_at TEXT,"
        "  UNIQUE(engagement_id, kind, value, include))"
    ),
    # Probe RUNS were recorded nowhere: `yhwach probe` wrote a row only on a HIT,
    # so "never probed" and "probed, nothing matched" were indistinguishable —
    # and brief.py reports "Unprobed services" from a LEFT JOIN on `surface`,
    # which is wrong for exactly that reason.
    # Model-authored prose about a host. The engine never calls a model: the
    # deterministic dossier is the product, and Claude Code (the MCP client) is
    # what writes a row here. See docs/design-ui-information-surface.md §5.4.
    "host_annotation": (
        "CREATE TABLE IF NOT EXISTS host_annotation ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  stage TEXT NOT NULL,"
        "  section TEXT NOT NULL,"
        "  body TEXT NOT NULL,"
        "  author TEXT,"
        "  model TEXT,"
        "  source_hash TEXT NOT NULL,"
        "  created_at TEXT NOT NULL,"
        "  UNIQUE(host_id, stage, section))"
    ),
    "probe_run": (
        "CREATE TABLE IF NOT EXISTS probe_run ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  port INTEGER NOT NULL,"
        "  probe TEXT NOT NULL,"
        "  result TEXT NOT NULL,"          # hit | miss | error
        "  kind TEXT,"
        "  ran_at TEXT NOT NULL,"
        "  UNIQUE(host_id, port, probe))"
    ),
    "tunnel": (
        "CREATE TABLE IF NOT EXISTS tunnel ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER REFERENCES engagement(id),"
        "  via_host_id INTEGER REFERENCES host(id),"
        "  subnet TEXT NOT NULL,"
        "  kind TEXT NOT NULL DEFAULT 'ligolo',"
        "  agent_path TEXT,"
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
    # worker_state: a live heartbeat per host-worker so the UI "gaze" reflects
    # what is running NOW (all parallel workers, with staleness), instead of
    # inferring a single active worker from the last attempt row. One row per
    # (engagement, host); upserted at worker start/step/end.
    "worker_state": (
        "CREATE TABLE IF NOT EXISTS worker_state ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_ip TEXT NOT NULL,"
        "  status TEXT NOT NULL,"  # watching | running | done | fail | idle
        "  focus TEXT,"
        "  cmd TEXT,"
        "  phase TEXT,"
        "  updated_at TEXT NOT NULL,"
        "  UNIQUE(engagement_id, host_ip))"
    ),
    # host_tag: free-form multi-labels on a host (windows, dc, ai-target, tier0,
    # dead-end, ...) — orthogonal to the single FSM `stage`. Deduped per (host, tag).
    "host_tag": (
        "CREATE TABLE IF NOT EXISTS host_tag ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  tag TEXT NOT NULL,"
        "  note TEXT,"
        "  added_at TEXT NOT NULL,"
        "  UNIQUE(host_id, tag))"
    ),
    # stage_transition: the per-host history trail (scanned -> enumerated ->
    # looted ...), written on every real stage change so the UI shows what
    # happened to a host and when, not just where it landed.
    "stage_transition": (
        "CREATE TABLE IF NOT EXISTS stage_transition ("
        "  id INTEGER PRIMARY KEY,"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  from_stage TEXT,"
        "  to_stage TEXT NOT NULL,"
        "  note TEXT,"
        "  ts TEXT NOT NULL)"
    ),
    # credential_access: which host/port a credential actually opens. One row per
    # (cred, host, proto, port). Feeds the UI Vault "opens" column and turns the
    # credential's `validated_on_host_id` from a guess into a proven fact.
    "credential_access": (
        "CREATE TABLE IF NOT EXISTS credential_access ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  credential_id INTEGER NOT NULL REFERENCES credential(id),"
        "  host_id INTEGER NOT NULL REFERENCES host(id),"
        "  port INTEGER,"
        "  proto TEXT,"
        "  service_kind TEXT,"
        "  result TEXT NOT NULL DEFAULT 'success',"  # success | admin | fail
        "  source TEXT,"
        "  checked_at TEXT NOT NULL,"
        "  UNIQUE(credential_id, host_id, proto, port))"
    ),
    # -- schema v4 — engagement-memory ledgers (mirror db/schema.sql exactly) ---
    "notice": (
        "CREATE TABLE IF NOT EXISTS notice ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  kind TEXT NOT NULL,"
        "  body TEXT NOT NULL,"
        "  finding_id INTEGER REFERENCES finding(id),"
        "  actor TEXT,"
        "  channel TEXT,"
        "  at TEXT NOT NULL)"
    ),
    "activity": (
        "CREATE TABLE IF NOT EXISTS activity ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  actor TEXT NOT NULL,"
        "  action TEXT NOT NULL,"
        "  target TEXT,"
        "  command TEXT,"
        "  result TEXT,"
        "  at TEXT NOT NULL)"
    ),
    "artifact": (
        "CREATE TABLE IF NOT EXISTS artifact ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  kind TEXT NOT NULL,"
        "  location TEXT NOT NULL,"
        "  state TEXT NOT NULL DEFAULT 'rendered',"
        "  note TEXT,"
        "  created_at TEXT NOT NULL,"
        "  removed_at TEXT)"
    ),
    "submission": (
        "CREATE TABLE IF NOT EXISTS submission ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  program TEXT,"
        "  finding_id INTEGER REFERENCES finding(id),"
        "  endpoint TEXT,"
        "  param TEXT,"
        "  cls TEXT,"
        "  status TEXT,"
        "  note TEXT,"
        "  submitted_at TEXT NOT NULL)"
    ),
    # schema v7 — domain-wide AD facts (mirror db/schema.sql exactly)
    "domain_fact": (
        "CREATE TABLE IF NOT EXISTS domain_fact ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  domain TEXT,"
        "  key TEXT NOT NULL,"
        "  value TEXT,"
        "  source TEXT,"
        "  discovered_at TEXT NOT NULL,"
        "  UNIQUE(engagement_id, domain, key))"
    ),
    "payload": (
        "CREATE TABLE IF NOT EXISTS payload ("
        "  id INTEGER PRIMARY KEY,"
        "  engagement_id INTEGER NOT NULL REFERENCES engagement(id),"
        "  host_id INTEGER REFERENCES host(id),"
        "  surface TEXT,"
        "  payload TEXT NOT NULL,"
        "  response TEXT,"
        "  canary TEXT,"
        "  auto_verdict TEXT,"
        "  verdict TEXT NOT NULL DEFAULT 'unclear',"
        "  note TEXT,"
        "  at TEXT NOT NULL)"
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
    # Indexes an older DB will not have. CREATE INDEX IF NOT EXISTS is cheap and
    # idempotent, and without idx_surface_service the /surfaces inventory runs a
    # full scan of `surface` per `service`.
    for ddl in (
        "CREATE INDEX IF NOT EXISTS idx_surface_service ON surface(service_id)",
        "CREATE INDEX IF NOT EXISTS idx_surface_host ON surface(host_id)",
        "CREATE INDEX IF NOT EXISTS idx_scope_entry_eng ON scope_entry(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_evidence_eng ON evidence(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_evidence_link_finding ON evidence_link(finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_notice_eng ON notice(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_activity_eng ON activity(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_artifact_eng ON artifact(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_submission_eng ON submission(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_domain_fact_eng ON domain_fact(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_payload_eng ON payload(engagement_id)",
    ):
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute(ddl)
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
    # Stamp the schema version so a later rebuild-style migration can branch on
    # it. PRAGMA doesn't take bound params; SCHEMA_VERSION is our own int.
    with contextlib.suppress(sqlite3.OperationalError):
        if int(conn.execute("PRAGMA user_version").fetchone()[0]) != SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            changed = True
    if changed:
        conn.commit()


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection with row-dict access, foreign keys on, and schema self-heal."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Wait (up to 5s) instead of erroring when another connection holds the write
    # lock — required so parallel per-host workers (and the live UI reading
    # alongside a run) share the DB safely under WAL.
    conn.execute("PRAGMA busy_timeout = 5000")
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
        # Stamp the version on a fresh DB too, so it matches a self-healed one
        # (schema.sql does not carry it). PRAGMA takes no bound params.
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()
    harden_perms(path)


# The DB holds credentials in the clear (by design — the operator needs them),
# so the one cheap protection kept from Theme G is owner-only file perms: 0600 on
# the DB and its WAL/SHM sidecars, 0700 on the directory. POSIX-only; a no-op on
# Windows (the target platform is Linux), where chmod cannot express this.
_SIDECAR_SUFFIXES = ("-wal", "-shm")
_INSECURE_MASK = 0o077  # any group/other bit set


def _db_targets(db_path: Path | str) -> list[Path]:
    path = Path(db_path)
    return [path, *(path.with_name(path.name + s) for s in _SIDECAR_SUFFIXES)]


def harden_perms(db_path: Path | str) -> None:
    """Best-effort chmod the DB (and sidecars) to 0600 and its dir to 0700."""
    if os.name != "posix":
        return
    path = Path(db_path)
    with suppress(OSError):
        os.chmod(path.parent, 0o700)
    for p in _db_targets(path):
        if p.exists():
            with suppress(OSError):
                os.chmod(p, 0o600)


def perms_insecure(db_path: Path | str) -> list[str]:
    """Existing DB-related paths readable or writable by group/other.

    Empty on success, and always empty on non-POSIX platforms (where the bits
    do not apply). Used by `yhwach doctor` to warn without changing anything."""
    if os.name != "posix":
        return []
    path = Path(db_path)
    bad: list[str] = []
    for p in (path.parent, *_db_targets(path)):
        with suppress(OSError):
            if p.exists() and (os.stat(p).st_mode & _INSECURE_MASK):
                bad.append(str(p))
    return bad


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


# Engagement kinds whose default posture is ARMED (active traffic allowed on a
# memory write). Every other kind defaults to record_only — a client engagement
# must be armed deliberately, in a terminal, not by taking a note.
_ARMED_BY_DEFAULT_KINDS = frozenset({"lab", "ctf"})


def default_active_mode(kind: str | None) -> str:
    """The posture a new engagement of this kind starts in."""
    return "armed" if (kind or "lab") in _ARMED_BY_DEFAULT_KINDS else "record_only"


def upsert_engagement(
    conn: sqlite3.Connection,
    lab: str,
    scope: str,
    domain: str | None = None,
    dc_ip: str | None = None,
    started_at: str | None = None,
    points_target: int | None = None,
    points_max: int | None = None,
    time_budget_h: float | None = None,
    kind: str | None = None,
    client: str | None = None,
    active_mode: str | None = None,
) -> int:
    """Create or update an engagement row and return its id.

    `points_target` / `points_max` / `time_budget_h` are optional, engagement-
    specific scoring knobs (NULL = unscored); set them to drive the scoreboard's
    pace/percentage view. They are never assumed by the engine.

    `kind` picks the engagement profile (lab|ctf|internal|external|web|cloud|
    redteam|bounty|retest; NULL == lab). `active_mode` is the traffic posture
    (armed|record_only); when NULL on a new engagement it defaults from the kind
    (lab/ctf armed, everything else record_only). Arming is otherwise a
    deliberate CLI act, never set from the MCP wire.
    """
    if started_at is None:
        started_at = _now_utc()

    existing = engagement_id_for(conn, lab)
    if existing is not None:
        conn.execute(
            "UPDATE engagement SET scope = ?, domain = COALESCE(?, domain), "
            "dc_ip = COALESCE(?, dc_ip), points_target = COALESCE(?, points_target), "
            "points_max = COALESCE(?, points_max), time_budget_h = COALESCE(?, time_budget_h), "
            "kind = COALESCE(?, kind), client = COALESCE(?, client), "
            "active_mode = COALESCE(?, active_mode) "
            "WHERE id = ?",
            (scope, domain, dc_ip, points_target, points_max, time_budget_h,
             kind, client, active_mode, existing),
        )
        return existing

    if active_mode is None:
        active_mode = default_active_mode(kind)
    cur = conn.execute(
        "INSERT INTO engagement (lab, domain, dc_ip, scope, started_at, "
        "points_target, points_max, time_budget_h, kind, client, active_mode, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
        (lab, domain, dc_ip, scope, started_at, points_target, points_max,
         time_budget_h, kind, client, active_mode),
    )
    return int(cur.lastrowid)


def engagement_armed(conn: sqlite3.Connection, engagement_id: int) -> bool:
    """True when active traffic is allowed for this engagement.

    Posture comes from engagement.active_mode (NULL => armed, matching the
    pre-profile lab default). A terminal-set `record_only` disables every
    traffic-sending path until `yhwach arm` flips it.
    """
    row = conn.execute(
        "SELECT active_mode FROM engagement WHERE id = ?", (engagement_id,)
    ).fetchone()
    if row is None:
        return False
    return (row["active_mode"] or "armed") != "record_only"


def set_active_mode(conn: sqlite3.Connection, engagement_id: int, mode: str) -> None:
    if mode not in ("armed", "record_only"):
        raise ValueError(f"invalid active_mode {mode!r} (armed|record_only)")
    conn.execute(
        "UPDATE engagement SET active_mode = ? WHERE id = ?", (mode, engagement_id)
    )


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
    note: str | None = None,
) -> tuple[bool, str | None]:
    """Set a host's FSM stage. With monotonic=True, refuse to move backwards
    (except to 'blocked'). Returns (changed, message).

    `note` records WHY the host moved. The column existed from the start and had
    no writer, so "what evidence moved this host to this stage" was answerable
    only by timestamp inference."""
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
    now = _now_utc()
    conn.execute(
        "UPDATE host SET stage = ?, last_updated = ? WHERE id = ?",
        (stage, now, row["id"]),
    )
    if stage != cur_stage:  # record the history trail on a real transition
        conn.execute(
            "INSERT INTO stage_transition (host_id, from_stage, to_stage, note, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["id"], cur_stage, stage, note, now),
        )
    return True, None


# Recognised tunnel kinds — a soft-enum enforced by add_tunnel(strict=True).
# 'ligolo' stays the historical default so pre-arsenal callers keep working;
# 'chisel' is the Linux-foothold fast path (see yhwach.arsenal.CHISEL);
# 'ssh_dyn' / 'socat' cover the manual-fallback shapes an operator may use
# when neither ligolo nor chisel is deployable.
TUNNEL_KINDS = ("ligolo", "chisel", "ssh_dyn", "socat")


def host_fingerprint(conn: sqlite3.Connection, host_id: int) -> str:
    """A cheap, exact "has anything been learned about this host" key.

    MAX(id) over six monotonic tables plus the stage. One SELECT, and it changes
    if and only if something new was recorded — so a stored annotation can be
    compared against it with two string equalities and no model call.
    """
    row = conn.execute(
        "SELECT (SELECT COALESCE(stage,'') FROM host WHERE id=:h) "
        "|| '|' || (SELECT COALESCE(MAX(id),0) FROM service WHERE host_id=:h) "
        "|| '|' || (SELECT COALESCE(MAX(id),0) FROM surface WHERE host_id=:h) "
        "|| '|' || (SELECT COALESCE(MAX(id),0) FROM finding WHERE host_id=:h) "
        "|| '|' || (SELECT COALESCE(MAX(id),0) FROM attempt WHERE host_id=:h) "
        "|| '|' || (SELECT COALESCE(MAX(id),0) FROM scan_coverage WHERE host_id=:h) "
        "|| '|' || (SELECT COALESCE(MAX(id),0) FROM stage_transition WHERE host_id=:h) AS fp",
        {"h": host_id},
    ).fetchone()
    return hashlib.sha256((row["fp"] or "").encode()).hexdigest()[:32]


def add_host_annotation(
    conn: sqlite3.Connection,
    host_id: int,
    section: str,
    body: str,
    *,
    author: str | None = None,
    model: str | None = None,
) -> str:
    """Store model-authored prose about a host, stamped with the world-model
    state it was written against. Returns the fingerprint. Deduped on
    (host, stage, section): re-annotating replaces."""
    stage = conn.execute("SELECT stage FROM host WHERE id=?", (host_id,)).fetchone()
    stage = stage["stage"] if stage else ""
    fp = host_fingerprint(conn, host_id)
    conn.execute(
        "INSERT INTO host_annotation (host_id, stage, section, body, author, model, "
        "source_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(host_id, stage, section) DO UPDATE SET body=excluded.body, "
        "author=excluded.author, model=excluded.model, source_hash=excluded.source_hash, "
        "created_at=excluded.created_at",
        (host_id, stage, section, body, author, model, fp, _now_utc()),
    )
    return fp


def host_annotations(conn: sqlite3.Connection, host_id: int) -> list[sqlite3.Row]:
    """Annotations for a host, newest first, each carrying whether it is stale.

    The board NEVER rewrites the hash, deletes a stale row, or calls a model — it
    compares two strings.
    """
    live = host_fingerprint(conn, host_id)
    rows = conn.execute(
        "SELECT section, body, stage, COALESCE(author,'') author, COALESCE(model,'') model, "
        "source_hash, created_at, (source_hash <> ?) AS stale "
        "FROM host_annotation WHERE host_id=? ORDER BY created_at DESC",
        (live, host_id),
    ).fetchall()
    return rows


def hosts_in_subnet(
    conn: sqlite3.Connection,
    engagement_id: int,
    cidr: str,
    *,
    include_undiscovered: bool = False,
) -> tuple[int, int]:
    """(known, owned) hosts inside a CIDR. Returns (0, 0) for an unparseable one.

    Membership is decided numerically, not by truncating the string to a /24 —
    that got a /16 tunnel wrong in both directions and fell back to LIKE '%'
    (i.e. "every host in the engagement") when the subnet had no dotted prefix.

    `undiscovered` hosts are excluded by default: `engage` materialises every IP
    of every scope CIDR as a placeholder row, so counting them reported a
    completely untouched /24 as 254 hosts "known inside".
    """
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except (ValueError, TypeError):
        return 0, 0
    known = owned = 0
    for r in conn.execute(
        "SELECT ip, stage FROM host WHERE engagement_id = ?", (engagement_id,)
    ):
        if not include_undiscovered and r["stage"] == "undiscovered":
            continue
        try:
            if ipaddress.ip_address(r["ip"]) not in net:
                continue
        except (ValueError, TypeError):
            continue
        known += 1
        if r["stage"] in ("foothold", "looted", "pivoted", "done"):
            owned += 1
    return known, owned


def record_probe_run(
    conn: sqlite3.Connection,
    engagement_id: int,
    host_id: int,
    port: int,
    probe: str,
    result: str,
    *,
    kind: str | None = None,
) -> None:
    """Record that a probe actually ran against a host:port.

    Deduped on (host, port, probe): a later run overwrites the verdict, so a miss
    that becomes a hit is not double-counted. This is what separates "never
    probed" from "probed, nothing matched".
    """
    conn.execute(
        "INSERT INTO probe_run (engagement_id, host_id, port, probe, result, kind, ran_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(host_id, port, probe) DO UPDATE SET result=excluded.result, "
        "kind=excluded.kind, ran_at=excluded.ran_at",
        (engagement_id, host_id, port, probe, result, kind, _now_utc()),
    )


def add_tunnel(
    conn: sqlite3.Connection,
    engagement_id: int,
    via_host_id: int | None,
    subnet: str,
    kind: str = "ligolo",
    agent_path: str | None = None,
    *,
    strict: bool = False,
) -> tuple[int, bool]:
    """Record a pivot tunnel (a subnet reachable via a host).

    Deduped by (engagement, via_host, subnet). ``kind`` is a soft-enum from
    :data:`TUNNEL_KINDS`; ``strict=True`` rejects unknown kinds instead of
    accepting them, for callers that want the enum enforced (the CLI passes
    strict=True; ingest paths that reconstruct historical rows do not).
    ``agent_path`` optionally records the exact arsenal binary that was
    deployed (a :mod:`yhwach.arsenal` key like ``"SVCMON_WIN"`` or an
    absolute path) so the DB carries ground truth about what shipped.

    Returns ``(id, created)``.
    """
    if strict and kind not in TUNNEL_KINDS:
        raise ValueError(
            f"unknown tunnel kind {kind!r}; expected one of {TUNNEL_KINDS}"
        )
    existing = conn.execute(
        "SELECT id FROM tunnel WHERE engagement_id = ? AND via_host_id IS ? AND subnet = ?",
        (engagement_id, via_host_id, subnet),
    ).fetchone()
    if existing is not None:
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO tunnel (engagement_id, via_host_id, subnet, kind, agent_path, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (engagement_id, via_host_id, subnet, kind, agent_path, _now_utc()),
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
    provenance: str | None = None,
    principal_id: int | None = None,
    spray_policy: str | None = None,
) -> tuple[int, bool]:
    """Add/update a credential (deduped by engagement+identifier+kind).

    `provenance` is how the cred came to us: provided (client-issued — an
    assumed-breach / test account), discovered (compromised; the default when
    NULL), derived, or guess. A 'provided' cred must never be sprayed or counted
    as compromised; provenance is never downgraded on re-record.

    Creds are never exhausted — the spray primitive keeps them in play against
    every host. On update, `source` is APPENDED (comma-joined) rather than
    overwritten, so a cred rediscovered via a new channel keeps its full
    provenance chain (e.g. `sqli_app_config,jenkins_credentials.xml`).
    `source_host_id`, when supplied on an update, is only filled in if the
    row didn't already carry one — the original discovery host wins.
    """
    existing = conn.execute(
        "SELECT id, secret, source, source_host_id, provenance FROM credential "
        "WHERE engagement_id = ? AND identifier = ? AND kind = ?",
        (engagement_id, identifier, kind),
    ).fetchone()
    if existing is not None:
        merged_source = existing["source"]
        if source and source not in [s.strip() for s in (existing["source"] or "").split(",")]:
            merged_source = f"{existing['source']},{source}" if existing["source"] else source
        # Never downgrade provenance: a cred recorded as 'provided' stays
        # provided even if later re-seen through a discovery channel.
        prov = None if existing["provenance"] == "provided" else provenance
        conn.execute(
            "UPDATE credential SET secret = COALESCE(?, secret), source = ?, "
            "source_host_id = COALESCE(source_host_id, ?), "
            "provenance = COALESCE(?, provenance), "
            "principal_id = COALESCE(principal_id, ?), "
            "spray_policy = COALESCE(?, spray_policy) WHERE id = ?",
            (secret, merged_source, source_host_id, prov, principal_id,
             spray_policy, existing["id"]),
        )
        # If the secret actually changed, the cached 'fail' rows were for the
        # OLD secret — drop them so a password-spray with a new candidate
        # actually gets tried instead of short-circuiting on a stale miss.
        if secret is not None and secret != existing["secret"]:
            conn.execute(
                "DELETE FROM credential_access WHERE credential_id = ? AND result = 'fail'",
                (existing["id"],),
            )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO credential (engagement_id, identifier, secret, kind, source, "
        "source_host_id, discovered_at, provenance, principal_id, spray_policy) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, identifier, secret, kind, source, source_host_id,
         _now_utc(), provenance, principal_id, spray_policy),
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
        "SELECT c.id, c.identifier, c.secret, c.kind, c.source, c.discovered_at, "
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


def record_cred_access(
    conn: sqlite3.Connection,
    engagement_id: int,
    credential_id: int,
    host_id: int,
    *,
    port: int | None = None,
    proto: str | None = None,
    service_kind: str | None = None,
    result: str = "success",
    source: str | None = None,
) -> int:
    """Record that a credential opens a given host/port (deduped by
    cred+host+proto+port). `result` is 'success' | 'admin' | 'fail'; a later
    'admin' upgrades a prior 'success'. Returns the row id."""
    existing = conn.execute(
        "SELECT id, result FROM credential_access "
        "WHERE credential_id = ? AND host_id = ? AND IFNULL(proto,'') = IFNULL(?,'') "
        "AND IFNULL(port,-1) = IFNULL(?,-1)",
        (credential_id, host_id, proto, port),
    ).fetchone()
    if existing is not None:
        # admin beats success beats fail — never downgrade a proven access.
        rank = {"fail": 0, "success": 1, "admin": 2}
        keep = existing["result"]
        if rank.get(result, 1) > rank.get(keep, 1):
            keep = result
        conn.execute(
            "UPDATE credential_access SET result = ?, service_kind = COALESCE(?, service_kind), "
            "source = COALESCE(?, source), checked_at = ? WHERE id = ?",
            (keep, service_kind, source, _now_utc(), existing["id"]),
        )
        return int(existing["id"])
    cur = conn.execute(
        "INSERT INTO credential_access (engagement_id, credential_id, host_id, port, proto, "
        "service_kind, result, source, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, credential_id, host_id, port, proto, service_kind, result, source,
         _now_utc()),
    )
    return int(cur.lastrowid)


def mark_credential_validated(
    conn: sqlite3.Connection,
    engagement_id: int,
    credential_id: int,
    host_id: int,
    *,
    port: int | None = None,
    proto: str | None = None,
    service_kind: str | None = None,
    result: str = "success",
    source: str | None = None,
) -> None:
    """Prove a credential on a host: set `validated_on_host_id` (first proof wins,
    unless this one is 'admin' — an admin proof always takes the slot) and record
    the access row. This is what flips the vault's 'untried' to a real fact."""
    row = conn.execute(
        "SELECT validated_on_host_id FROM credential WHERE id = ?", (credential_id,)
    ).fetchone()
    if row is not None and (row["validated_on_host_id"] is None or result == "admin"):
        conn.execute(
            "UPDATE credential SET validated_on_host_id = ? WHERE id = ?",
            (host_id, credential_id),
        )
    record_cred_access(
        conn, engagement_id, credential_id, host_id, port=port, proto=proto,
        service_kind=service_kind, result=result, source=source,
    )


def list_credential_access(
    conn: sqlite3.Connection, engagement_id: int
) -> dict[int, list[sqlite3.Row]]:
    """Access rows grouped by credential_id: {cred_id: [rows...]}, each row
    carrying the target host IP. Powers the Vault 'opens' column."""
    rows = conn.execute(
        "SELECT ca.credential_id, ca.port, ca.proto, ca.service_kind, ca.result, "
        "h.ip AS host_ip FROM credential_access ca "
        "JOIN host h ON h.id = ca.host_id WHERE ca.engagement_id = ? "
        "ORDER BY ca.result = 'admin' DESC, h.ip, ca.port",
        (engagement_id,),
    ).fetchall()
    out: dict[int, list[sqlite3.Row]] = {}
    for r in rows:
        out.setdefault(int(r["credential_id"]), []).append(r)
    return out


def heartbeat_worker(
    conn: sqlite3.Connection,
    engagement_id: int,
    host_ip: str,
    status: str,
    *,
    focus: str | None = None,
    cmd: str | None = None,
    phase: str | None = None,
) -> None:
    """Upsert a host-worker's live state (one row per engagement+host). Called at
    worker start/step/end so the UI gaze reflects what is running now. `focus`
    and `cmd` are only overwritten when provided, so an end-of-step 'done' beat
    keeps the last technique/command it worked."""
    conn.execute(
        "INSERT INTO worker_state (engagement_id, host_ip, status, focus, cmd, phase, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(engagement_id, host_ip) DO UPDATE SET status=excluded.status, "
        "focus=COALESCE(excluded.focus, worker_state.focus), "
        "cmd=COALESCE(excluded.cmd, worker_state.cmd), "
        "phase=COALESCE(excluded.phase, worker_state.phase), updated_at=excluded.updated_at",
        (engagement_id, host_ip, status, focus, cmd, phase, _now_utc()),
    )


def list_worker_state(conn: sqlite3.Connection, engagement_id: int) -> list[sqlite3.Row]:
    """Every worker heartbeat for the engagement, newest first."""
    return conn.execute(
        "SELECT host_ip, status, focus, cmd, phase, updated_at FROM worker_state "
        "WHERE engagement_id = ? ORDER BY updated_at DESC",
        (engagement_id,),
    ).fetchall()


@lru_cache(maxsize=1)
def _persona_hash() -> str:
    """Fingerprint of the operator persona in effect (for replay). Cached per run."""
    try:
        return hashlib.sha256(persona_path().read_bytes()).hexdigest()[:16]
    except (FileNotFoundError, OSError):
        return ""


@lru_cache(maxsize=1)
def _rules_hash() -> str:
    """Fingerprint of the rule-set in effect: all playbooks/*.yaml + data/*.yaml.
    Cached per run; call `_rules_hash.cache_clear()` in tests that mutate them."""
    from yhwach.knowledge import default_playbook_dir  # lazy: knowledge imports db

    files: list[Path] = []
    with suppress(OSError):
        files += list(default_playbook_dir().glob("*.yaml"))
    with suppress(FileNotFoundError, OSError):
        files += list(data_path("cve_map.yaml").parent.glob("*.yaml"))
    h = hashlib.sha256()
    for p in sorted(files, key=lambda x: x.name):
        try:
            h.update(p.name.encode())
            h.update(p.read_bytes())
        except OSError:
            continue
    return h.hexdigest()[:16]


def log_event(
    conn: sqlite3.Connection,
    engagement_id: int,
    kind: str,
    payload: dict,
) -> int:
    """Append an audit event (drives the report + replay). Every event is stamped
    with the persona + rule-set fingerprints so a run can be replayed against the
    exact doctrine that produced it."""
    import json as _json

    cur = conn.execute(
        "INSERT INTO event (engagement_id, ts, kind, persona_hash, rules_hash, payload_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (engagement_id, _now_utc(), kind, _persona_hash(), _rules_hash(),
         _json.dumps(payload, sort_keys=True)),
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
    location: str | None = None,
) -> tuple[int, bool]:
    """Insert or update a finding, deduped by (engagement, host_id, class, title,
    location).

    `engagement_id` scopes the finding so host-less findings never leak across
    labs; when omitted it is derived from `host_id`. `tag` is the chaining key a
    rule's `findings_include` matches on; on update it is only (re)set when a
    non-null tag is supplied, so a later untagged re-detection never clears it.
    `location` (a URL/param/resource) makes the same class+title on N assets N
    rows, rolled up by `group_key` for the register. A finding the operator has
    curated (via :func:`set_finding`) is frozen: a parser re-ingest never
    clobbers its evidence/severity.
    """
    now = _now_utc()
    if engagement_id is None and host_id is not None:
        hrow = conn.execute("SELECT engagement_id FROM host WHERE id = ?", (host_id,)).fetchone()
        engagement_id = hrow["engagement_id"] if hrow else None
    existing = conn.execute(
        "SELECT id, curated FROM finding WHERE engagement_id IS ? AND host_id IS ? "
        "AND class = ? AND title = ? AND COALESCE(location,'') = COALESCE(?,'')",
        (engagement_id, host_id, cls, title, location),
    ).fetchone()
    if existing is not None:
        if existing["curated"]:
            # Operator-curated: never clobber evidence/severity on re-ingest;
            # only refresh the chaining tag (+ its derived group_key) and ts.
            if tag is not None:
                conn.execute(
                    "UPDATE finding SET tag = ?, group_key = ?, updated_at = ? WHERE id = ?",
                    (tag, tag, now, existing["id"]))
            else:
                conn.execute("UPDATE finding SET updated_at = ? WHERE id = ?",
                             (now, existing["id"]))
        elif tag is not None:
            conn.execute(
                "UPDATE finding SET evidence = ?, tag = ?, group_key = ?, updated_at = ? WHERE id = ?",
                (evidence, tag, tag, now, existing["id"]),
            )
        else:
            conn.execute(
                "UPDATE finding SET evidence = ?, updated_at = ? WHERE id = ?",
                (evidence, now, existing["id"]),
            )
        return int(existing["id"]), False
    group_key = tag or f"{cls}:{title}"
    cur = conn.execute(
        "INSERT INTO finding (engagement_id, host_id, surface_id, class, title, severity, "
        "evidence, tag, playbook_rule_id, status, discovered_at, location, group_key) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        (engagement_id, host_id, surface_id, cls, title, severity, evidence, tag,
         playbook_rule_id, now, location, group_key),
    )
    return int(cur.lastrowid), True


def set_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    evidence: str | None = None,
    author: str | None = None,
) -> sqlite3.Row:
    """Operator correction of a finding: change its status (open/confirmed/
    exploited/false_positive/duplicate/remediated/dead), severity or evidence,
    and mark it curated so a later parser re-ingest cannot overwrite it. Returns
    the old row (for the event). Never deletes — a wrong finding is closed, not
    erased (memory is sacred)."""
    if status is not None and status not in FINDING_STATUSES:
        raise ValueError(f"invalid status {status!r} (one of {', '.join(FINDING_STATUSES)})")
    if severity is not None:
        severity = severity.strip().lower()
        if severity not in FINDING_SEVERITIES:
            raise ValueError(
                f"invalid severity {severity!r} (one of {', '.join(FINDING_SEVERITIES)})")
    old = conn.execute("SELECT id, status, severity FROM finding WHERE id = ?",
                       (finding_id,)).fetchone()
    if old is None:
        raise ValueError(f"no finding #{finding_id}")
    sets, params = ["curated = 1", "updated_at = ?"], [_now_utc()]
    for col, val in (("status", status), ("severity", severity),
                     ("evidence", evidence), ("author", author)):
        if val is not None:
            sets.append(f"{col} = ?")
            params.append(val)
    params.append(finding_id)
    conn.execute(f"UPDATE finding SET {', '.join(sets)} WHERE id = ?", params)
    return old


def add_evidence(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    kind: str,
    path: str | None = None,
    text: str | None = None,
    finding_id: int | None = None,
    objective: str | None = None,
    caption: str | None = None,
    contains_secret: bool = False,
    captured_by: str | None = None,
    artifact_dir: Path | None = None,
) -> tuple[int, bool]:
    """Record a proof artefact and bind it to a finding/objective.

    Exactly one of `path` (an existing, non-empty file — hashed at record time,
    refused if missing/empty, mirroring the anti-fabrication rule of the
    screenshot hook) or `text` (written under `artifact_dir`) must be given.
    Deduped by (engagement, sha256); one artefact may back many findings via
    evidence_link. Returns (evidence_id, created_new_evidence)."""
    import hashlib

    if (path is None) == (text is None):
        raise ValueError("pass exactly one of path= or text=")
    if path is not None:
        p = Path(path)
        if not p.is_file() or p.stat().st_size == 0:
            raise ValueError(f"evidence file missing or empty: {path}")
        data = p.read_bytes()
        stored = str(p)
        size = len(data)
    else:
        data = text.encode("utf-8", "replace")
        if not data:
            raise ValueError("empty evidence text")
        d = artifact_dir or Path(".")
        d.mkdir(parents=True, exist_ok=True)
        sha_pre = hashlib.sha256(data).hexdigest()
        p = d / f"evidence_{kind}_{sha_pre[:12]}.txt"
        p.write_text(text, encoding="utf-8")
        stored = str(p)
        size = len(data)
    sha = hashlib.sha256(data).hexdigest()
    now = _now_utc()
    existing = conn.execute(
        "SELECT id FROM evidence WHERE engagement_id = ? AND sha256 = ?",
        (engagement_id, sha)).fetchone()
    created = existing is None
    if existing is None:
        cur = conn.execute(
            "INSERT INTO evidence (engagement_id, kind, path, sha256, size, caption, "
            "contains_secret, captured_at, captured_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (engagement_id, kind, stored, sha, size, caption, 1 if contains_secret else 0,
             now, captured_by))
        eid_ev = int(cur.lastrowid)
    else:
        eid_ev = int(existing["id"])
    if finding_id is not None or objective is not None:
        # NULL-safe idempotency: SQLite treats NULLs as distinct in a UNIQUE
        # index, so OR IGNORE would NOT dedup a finding-only (objective NULL) or
        # objective-only (finding_id NULL) re-bind. `IS` is NULL-safe equality.
        conn.execute(
            "INSERT INTO evidence_link (evidence_id, finding_id, objective) "
            "SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM evidence_link "
            "WHERE evidence_id = ? AND finding_id IS ? AND objective IS ?)",
            (eid_ev, finding_id, objective, eid_ev, finding_id, objective))
    return eid_ev, created


def evidence_for(conn: sqlite3.Connection, finding_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT e.id, e.kind, e.path, e.sha256, e.caption, e.captured_at FROM evidence e "
        "JOIN evidence_link l ON l.evidence_id = e.id WHERE l.finding_id = ? ORDER BY e.id",
        (finding_id,)).fetchall()


# ---------------------------------------------------------------------------
# Engagement-memory ledgers (schema v4) — what the client was told, what traffic
# yhwach originated, what it left behind, and what was submitted. Memory only:
# nothing here computes a score or renders a report.
# ---------------------------------------------------------------------------
NOTICE_KINDS = (
    "critical_notification", "status_update", "stop", "pause", "resume",
    "detection", "scope_change",
)
ACTIVITY_ACTORS = ("yhwach", "operator", "model")
ARTIFACT_STATES = ("rendered", "deployed", "removed")

# Flags whose following (or attached/= -joined) token is a secret, so the
# activity ledger stores `-p ***` rather than the plaintext (the ps/argv leak).
_SECRET_FLAGS = (
    "-p", "--password", "--pass", "-H", "--hash", "--nthash", "-k", "--key",
    "--token", "--secret", "--api-key",
)
_SECRET_FLAGS_ATTACHED = ("-p", "-H", "-k")  # short forms that glue the value on


def redact_argv(cmd: str | None) -> str | None:
    """Mask secret values in a command line before it is stored.

    Whitespace is normalised (this is a memory aid, not a re-exec string), and a
    value quoted with spaces may be only partly masked — so callers must never
    treat a stored command as safe to run verbatim."""
    if not cmd:
        return cmd
    out: list[str] = []
    redact_next = False
    for tok in cmd.split():
        if redact_next:
            out.append("***")
            redact_next = False
            continue
        base = tok.split("=", 1)[0]
        if "=" in tok and base in _SECRET_FLAGS:
            out.append(base + "=***")
        elif len(tok) > 2 and tok[:2] in _SECRET_FLAGS_ATTACHED:
            out.append(tok[:2] + "***")
        elif tok in _SECRET_FLAGS:
            out.append(tok)
            redact_next = True
        else:
            out.append(tok)
    return " ".join(out)


# -- G4a notice ledger -------------------------------------------------------
def add_notice(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    kind: str,
    body: str,
    finding_id: int | None = None,
    actor: str | None = None,
    channel: str | None = None,
) -> int:
    """Record one client communication (what was said and when)."""
    if kind not in NOTICE_KINDS:
        raise ValueError(f"unknown notice kind '{kind}' — use one of {', '.join(NOTICE_KINDS)}")
    cur = conn.execute(
        "INSERT INTO notice (engagement_id, kind, body, finding_id, actor, channel, at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, kind, body, finding_id, actor, channel, _now_utc()),
    )
    return int(cur.lastrowid)


def list_notices(
    conn: sqlite3.Connection, engagement_id: int, *, limit: int | None = None,
) -> list[sqlite3.Row]:
    sql = ("SELECT id, kind, body, finding_id, actor, channel, at FROM notice "
           "WHERE engagement_id = ? ORDER BY id DESC")
    params: list = [engagement_id]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


def uncommunicated_critical_findings(
    conn: sqlite3.Connection, engagement_id: int,
) -> list[sqlite3.Row]:
    """Live critical findings with no critical_notification notice linked — the
    QA rule: telling the client about a critical is blocking before close."""
    marks = ", ".join("?" * len(LIVE_FINDING_STATUSES))
    return conn.execute(
        f"SELECT f.id, f.title, f.severity, f.status FROM finding f "
        f"WHERE f.engagement_id = ? AND f.severity = 'critical' "
        f"AND f.status IN ({marks}) "
        f"AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.engagement_id = f.engagement_id "
        f"AND n.kind = 'critical_notification' AND n.finding_id = f.id) "
        f"ORDER BY f.id",
        (engagement_id, *LIVE_FINDING_STATUSES),
    ).fetchall()


# -- I05 activity ledger -----------------------------------------------------
def add_activity(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    actor: str,
    action: str,
    host_id: int | None = None,
    target: str | None = None,
    command: str | None = None,
    result: str | None = None,
) -> int:
    """Append one originated action. `command` is redacted here, so a caller may
    pass a raw command line without leaking a secret into the ledger."""
    if actor not in ACTIVITY_ACTORS:
        raise ValueError(f"unknown actor '{actor}' — use one of {', '.join(ACTIVITY_ACTORS)}")
    cur = conn.execute(
        "INSERT INTO activity (engagement_id, host_id, actor, action, target, "
        "command, result, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, actor, action, target, redact_argv(command),
         result, _now_utc()),
    )
    return int(cur.lastrowid)


def list_activity(
    conn: sqlite3.Connection, engagement_id: int, *, limit: int | None = None,
) -> list[sqlite3.Row]:
    sql = ("SELECT a.id, a.actor, a.action, a.target, a.command, a.result, a.at, "
           "h.ip AS host_ip FROM activity a LEFT JOIN host h ON h.id = a.host_id "
           "WHERE a.engagement_id = ? ORDER BY a.id DESC")
    params: list = [engagement_id]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


# -- I39 artifact cleanup ledger ---------------------------------------------
def add_artifact(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    kind: str,
    location: str,
    host_id: int | None = None,
    state: str = "rendered",
    note: str | None = None,
) -> int:
    """Record something left on a client system that must be cleaned up."""
    if state not in ARTIFACT_STATES:
        raise ValueError(f"unknown state '{state}' — use one of {', '.join(ARTIFACT_STATES)}")
    cur = conn.execute(
        "INSERT INTO artifact (engagement_id, host_id, kind, location, state, note, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, kind, location, state, note, _now_utc()),
    )
    return int(cur.lastrowid)


def set_artifact_state(
    conn: sqlite3.Connection, artifact_id: int, state: str,
) -> None:
    """Advance an artifact (operator confirms the drop -> 'removed')."""
    if state not in ARTIFACT_STATES:
        raise ValueError(f"unknown state '{state}' — use one of {', '.join(ARTIFACT_STATES)}")
    removed_at = _now_utc() if state == "removed" else None
    conn.execute(
        "UPDATE artifact SET state = ?, removed_at = ? WHERE id = ?",
        (state, removed_at, artifact_id),
    )


def list_artifacts(
    conn: sqlite3.Connection, engagement_id: int, *, outstanding_only: bool = False,
) -> list[sqlite3.Row]:
    sql = ("SELECT a.id, a.kind, a.location, a.state, a.note, a.created_at, "
           "a.removed_at, h.ip AS host_ip FROM artifact a "
           "LEFT JOIN host h ON h.id = a.host_id WHERE a.engagement_id = ?")
    if outstanding_only:
        sql += " AND a.state != 'removed'"
    return conn.execute(sql + " ORDER BY a.id DESC", (engagement_id,)).fetchall()


def outstanding_artifacts(
    conn: sqlite3.Connection, engagement_id: int,
) -> list[sqlite3.Row]:
    """Artefacts not yet confirmed removed — these block a clean close."""
    return list_artifacts(conn, engagement_id, outstanding_only=True)


# -- I20 bounty submission memory --------------------------------------------
def add_submission(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    program: str | None = None,
    finding_id: int | None = None,
    endpoint: str | None = None,
    param: str | None = None,
    cls: str | None = None,
    status: str | None = None,
    note: str | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO submission (engagement_id, program, finding_id, endpoint, "
        "param, cls, status, note, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, program, finding_id, endpoint, param, cls, status, note,
         _now_utc()),
    )
    return int(cur.lastrowid)


def list_submissions(
    conn: sqlite3.Connection, engagement_id: int, *, limit: int | None = None,
) -> list[sqlite3.Row]:
    sql = ("SELECT id, program, finding_id, endpoint, param, cls, status, note, "
           "submitted_at FROM submission WHERE engagement_id = ? ORDER BY id DESC")
    params: list = [engagement_id]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


PAYLOAD_VERDICTS = ("success", "refused", "blocked", "unclear")


def engagement_canary(conn: sqlite3.Connection, engagement_id: int) -> str:
    """A stable, NEUTRAL per-engagement canary token (no tool-fingerprinting
    prefix). Generated once and stored, so an indirect-injection echo is
    attributable to this engagement."""
    import secrets as _secrets

    row = conn.execute(
        "SELECT value FROM domain_fact WHERE engagement_id = ? AND key = 'canary'",
        (engagement_id,)).fetchone()
    if row and row["value"]:
        return row["value"]
    token = "c" + _secrets.token_hex(4)
    add_domain_fact(conn, engagement_id, "canary", token, source="payload")
    return token


def add_payload(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    payload: str,
    response: str | None = None,
    surface: str | None = None,
    host_id: int | None = None,
    canary: str | None = None,
    auto_verdict: str | None = None,
    verdict: str = "unclear",
    note: str | None = None,
) -> int:
    """Append an injection-test row. The heuristic `auto_verdict` is advisory;
    `verdict` (operator) is the fact of record and defaults to 'unclear'."""
    if verdict not in PAYLOAD_VERDICTS:
        raise ValueError(f"unknown verdict '{verdict}' — use one of {', '.join(PAYLOAD_VERDICTS)}")
    resp = response if response is None or len(response) <= 2000 else response[:2000] + "…"
    cur = conn.execute(
        "INSERT INTO payload (engagement_id, host_id, surface, payload, response, canary, "
        "auto_verdict, verdict, note, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, surface, payload, resp, canary, auto_verdict, verdict,
         note, _now_utc()),
    )
    return int(cur.lastrowid)


def set_payload_verdict(conn: sqlite3.Connection, payload_id: int, verdict: str,
                        *, note: str | None = None) -> None:
    """The operator's override — the recorded fact of record for the test."""
    if verdict not in PAYLOAD_VERDICTS:
        raise ValueError(f"unknown verdict '{verdict}' — use one of {', '.join(PAYLOAD_VERDICTS)}")
    conn.execute("UPDATE payload SET verdict = ?, note = COALESCE(?, note) WHERE id = ?",
                 (verdict, note, payload_id))


def list_payloads(conn: sqlite3.Connection, engagement_id: int, *,
                  limit: int | None = None) -> list[sqlite3.Row]:
    sql = ("SELECT id, surface, payload, response, canary, auto_verdict, verdict, note, at "
           "FROM payload WHERE engagement_id = ? ORDER BY id DESC")
    params: list = [engagement_id]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


def submission_duplicate_risk(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    endpoint: str | None = None,
    param: str | None = None,
    cls: str | None = None,
    program: str | None = None,
) -> list[str]:
    """Advisory duplicate-risk lines at two granularities (same endpoint+param;
    same class program-wide). Advisory ONLY — never changes a finding's status."""
    out: list[str] = []
    if endpoint and param:
        n = conn.execute(
            "SELECT COUNT(*) FROM submission WHERE engagement_id = ? AND endpoint = ? "
            "AND param = ?", (engagement_id, endpoint, param),
        ).fetchone()[0]
        if n:
            out.append(f"likely duplicate: {n} prior submission(s) for {endpoint} param '{param}'")
    if cls:
        clauses = ["engagement_id = ?", "cls = ?"]
        params: list = [engagement_id, cls]
        if program:
            clauses.append("program = ?")
            params.append(program)
        n = conn.execute(
            f"SELECT COUNT(*) FROM submission WHERE {' AND '.join(clauses)}", params,
        ).fetchone()[0]
        if n:
            scope = f"program '{program}'" if program else "this program set"
            out.append(f"program noise: {n} prior '{cls}' submission(s) in {scope}")
    return out


def all_services_for_scanned_hosts(
    conn: sqlite3.Connection,
    engagement_id: int,
) -> list[dict]:
    """Every service on scanned/enumerated hosts. Used for traditional detection
    (which, unlike the AI probes, is not restricted to a fixed port list)."""
    rows = conn.execute(
        "SELECT h.id AS host_id, h.ip AS ip, s.id AS service_id, s.port AS port, "
        "s.proto AS proto, s.product AS product "
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
    plugin_id: str | None = None,
    port: int | None = None,
    solution: str | None = None,
    plugin_output: str | None = None,
) -> tuple[int, bool]:
    """Record a vulnerability. A scanner row (plugin_id given) dedupes on
    host+plugin_id+port; a version->CVE hypothesis dedupes on host+cve+software."""
    now = _now_utc()
    if plugin_id is not None:
        existing = conn.execute(
            "SELECT id FROM vulnerability WHERE host_id = ? AND plugin_id = ? AND port IS ?",
            (host_id, plugin_id, port),
        ).fetchone()
    else:
        existing = conn.execute(
            "SELECT id FROM vulnerability WHERE host_id = ? AND cve IS ? AND software_id IS ?",
            (host_id, cve, software_id),
        ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE vulnerability SET state = ?, cvss = COALESCE(?, cvss), "
            "title = COALESCE(?, title), exploit_ref = COALESCE(?, exploit_ref), "
            "exploit_available = ?, source = COALESCE(?, source), "
            "cve = COALESCE(?, cve), solution = COALESCE(?, solution), "
            "plugin_output = COALESCE(?, plugin_output), updated_at = ? WHERE id = ?",
            (state, cvss, title, exploit_ref, 1 if exploit_available else 0, source,
             cve, solution, plugin_output, now, existing["id"]),
        )
        return int(existing["id"]), False
    cur = conn.execute(
        "INSERT INTO vulnerability (engagement_id, host_id, software_id, service_id, cve, "
        "title, cvss, state, exploit_ref, exploit_available, source, plugin_id, port, "
        "solution, plugin_output, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, host_id, software_id, service_id, cve, title, cvss, state,
         exploit_ref, 1 if exploit_available else 0, source, plugin_id, port,
         solution, plugin_output, now),
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


def set_principal_owned(
    conn: sqlite3.Connection, engagement_id: int, name: str, *, domain: str | None = None,
) -> int:
    """Mark a principal operator-owned (yhwach_own) — access won out-of-band that
    yhwach cannot observe. Creates the principal if it is not yet known."""
    pid, _ = add_principal(conn, engagement_id, name, domain=domain, source="operator")
    conn.execute("UPDATE principal SET owned = 1, updated_at = ? WHERE id = ?",
                 (_now_utc(), pid))
    return pid


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


def set_host_meta(
    conn: sqlite3.Connection,
    engagement_id: int,
    ip: str,
    *,
    hostname: str | None = None,
    os: str | None = None,
    role: str | None = None,
) -> bool:
    """Set a host's hostname / os / role (COALESCE — only overwrites when a value
    is given). Returns True if the host exists. Lets the operator name a box
    (DC01, Jenkins CI, ...) when scans don't carry a PTR/role."""
    row = conn.execute(
        "SELECT id FROM host WHERE engagement_id = ? AND ip = ?", (engagement_id, ip)
    ).fetchone()
    if row is None:
        return False
    conn.execute(
        "UPDATE host SET hostname = COALESCE(?, hostname), os = COALESCE(?, os), "
        "role = COALESCE(?, role), last_updated = ? WHERE id = ?",
        (hostname, os, role, _now_utc(), row["id"]),
    )
    return True


def add_host_tag(
    conn: sqlite3.Connection, engagement_id: int, ip: str, tag: str,
    *, note: str | None = None,
) -> tuple[bool, str | None]:
    """Attach a free-form tag to a host (deduped per host+tag). Returns
    (ok, message). Tags are lowercased/trimmed for consistency."""
    tag = tag.strip().lower()
    if not tag:
        return False, "empty tag"
    row = conn.execute(
        "SELECT id FROM host WHERE engagement_id = ? AND ip = ?", (engagement_id, ip)
    ).fetchone()
    if row is None:
        return False, f"host {ip} not found"
    conn.execute(
        "INSERT INTO host_tag (host_id, tag, note, added_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(host_id, tag) DO UPDATE SET note = COALESCE(excluded.note, host_tag.note)",
        (row["id"], tag, note, _now_utc()),
    )
    return True, None


def remove_host_tag(conn: sqlite3.Connection, engagement_id: int, ip: str, tag: str) -> bool:
    """Remove a tag from a host. Returns True if a row was deleted."""
    row = conn.execute(
        "SELECT id FROM host WHERE engagement_id = ? AND ip = ?", (engagement_id, ip)
    ).fetchone()
    if row is None:
        return False
    cur = conn.execute("DELETE FROM host_tag WHERE host_id = ? AND tag = ?",
                       (row["id"], tag.strip().lower()))
    return cur.rowcount > 0


def tags_for_hosts(conn: sqlite3.Connection, engagement_id: int) -> dict[int, list[str]]:
    """{host_id: [tags]} for every tagged host in the engagement."""
    rows = conn.execute(
        "SELECT ht.host_id, ht.tag FROM host_tag ht JOIN host h ON h.id = ht.host_id "
        "WHERE h.engagement_id = ? ORDER BY ht.tag", (engagement_id,)
    ).fetchall()
    out: dict[int, list[str]] = {}
    for r in rows:
        out.setdefault(int(r["host_id"]), []).append(r["tag"])
    return out


def stage_history(conn: sqlite3.Connection, host_id: int) -> list[sqlite3.Row]:
    """The ordered stage-transition trail for one host."""
    return conn.execute(
        "SELECT from_stage, to_stage, COALESCE(note,'') note, ts FROM stage_transition "
        "WHERE host_id = ? ORDER BY id",
        (host_id,),
    ).fetchall()


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


def add_domain_fact(
    conn: sqlite3.Connection,
    engagement_id: int,
    key: str,
    value: str | None,
    *,
    domain: str | None = None,
    source: str | None = None,
) -> int:
    """Upsert a domain-wide AD fact (deduped by engagement+domain+key). The last
    observation wins — MAQ/LDAP-signing/LAPS state can change mid-engagement."""
    cur = conn.execute(
        "INSERT INTO domain_fact (engagement_id, domain, key, value, source, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(engagement_id, domain, key) DO UPDATE SET "
        "value = excluded.value, source = COALESCE(excluded.source, domain_fact.source)",
        (engagement_id, domain, key, value, source, _now_utc()),
    )
    return int(cur.lastrowid)


def list_domain_facts(
    conn: sqlite3.Connection, engagement_id: int, *, domain: str | None = None,
) -> list[sqlite3.Row]:
    q = "SELECT id, domain, key, value, source FROM domain_fact WHERE engagement_id = ?"
    params: list = [engagement_id]
    if domain is not None:
        q += " AND domain = ?"
        params.append(domain)
    return conn.execute(q + " ORDER BY domain, key", params).fetchall()


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


def capture_objective(
    conn: sqlite3.Connection,
    engagement_id: int,
    label: str,
    *,
    host_ip: str | None = None,
) -> tuple[int, str | None]:
    """Mark matching uncaptured objective(s) captured (by label, case-insensitive;
    optionally scoped to a host IP). Returns (n_captured, message). The score is
    derived from `captured` rows, so this is the only write a capture needs."""
    params: list = [engagement_id, label]
    host_clause = ""
    if host_ip is not None:
        host_clause = (" AND host_id = (SELECT id FROM host WHERE engagement_id=? AND ip=?)")
        params += [engagement_id, host_ip]
    rows = conn.execute(
        "SELECT id FROM objective WHERE engagement_id=? AND LOWER(label)=LOWER(?) "
        f"AND COALESCE(captured,0)=0{host_clause}",
        params,
    ).fetchall()
    if not rows:
        where = f" on {host_ip}" if host_ip else ""
        return 0, f"no uncaptured objective matching '{label}'{where}"
    ids = [r["id"] for r in rows]
    ph = ",".join("?" * len(ids))
    conn.execute(f"UPDATE objective SET captured=1 WHERE id IN ({ph})", ids)
    return len(ids), None


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
