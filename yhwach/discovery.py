"""Host discovery + world-model materialisation.

Fixes the "10 IPs learned, 2 in the UI" bug. Any code path that learns about an
IP — engagement scope, cert SAN, /etc/hosts, an evidence blob from a finding, a
`source_host` on a credential — funnels through `observe_ip()` so the host is
upserted as an `undiscovered` row *the moment it is known*, not "eventually,
after somebody remembers to nmap it".

The three public helpers are intentionally minimal:

  * ``upsert_host(conn, eid, ip, hostname=?, source=?)`` — idempotent single-row
    upsert. Existing hosts are updated (hostname coalesced, ``discovery_source``
    kept, ``last_updated`` bumped). New hosts land at ``stage='undiscovered'``
    with ``scan_needed=1`` so :mod:`yhwach.scanner` (PR-2) picks them up.
  * ``upsert_hosts_from_scope(conn, eid, scope)`` — expands every CIDR in the
    engagement scope, up to a hard cap. Refuses networks larger than ``/20``
    (4 094 hosts) unless the caller explicitly opts in via ``force=True``.
  * ``observe_ip(conn, eid, ip, source, hostname=?)`` — the "safe to spam"
    entry point every hook uses. No return value, silently no-ops on
    invalid/out-of-scope IPs so callers can hand it evidence strings without
    pre-parsing.

Host rows created here are marked ``discovery_source`` (added in db.py's
``_ADDED_COLUMNS``) so we can trace *why* a host appeared: scope expansion,
nmap output, an operator finding, a cert SAN. ``scan_needed=1`` on every new
row is the signal PR-2's scanner reads.

Everything is transactional — callers already hold ``yhdb.transaction(...)``
and pass its conn. No commit here; the outer ``with`` block owns commit/rollback.
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import UTC, datetime

# Hosts an engagement may materialise from a single CIDR without --force.
# /20 = 4 094 addressable hosts. Bigger scopes want a rate-limited scan, not a
# quiet 65k-row insert on ``engage``.
_SCOPE_EXPAND_CAP = 4_094

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _valid_ipv4(s: str) -> bool:
    try:
        addr = ipaddress.ip_address(s.strip())
    except (ValueError, AttributeError):
        return False
    if addr.version != 4:
        return False
    # Skip broadcast/loopback/multicast/link-local — never useful as host rows.
    return not (addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _ip_in_scope(ip: str, scope: str | None) -> bool:
    """True if ``ip`` falls in any CIDR/IP token of the engagement scope.

    Empty scope means "no scope enforcement" and returns True so tests that
    don't set a scope still get host materialisation.
    """
    if not scope:
        return True
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    for tok in scope.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False


def _engagement_scope(conn: sqlite3.Connection, engagement_id: int) -> str | None:
    row = conn.execute("SELECT scope FROM engagement WHERE id = ?", (engagement_id,)).fetchone()
    if row is None:
        return None
    return row["scope"] if isinstance(row, sqlite3.Row) else row[0]


def upsert_host(
    conn: sqlite3.Connection,
    engagement_id: int,
    ip: str,
    *,
    hostname: str | None = None,
    source: str = "operator",
) -> tuple[int, bool]:
    """Insert or update a host row keyed by ``(engagement_id, ip)``.

    Returns ``(host_id, created)`` where ``created`` is True when the row is
    new. The row lands with ``stage='undiscovered'`` on first insert;
    subsequent calls only coalesce fields (never regress the stage).

    On an existing row: ``hostname`` is filled in when missing, and
    ``last_updated`` is bumped. ``discovery_source`` is preserved (first source
    wins — the "who first named this host?" audit trail).
    """
    ip = (ip or "").strip()
    if not _valid_ipv4(ip):
        raise ValueError(f"invalid ipv4: {ip!r}")
    now = _now()
    row = conn.execute(
        "SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
        (engagement_id, ip),
    ).fetchone()
    if row is not None:
        host_id = int(row["id"])
        conn.execute(
            "UPDATE host SET hostname = COALESCE(hostname, ?), last_updated = ? "
            "WHERE id = ?",
            (hostname, now, host_id),
        )
        return host_id, False
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, hostname, stage, discovery_source, "
        "scan_needed, first_seen, last_updated) "
        "VALUES (?, ?, ?, 'undiscovered', ?, 1, ?, ?)",
        (engagement_id, ip, hostname, source, now, now),
    )
    return int(cur.lastrowid), True


def upsert_hosts_from_scope(
    conn: sqlite3.Connection,
    engagement_id: int,
    scope: str,
    *,
    source: str = "scope",
    force: bool = False,
) -> tuple[int, list[str]]:
    """Materialise every host in ``scope`` as an ``undiscovered`` row.

    Returns ``(created_count, skipped_reasons)``. A CIDR larger than the
    ``_SCOPE_EXPAND_CAP`` (default /20, 4 094 hosts) is skipped with a reason
    string unless ``force=True``. Single IPs and small CIDRs are always
    expanded — this is the fix for the UI showing 2 hosts when the operator
    wrote a /24 into ``yhwach engage``.
    """
    created = 0
    skipped: list[str] = []
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            skipped.append(f"invalid: {tok}")
            continue
        # A /32 has one addressable host, so ``num_addresses`` == 1 there.
        n_hosts = net.num_addresses if net.prefixlen == 32 else max(net.num_addresses - 2, 0)
        if n_hosts == 0:
            # e.g. /31 in RFC-3021 mode — treat both addresses as usable.
            n_hosts = net.num_addresses
        if n_hosts > _SCOPE_EXPAND_CAP and not force:
            skipped.append(f"too-large: {tok} ({n_hosts} hosts > cap {_SCOPE_EXPAND_CAP})")
            continue
        hosts_iter = [net.network_address] if net.prefixlen == 32 else net.hosts()
        for addr in hosts_iter:
            ip = str(addr)
            if not _valid_ipv4(ip):
                continue
            _, was_new = upsert_host(
                conn, engagement_id, ip, source=source,
            )
            if was_new:
                created += 1
    return created, skipped


def observe_ip(
    conn: sqlite3.Connection,
    engagement_id: int,
    ip: str,
    *,
    source: str,
    hostname: str | None = None,
) -> int | None:
    """Best-effort host materialisation from any evidence blob.

    Every internal hook (finding, cred, ingest, cert SAN, /etc/hosts parser)
    calls this. It silently no-ops on invalid IPs or IPs outside the
    engagement scope so callers don't need to pre-validate. Returns the
    host_id on success, ``None`` when skipped.

    ``source`` is a short tag ('finding', 'cred', 'cert_san', 'hosts_file',
    ...) so ``discovery_source`` records how the host first became known.
    """
    if not ip:
        return None
    ip = ip.strip()
    if not _valid_ipv4(ip):
        return None
    scope = _engagement_scope(conn, engagement_id)
    if not _ip_in_scope(ip, scope):
        return None
    try:
        host_id, _ = upsert_host(
            conn, engagement_id, ip, hostname=hostname, source=source,
        )
    except ValueError:
        return None
    return host_id


def observe_ips_in_text(
    conn: sqlite3.Connection,
    engagement_id: int,
    text: str,
    *,
    source: str,
) -> list[int]:
    """Scan ``text`` for IPv4 literals and materialise each in-scope one.

    Used by the finding/loot hooks: an operator pastes evidence like
    "leaked config points to 198.51.100.55" and the host row appears without
    them having to fill a separate ``host=`` field.
    """
    if not text:
        return []
    seen: set[str] = set()
    added: list[int] = []
    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if ip in seen:
            continue
        seen.add(ip)
        hid = observe_ip(conn, engagement_id, ip, source=source)
        if hid is not None:
            added.append(hid)
    return added
