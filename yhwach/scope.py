"""Engagement scope — keep Yhwach pointed only at authorized targets.

Two layers:

* Legacy string helpers (`is_ip_or_cidr`, `validate_scope`, `scope_networks`,
  `in_scope`) operate on the comma-separated IP/CIDR string on
  `engagement.scope`. Kept for back-compat.

* The typed layer (`scope_entry` rows + `assert_target` / `build_matcher`) is
  the authority for the traffic gate. A token is a cidr, ip, hostname, or
  wildcard (`*.example.com`); entries are include or exclude, and exclude wins.
  An engagement with NO include coverage refuses traffic (memory writes still
  allowed). When an engagement has no `scope_entry` rows yet (older DB, or a row
  seeded straight through `upsert_engagement`), the matcher falls back to the
  `engagement.scope` string so nothing regresses.
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import UTC, datetime


def is_ip_or_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token.strip(), strict=False)
        return True
    except ValueError:
        return False


def validate_scope(scope: str) -> list[str]:
    """Return the malformed scope tokens (empty list = all valid)."""
    bad: list[str] = []
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if tok and not is_ip_or_cidr(tok):
            bad.append(tok)
    return bad


def scope_networks(scope: str) -> list:
    nets = []
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return nets


def in_scope(target: str, scope: str) -> bool:
    """True if `target` (an IP or CIDR) is contained in any scope network.

    An empty/unknown scope does not block (returns True). A non-IP target
    (hostname) returns False — the caller decides how to treat that."""
    nets = scope_networks(scope)
    if not nets:
        return True
    try:
        tnet = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return False
    return any(tnet.version == n.version and tnet.subnet_of(n) for n in nets)


# ---------------------------------------------------------------------------
# Typed scope layer — scope_entry rows + the traffic gate
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)


def classify_token(token: str) -> str | None:
    """Classify a scope token: cidr | ip | wildcard | hostname, or None if junk."""
    t = (token or "").strip()
    if not t:
        return None
    if t.startswith("*."):
        rest = t[2:]
        return "wildcard" if _HOSTNAME_RE.match(rest) else None
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
        except ValueError:
            return None
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    return "hostname" if _HOSTNAME_RE.match(t) else None


def validate_tokens(scope: str) -> list[str]:
    """Return malformed tokens in a scope string (accepts ip/cidr/host/wildcard)."""
    bad: list[str] = []
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if tok and classify_token(tok) is None:
            bad.append(tok)
    return bad


class _Matcher:
    """Pre-loaded include/exclude rules for one engagement. exclude wins."""

    def __init__(self, includes: list[tuple[str, str]], excludes: list[tuple[str, str]]):
        self.includes = includes
        self.excludes = excludes

    @staticmethod
    def _matches(kind: str, value: str, target: str, target_ip) -> bool:
        if kind in ("cidr", "ip"):
            if target_ip is None:
                return False
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return False
            return target_ip.version == net.version and target_ip in net
        tl = target.strip().lower()
        if kind == "hostname":
            return tl == value.lower()
        if kind == "wildcard":  # value stored as the suffix after '*.'
            # Subdomains only — `*.example.com` does NOT include the apex
            # example.com (list the apex explicitly if it is in scope).
            return tl.endswith("." + value.lower())
        if kind == "domain":
            dl = value.lower()
            return tl == dl or tl.endswith("." + dl)
        return False

    def allows(self, target: str) -> tuple[bool, str]:
        t = (target or "").strip()
        if not t:
            return False, "empty target"
        try:
            tip = ipaddress.ip_address(t)
        except ValueError:
            tip = None
        for kind, value in self.excludes:
            if self._matches(kind, value, t, tip):
                return False, f"excluded by scope rule {kind}:{value}"
        if not self.includes:
            return False, "no scope defined for this engagement — traffic refused"
        for kind, value in self.includes:
            if self._matches(kind, value, t, tip):
                return True, ""
        return False, "out of scope"


def build_matcher(conn: sqlite3.Connection, engagement_id: int) -> _Matcher:
    """Build the traffic matcher from scope_entry rows.

    The legacy engagement.scope string is used ONLY when the engagement has
    NEVER had a typed scope_entry row (a pre-Phase-1 DB that self-healed). Once
    any typed row exists — even if all live ones were later removed, or only an
    exclude was added — the typed layer is authoritative; otherwise removing the
    last include, or adding a lone exclude, would silently resurrect the stale
    include string.
    """
    rows = conn.execute(
        "SELECT kind, value, include FROM scope_entry "
        "WHERE engagement_id = ? AND removed_at IS NULL",
        (engagement_id,),
    ).fetchall()
    includes: list[tuple[str, str]] = []
    excludes: list[tuple[str, str]] = []
    for r in rows:
        (includes if r["include"] else excludes).append((r["kind"], _store_value(r["kind"], r["value"])))
    if not includes and not excludes:
        ever = conn.execute(
            "SELECT 1 FROM scope_entry WHERE engagement_id = ? LIMIT 1", (engagement_id,)
        ).fetchone()
        if ever is None:  # genuinely never typed — legacy string fallback
            srow = conn.execute(
                "SELECT scope FROM engagement WHERE id = ?", (engagement_id,)
            ).fetchone()
            for tok in ((srow["scope"] if srow else "") or "").split(","):
                tok = tok.strip()
                k = classify_token(tok)
                if k:
                    includes.append((k, _store_value(k, tok)))
    return _Matcher(includes, excludes)


def assert_target(conn: sqlite3.Connection, engagement_id: int, target: str) -> tuple[bool, str]:
    """(allowed, reason) for sending traffic to `target` on this engagement."""
    return build_matcher(conn, engagement_id).allows(target)


def _store_value(kind: str, token: str) -> str:
    """Normalise a token to the stored value (wildcard -> suffix after '*.')."""
    t = token.strip()
    if kind == "wildcard" and t.startswith("*."):
        return t[2:].lower()
    return t


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed_legacy_includes(conn: sqlite3.Connection, engagement_id: int) -> None:
    """If the engagement has no typed scope rows yet, convert its legacy
    engagement.scope string into include rows (idempotent; no-op otherwise)."""
    ever = conn.execute(
        "SELECT 1 FROM scope_entry WHERE engagement_id = ? LIMIT 1", (engagement_id,)
    ).fetchone()
    if ever is not None:
        return
    srow = conn.execute(
        "SELECT scope FROM engagement WHERE id = ?", (engagement_id,)
    ).fetchone()
    for tok in ((srow["scope"] if srow else "") or "").split(","):
        tok = tok.strip()
        k = classify_token(tok)
        if k:
            conn.execute(
                "INSERT OR IGNORE INTO scope_entry "
                "(engagement_id, kind, value, include, source, added_at) "
                "VALUES (?, ?, ?, 1, 'legacy', ?)",
                (engagement_id, k, _store_value(k, tok), _now()),
            )


def add_scope_entry(
    conn: sqlite3.Connection, engagement_id: int, token: str, *,
    include: bool = True, source: str = "operator", note: str | None = None,
) -> tuple[int, str]:
    """Add a scope entry. Returns (rows_affected, classified_kind). Raises on junk."""
    kind = classify_token(token)
    if kind is None:
        raise ValueError(f"unrecognised scope token: {token!r}")
    # On the FIRST typed entry for a legacy engagement (scope lived only in the
    # engagement.scope string), materialise that string as include rows first —
    # otherwise adding a lone exclude would leave zero includes and, with the
    # build_matcher 'ever typed' guard, refuse all traffic.
    _seed_legacy_includes(conn, engagement_id)
    value = _store_value(kind, token)
    conn.execute(
        "INSERT OR IGNORE INTO scope_entry "
        "(engagement_id, kind, value, include, note, source, added_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (engagement_id, kind, value, 1 if include else 0, note, source, _now()),
    )
    # Un-remove a previously soft-deleted identical row.
    conn.execute(
        "UPDATE scope_entry SET removed_at = NULL "
        "WHERE engagement_id=? AND kind=? AND value=? AND include=?",
        (engagement_id, kind, value, 1 if include else 0),
    )
    render_mirror(conn, engagement_id)
    return 1, kind


def remove_scope_entry(conn: sqlite3.Connection, engagement_id: int, token: str,
                       *, include: bool = True) -> int:
    kind = classify_token(token)
    if kind is None:
        return 0
    value = _store_value(kind, token)
    cur = conn.execute(
        "UPDATE scope_entry SET removed_at = ? "
        "WHERE engagement_id=? AND kind=? AND value=? AND include=? AND removed_at IS NULL",
        (_now(), engagement_id, kind, value, 1 if include else 0),
    )
    render_mirror(conn, engagement_id)
    return cur.rowcount


def list_scope_entries(conn: sqlite3.Connection, engagement_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT kind, value, include, note, source FROM scope_entry "
        "WHERE engagement_id=? AND removed_at IS NULL ORDER BY include DESC, kind, value",
        (engagement_id,),
    ).fetchall()


def sync_from_string(conn: sqlite3.Connection, engagement_id: int, scope: str,
                     *, source: str = "engage") -> None:
    """Populate scope_entry include rows from a comma-separated scope string.

    Additive: tokens already present are left as-is (INSERT OR IGNORE), so an
    engage that repeats the scope does not churn history. Does not remove rows
    that dropped out of the string — use `yhwach scope remove` for that, so a
    re-engage never silently un-scopes a target mid-engagement.
    """
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if classify_token(tok) is not None:
            add_scope_entry(conn, engagement_id, tok, include=True, source=source)
    render_mirror(conn, engagement_id)


def render_mirror(conn: sqlite3.Connection, engagement_id: int) -> None:
    """Rewrite engagement.scope as the comma string of include ip/cidr values,
    so the legacy readers (report, discovery materialisation) keep working."""
    rows = conn.execute(
        "SELECT value FROM scope_entry WHERE engagement_id=? AND include=1 "
        "AND removed_at IS NULL AND kind IN ('ip','cidr') ORDER BY value",
        (engagement_id,),
    ).fetchall()
    mirror = ",".join(r["value"] for r in rows)
    if mirror:  # don't blank an existing string when only host/wildcard rows exist
        conn.execute("UPDATE engagement SET scope = ? WHERE id = ?", (mirror, engagement_id))
