"""Tests for yhwach.sprayer — the auto-spray fix.

Regression: adding ``sa/Acme-SQL-SA!2026`` to the vault used to store the
cred and stop. It never tried the credential against 10.0.0.30:1433 —
the operator had to remember to run ``yhwach_spray`` or ``nxc mssql ...``
manually. Now :mod:`yhwach.sprayer` fires on every add_cred (single cred vs
matching services) and on every nmap ingest that adds services (whole vault
vs the new services), and the results (success + fail) land in
``credential_access`` so we never reattempt the same pair.

The adapter subprocess calls are patched out — these tests exercise the
candidate selection, matcher matrix, DB write path, backoff, and the auto
hooks. Live adapter behaviour is a separate integration concern.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from yhwach import db as yhdb
from yhwach import sprayer as yhspray
from yhwach.mcp_tools import (
    tool_add_cred,
    tool_engage,
    tool_spray,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _seed_engagement(db: Path) -> int:
    """Fresh engagement with two hosts and a mix of services."""
    tool_engage(db, "spray", "10.0.0.0/24")
    with yhdb.transaction(db) as conn:
        eid = yhdb.engagement_id_for(conn, "spray")
        # Materialise hosts as 'scanned' so services can attach.
        for ip in ("10.0.0.10", "10.0.0.30"):
            conn.execute(
                "UPDATE host SET stage='scanned' WHERE engagement_id=? AND ip=?",
                (eid, ip),
            )
        # A mix that exercises the matcher:
        #   10.0.0.10  → 22 ssh, 445 smb, 5985 winrm
        #   10.0.0.30  → 1433 mssql, 3389 rdp
        rows = conn.execute(
            "SELECT id, ip FROM host WHERE engagement_id=?", (eid,),
        ).fetchall()
        by_ip = {r["ip"]: r["id"] for r in rows}
        specs = [
            (by_ip["10.0.0.10"], 22,   "tcp", "OpenSSH"),
            (by_ip["10.0.0.10"], 445,  "tcp", "Samba"),
            (by_ip["10.0.0.10"], 5985, "tcp", "Microsoft HTTPAPI"),
            (by_ip["10.0.0.30"], 1433, "tcp", "Microsoft SQL Server"),
            (by_ip["10.0.0.30"], 3389, "tcp", "ms-wbt-server"),
        ]
        for host_id, port, proto, product in specs:
            conn.execute(
                "INSERT INTO service (host_id, port, proto, product, discovered_at) "
                "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00Z')",
                (host_id, port, proto, product),
            )
    return eid


def _add_cred(db: Path, user: str, secret: str, kind: str = "password") -> int:
    """Insert a cred WITHOUT auto-spray firing (patched off), return cred id."""
    with patch.object(yhspray, "spray_cred") as mock:
        mock.return_value = yhspray.SprayBatch()
        tool_add_cred(db, "spray", user=user, secret=secret, kind=kind, source="test")
    with yhdb.transaction(db) as conn:
        eid = yhdb.engagement_id_for(conn, "spray")
        row = conn.execute(
            "SELECT id FROM credential WHERE engagement_id=? AND identifier=?",
            (eid, user),
        ).fetchone()
    return int(row["id"])


# ---------------------------------------------------------------------------
# Protocol matcher + candidate selection
# ---------------------------------------------------------------------------


def test_protocol_for_ports() -> None:
    assert yhspray._protocol_for(22, None) == "ssh"
    assert yhspray._protocol_for(445, None) == "smb"
    assert yhspray._protocol_for(5985, "Microsoft HTTPAPI") == "winrm"
    assert yhspray._protocol_for(1433, None) == "mssql"
    assert yhspray._protocol_for(3389, "ms-wbt-server") == "rdp"
    assert yhspray._protocol_for(636, None) == "ldaps"
    # Non-default port with a matching product → still classified.
    assert yhspray._protocol_for(2222, "OpenSSH") == "ssh"
    # Unknown → None (never sprayed).
    assert yhspray._protocol_for(11434, "Ollama") is None


def test_kind_matcher_matrix() -> None:
    """password reaches every credentialed protocol; ntlm is PtH-only;
    ssh_key/api_key are narrow; kerberos/dpapi never spray."""
    assert "mssql" in yhspray.PROTOCOL_MATCHERS["password"]
    assert "ssh" in yhspray.PROTOCOL_MATCHERS["password"]
    assert yhspray.PROTOCOL_MATCHERS["ntlm"] == {"smb", "winrm", "ldap", "ldaps", "mssql"}
    assert yhspray.PROTOCOL_MATCHERS["ssh_key"] == {"ssh"}
    assert yhspray.PROTOCOL_MATCHERS["kerberos"] == set()
    assert yhspray.PROTOCOL_MATCHERS["dpapi"] == set()


def test_candidate_selection_filters_by_matcher(tmp_db: Path) -> None:
    _seed_engagement(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "spray")
        # A password can go against ALL 5 services.
        services = yhspray._candidate_services(conn, eid)
    assert len(services) == 5
    # A protocol filter narrows correctly.
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "spray")
        mssql_only = yhspray._candidate_services(conn, eid, protocol="mssql")
    assert len(mssql_only) == 1
    assert mssql_only[0]["port"] == 1433


# ---------------------------------------------------------------------------
# Result caching / idempotency
# ---------------------------------------------------------------------------


def test_second_spray_reuses_cached_result(tmp_db: Path) -> None:
    """Once a (cred, service) is tried, the second spray SHORT-CIRCUITS
    without invoking the adapter again."""
    _seed_engagement(tmp_db)
    cred_id = _add_cred(tmp_db, "sa", "SQL!Pass")

    call_count = {"n": 0}

    def fake_adapter(ip, user, secret, kind, port):
        call_count["n"] += 1
        return "fail", "logon_failure"

    with patch.dict(yhspray._ADAPTERS, {"mssql": fake_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "spray")
            first = yhspray.spray_cred(
                conn, eid, cred_id, protocol="mssql",
            )
        # Second run: adapter must not be called again.
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "spray")
            second = yhspray.spray_cred(
                conn, eid, cred_id, protocol="mssql",
            )
    assert call_count["n"] == 1  # only the first spray hit the adapter
    assert len(first.attempts) == 1
    assert len(second.attempts) == 1
    assert "cached" in second.attempts[0].detail


def test_force_reattempts_cached_pair(tmp_db: Path) -> None:
    _seed_engagement(tmp_db)
    cred_id = _add_cred(tmp_db, "sa", "SQL!Pass")

    call_count = {"n": 0}

    def fake_adapter(ip, user, secret, kind, port):
        call_count["n"] += 1
        return "fail", "logon_failure"

    with patch.dict(yhspray._ADAPTERS, {"mssql": fake_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "spray")
            yhspray.spray_cred(conn, eid, cred_id, protocol="mssql")
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "spray")
            yhspray.spray_cred(
                conn, eid, cred_id, protocol="mssql", force=True,
            )
    assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# Success path — writes credential_access + marks the cred validated
# ---------------------------------------------------------------------------


def test_success_marks_cred_validated_and_records_access(tmp_db: Path) -> None:
    """The path the user cares about: sa:Acme... lands, sprayer hits
    dbhost01:1433, the vault flips from untried to 'opens 10.0.0.30:1433/mssql'."""
    _seed_engagement(tmp_db)
    cred_id = _add_cred(tmp_db, "sa", "SQL!Pass")

    def hit_adapter(ip, user, secret, kind, port):
        return "admin", "nxc: Pwn3d!"

    with patch.dict(yhspray._ADAPTERS, {"mssql": hit_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "spray")
            batch = yhspray.spray_cred(conn, eid, cred_id, protocol="mssql")

    assert len(batch.admins) == 1
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "spray")
        cred = conn.execute(
            "SELECT validated_on_host_id FROM credential WHERE id=?", (cred_id,),
        ).fetchone()
        access = conn.execute(
            "SELECT h.ip, ca.port, ca.proto, ca.result "
            "FROM credential_access ca JOIN host h ON h.id=ca.host_id "
            "WHERE ca.credential_id=?", (cred_id,),
        ).fetchall()
    assert cred["validated_on_host_id"] is not None
    assert len(access) == 1
    assert access[0]["ip"] == "10.0.0.30"
    assert access[0]["port"] == 1433
    assert access[0]["proto"] == "mssql"
    assert access[0]["result"] == "admin"


def test_fail_recorded_so_batch_is_idempotent(tmp_db: Path) -> None:
    _seed_engagement(tmp_db)
    cred_id = _add_cred(tmp_db, "svc_wiki", "wrong")

    with patch.dict(yhspray._ADAPTERS, {
        "mssql": lambda *a, **k: ("fail", "logon_failure"),
    }), yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "spray")
        yhspray.spray_cred(conn, eid, cred_id, protocol="mssql")
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM credential_access WHERE credential_id=? AND result='fail'",
            (cred_id,),
        ).fetchone()[0]
    assert n == 1


# ---------------------------------------------------------------------------
# Backoff
# ---------------------------------------------------------------------------


def test_backoff_stops_after_n_consecutive_fails(tmp_db: Path) -> None:
    """A dead port shouldn't burn 25 nxc calls — after N fails, remaining
    creds for that service are marked 'skipped' and never adapter-called."""
    _seed_engagement(tmp_db)
    # Add 10 creds → 10 attempts against 10.0.0.30:1433 if unbroken.
    for i in range(10):
        _add_cred(tmp_db, f"user{i}", f"pw{i}")

    call_count = {"n": 0}

    def fail_adapter(ip, user, secret, kind, port):
        call_count["n"] += 1
        return "fail", "logon_failure"

    with patch.dict(yhspray._ADAPTERS, {"mssql": fail_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "spray")
            batch = yhspray.spray_all(conn, eid, protocol="mssql")

    # Backoff kicks in at _SERVICE_FAIL_BACKOFF (4). So 4 real attempts
    # then skips. Skips don't count into 'attempts' below the backoff — but
    # they DO in batch.attempts (the transparency record).
    assert call_count["n"] == yhspray._SERVICE_FAIL_BACKOFF
    assert batch.skipped == 10 - yhspray._SERVICE_FAIL_BACKOFF


# ---------------------------------------------------------------------------
# Hook: tool_add_cred fires spray_cred automatically
# ---------------------------------------------------------------------------


def test_add_cred_autospray_hook_fires(tmp_db: Path) -> None:
    """The user-visible fix: adding a cred triggers a spray without a
    second tool call."""
    _seed_engagement(tmp_db)

    called_with: dict = {}

    def fake_spray_cred(conn, eid, cred_id, **kw):
        called_with["cred_id"] = cred_id
        return yhspray.SprayBatch()

    with patch.object(yhspray, "spray_cred", side_effect=fake_spray_cred):
        out = tool_add_cred(
            tmp_db, "spray", user="sa", secret="Acme-SQL-SA!2026",
            kind="password", source="playbook",
        )
    assert "credential 'sa'" in out
    assert "cred_id" in called_with


def test_add_cred_autospray_hits_are_named_in_output(tmp_db: Path) -> None:
    """When the auto-spray lands a hit, the identifier + host is echoed
    inline so the operator sees the win in the same reply."""
    _seed_engagement(tmp_db)

    def fake_spray_cred(conn, eid, cred_id, **kw):
        batch = yhspray.SprayBatch()
        r = yhspray.SprayResult(
            credential_id=cred_id, service_id=1, host_id=1,
            ip="10.0.0.30", port=1433, protocol="mssql",
            identifier="sa", result="admin", detail="nxc: Pwn3d!",
        )
        batch.attempts.append(r)
        batch.hits.append(r)
        batch.admins.append(r)
        return batch

    with patch.object(yhspray, "spray_cred", side_effect=fake_spray_cred):
        out = tool_add_cred(
            tmp_db, "spray", user="sa", secret="Acme-SQL-SA!2026",
        )
    assert "autospray" in out
    assert "admin" in out
    assert "10.0.0.30:1433/mssql" in out


def test_add_cred_survives_broken_adapter(tmp_db: Path) -> None:
    """If the sprayer throws (missing nxc, DB race, whatever) the cred STILL
    lands — we never lose intel because of a broken tool."""
    _seed_engagement(tmp_db)

    with patch.object(yhspray, "spray_cred", side_effect=RuntimeError("boom")):
        out = tool_add_cred(
            tmp_db, "spray", user="sa", secret="pw",
        )
    assert "credential 'sa'" in out
    # The error is surfaced but not raised.
    assert "autospray error" in out


# ---------------------------------------------------------------------------
# tool_spray facade
# ---------------------------------------------------------------------------


def test_tool_spray_dry_run(tmp_db: Path) -> None:
    _seed_engagement(tmp_db)
    _add_cred(tmp_db, "svc_wiki", "W1k1!")
    out = tool_spray(tmp_db, "spray", dry_run=True)
    assert "spray: " in out
    # No adapter calls happened → nothing in credential_access.
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM credential_access").fetchone()[0]
    assert n == 0


def test_tool_spray_filters_by_cred(tmp_db: Path) -> None:
    _seed_engagement(tmp_db)
    _add_cred(tmp_db, "svc_wiki", "W1k1!")
    _add_cred(tmp_db, "sa", "SQL!Pass")

    def hit_mssql(ip, user, secret, kind, port):
        assert user == "sa"  # only sa should reach the adapter
        return "admin", "nxc: Pwn3d!"

    with patch.dict(yhspray._ADAPTERS, {"mssql": hit_mssql}):
        # Empty out other adapters so the filter is watertight.
        for proto in ("ssh", "smb", "winrm", "ldap", "rdp", "ftp", "http-basic"):
            yhspray._ADAPTERS[proto] = lambda *a, **k: ("fail", "n/a")
        out = tool_spray(tmp_db, "spray", cred="sa")
    assert "sa" in out
    assert "10.0.0.30:1433/mssql" in out


def test_tool_spray_unknown_cred_errors(tmp_db: Path) -> None:
    _seed_engagement(tmp_db)
    out = tool_spray(tmp_db, "spray", cred="does_not_exist")
    assert "error" in out.lower()
    assert "not in vault" in out


# ---------------------------------------------------------------------------
# Lockout guard — never make the attempt that trips an account's lockout
# ---------------------------------------------------------------------------


def test_lockout_guard_blocks_near_threshold(tmp_db: Path) -> None:
    """With a domain lockout policy and the account already near the threshold,
    an un-cached domain-auth attempt is BLOCKED before the adapter ever fires."""
    eid = _seed_engagement(tmp_db)
    cid = _add_cred(tmp_db, "svc", "wrongpw")

    calls = {"n": 0}

    def fail_adapter(ip, user, secret, kind, port):
        calls["n"] += 1
        return "fail", "logon_failure"

    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_password_policy(conn, eid, domain="corp.local",
                                 lockout_threshold=3, lockout_window_min=30, source="test")
        h10 = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.10'",
                           (eid,)).fetchone()["id"]
        h30 = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.30'",
                           (eid,)).fetchone()["id"]
        # two recent bad attempts on this account, on OTHER services (so the
        # winrm pair below is un-cached and reaches the guard)
        yhdb.record_cred_access(conn, eid, cid, h10, port=445, proto="smb",
                                service_kind="smb", result="fail", source="prior")
        yhdb.record_cred_access(conn, eid, cid, h30, port=1433, proto="mssql",
                                service_kind="mssql", result="fail", source="prior")

    with patch.dict(yhspray._ADAPTERS, {"winrm": fail_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            batch = yhspray.spray_all(conn, eid, protocol="winrm")

    assert calls["n"] == 0                                   # never sent
    assert batch.blocked >= 1
    assert any(a.result == "blocked" for a in batch.attempts)


def test_no_lockout_policy_sprays_freely(tmp_db: Path) -> None:
    """No policy on record -> the guard is inert and the attempt proceeds."""
    eid = _seed_engagement(tmp_db)
    _add_cred(tmp_db, "svc", "pw")

    calls = {"n": 0}

    def fail_adapter(ip, user, secret, kind, port):
        calls["n"] += 1
        return "fail", "x"

    with patch.dict(yhspray._ADAPTERS, {"winrm": fail_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            batch = yhspray.spray_all(conn, eid, protocol="winrm")

    assert calls["n"] == 1
    assert batch.blocked == 0


def test_lockout_disabled_threshold_zero_sprays_freely(tmp_db: Path) -> None:
    """lockout_threshold = 0 means no lockout -> spraying is unconstrained."""
    eid = _seed_engagement(tmp_db)
    _add_cred(tmp_db, "svc", "pw")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_password_policy(conn, eid, domain="corp.local",
                                 lockout_threshold=0, lockout_window_min=30, source="test")

    calls = {"n": 0}

    def fail_adapter(ip, user, secret, kind, port):
        calls["n"] += 1
        return "fail", "x"

    with patch.dict(yhspray._ADAPTERS, {"winrm": fail_adapter}):
        with yhdb.transaction(tmp_db) as conn:
            batch = yhspray.spray_all(conn, eid, protocol="winrm")

    assert calls["n"] == 1 and batch.blocked == 0


def test_lockout_guard_caps_attempts_within_a_run(tmp_db: Path) -> None:
    """Across a single run, no more than (threshold - 1) bad attempts are sent
    against one account — the rest are blocked. Uses the DB fail cache written
    mid-run, so no separate in-run counter can drift."""
    eid = _seed_engagement(tmp_db)
    _add_cred(tmp_db, "svc", "pw")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_password_policy(conn, eid, domain="corp.local",
                                 lockout_threshold=2, lockout_window_min=30, source="test")

    calls: list[int] = []

    def fail_adapter(ip, user, secret, kind, port):
        calls.append(port)
        return "fail", "x"

    with patch.dict(yhspray._ADAPTERS, dict.fromkeys(yhspray._ADAPTERS, fail_adapter)):
        with yhdb.transaction(tmp_db) as conn:
            batch = yhspray.spray_all(conn, eid)

    domain_ports = {445, 5985, 1433, 3389}
    domain_calls = [p for p in calls if p in domain_ports]
    assert len(domain_calls) == 1          # threshold - 1 real bad attempts
    assert batch.blocked >= 1
