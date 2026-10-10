"""Tests for yhwach.patterns — credential pattern derivation.

Regression: ``sa : Acme-SQL-SA!2026`` sat in the operator's head for
hours because ``svc_wiki : W1k1!Svc#Acme2025`` was in the vault but nobody
generated the sibling accounts. This module turns known patterns into
concrete spray candidates for the sprayer (PR-3) to pick up.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import patterns as pat
from yhwach.mcp_tools import tool_derive, tool_engage


def _row(identifier: str, secret: str) -> dict:
    return {"identifier": identifier, "secret": secret}


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


def test_extract_suffix_tail() -> None:
    assert pat._extract_suffix_tail("W1k1!Svc#Acme2025") == "#Acme2025"
    assert pat._extract_suffix_tail("nothingspecial") is None
    assert pat._extract_suffix_tail("only#") is None
    # Only the LAST # counts — a mid-string # is not the tail.
    assert pat._extract_suffix_tail("mid#split!ThenTail2026") == "!ThenTail2026"


def test_extract_year() -> None:
    assert pat._extract_year("W1k1!Svc#Acme2025") == "2025"
    assert pat._extract_year("Acme-SQL-SA!2026") == "2026"
    assert pat._extract_year("no-year-here") is None


def test_extract_role_token_needs_username_match() -> None:
    # Password has 'Svc', username has 'svc_' — match.
    assert pat._extract_role_token("W1k1!Svc#Acme", "svc_wiki") == "Svc"
    # Password has 'Adm', but the user is svc_ — no role_token confidence.
    assert pat._extract_role_token("W1k1!Adm#Acme", "svc_wiki") is None


def test_leet_prefix() -> None:
    # First letter kept as ordinary capital (readable prefix), rest leets.
    assert pat._leet("svc_wiki").startswith("Sv")
    assert pat._leet("wiki") == "W1k1"
    assert pat._leet("sql") == "Sql"       # first cap; body has no leet chars
    assert pat._leet("admin") == "Adm1n"   # first letter kept cap, i->1
    assert pat._leet("") == ""


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------


def test_derive_role_swap() -> None:
    # svc_wiki:W1k1!Svc#Acme2025 → suggest svc_backup:?
    # We use svc_backup as the target (still 'Svc' role in name), so a
    # role-swap does nothing here — but a suffix reuse should still emit.
    cands = pat.derive_candidates(
        [_row("svc_wiki", "W1k1!Svc#Acme2025")],
        targets=["svc_backup"],
    )
    assert cands
    users = {c.username for c in cands}
    passwords = {c.password for c in cands}
    assert users == {"svc_backup"}
    # Suffix-reuse: B@ckup#Acme2025 (leet of 'backup' + tail).
    assert any("Acme2025" in p for p in passwords)


def test_derive_year_rotate() -> None:
    cands = pat.derive_candidates(
        [_row("svc_wiki", "W1k1!Svc#Acme2025")],
        targets=["svc_backup"],
    )
    passwords = {c.password for c in cands}
    # Year rotation: 2025 -> 2026 in the password.
    assert any("2026" in p for p in passwords)


def test_derive_skips_users_already_in_vault() -> None:
    """We don't burn cycles suggesting creds we already have."""
    vault = [
        _row("svc_wiki", "W1k1!Svc#Acme2025"),
        _row("sa",       "Acme-SQL-SA!2026"),
    ]
    cands = pat.derive_candidates(vault, targets=["sa", "svc_backup"])
    users = {c.username for c in cands}
    assert "sa" not in users
    assert "svc_backup" in users


def test_derive_dedupes_across_source_creds() -> None:
    """Two source creds producing the same candidate password only emit once."""
    vault = [
        _row("svc_wiki", "Pass#Common2025"),
        _row("svc_adm",  "Pass#Common2025"),   # same tail
    ]
    cands = pat.derive_candidates(vault, targets=["svc_backup"])
    pairs = {(c.username, c.password) for c in cands}
    # Any given (user, pass) pair appears once.
    assert len(pairs) == len(cands)


def test_derive_empty_vault_returns_empty() -> None:
    assert pat.derive_candidates([]) == []


def test_derive_skips_empty_secrets() -> None:
    """A cred with no secret (e.g. a hash marker) can't seed patterns."""
    cands = pat.derive_candidates(
        [_row("svc_wiki", "")],
        targets=["svc_backup"],
    )
    assert cands == []


# ---------------------------------------------------------------------------
# tool_derive facade
# ---------------------------------------------------------------------------


def test_tool_derive_dry_run_prints_candidates(tmp_db: Path) -> None:
    tool_engage(tmp_db, "d", "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "d")
        yhdb.add_credential(conn, eid, "svc_wiki", "W1k1!Svc#Acme2025",
                            "password", "test")
    out = tool_derive(tmp_db, "d")
    assert "candidate(s)" in out
    assert "svc_backup" in out or "svc_sql" in out
    # Vault size unchanged.
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM credential").fetchone()[0]
    assert n == 1


def test_tool_derive_spray_adds_vault_rows(tmp_db: Path) -> None:
    tool_engage(tmp_db, "d", "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "d")
        yhdb.add_credential(conn, eid, "svc_wiki", "W1k1!Svc#Acme2025",
                            "password", "test")
    out = tool_derive(tmp_db, "d", spray=True)
    assert "added to vault" in out
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM credential").fetchone()[0]
    assert n > 1


def test_tool_derive_empty_vault_is_friendly(tmp_db: Path) -> None:
    tool_engage(tmp_db, "d", "10.0.0.0/24")
    out = tool_derive(tmp_db, "d")
    assert "no candidates" in out


def test_tool_derive_custom_targets(tmp_db: Path) -> None:
    """The operator can name a specific username to generate FOR."""
    tool_engage(tmp_db, "d", "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "d")
        yhdb.add_credential(conn, eid, "svc_wiki", "W1k1!Svc#Acme2025",
                            "password", "test")
    out = tool_derive(tmp_db, "d", targets="svc_audit")
    assert "svc_audit" in out
    # Only for that target — no other svc_* usernames.
    assert "svc_backup" not in out
    assert "svc_sql" not in out
