"""Tests for yhwach.discovery — world-model auto-materialisation.

Regression: the "10 IPs learned, 2 in the UI" bug from a prior engagement,
where internal /24 hosts stayed invisible because no code path created
their `host` rows. Every hook now funnels through discovery.observe_ip /
upsert_host, so a scope with a /24 in engage() materialises the /24, and any
IP mentioned in a finding / cred / add_interface call becomes a host row.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import discovery as yhdisc
from yhwach.mcp_tools import (
    tool_add_cred,
    tool_add_finding,
    tool_add_interface,
    tool_add_loot,
    tool_engage,
    tool_set_host,
    tool_tag,
)

# ---------------------------------------------------------------------------
# Core module (no MCP layer)
# ---------------------------------------------------------------------------


def _engage(tmp_db: Path, scope: str, *, domain: str | None = None) -> int:
    """Bare engagement upsert without discovery hooks — for module-level tests."""
    with yhdb.transaction(tmp_db) as conn:
        return yhdb.upsert_engagement(conn, lab="d", scope=scope, domain=domain)


def test_upsert_host_creates_undiscovered_row(tmp_db: Path) -> None:
    eid = _engage(tmp_db, "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        host_id, created = yhdisc.upsert_host(
            conn, eid, "10.0.0.7", hostname="foo", source="finding",
        )
    assert created
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute(
            "SELECT hostname, stage, discovery_source, scan_needed FROM host WHERE id=?",
            (host_id,),
        ).fetchone()
    assert row["hostname"] == "foo"
    assert row["stage"] == "undiscovered"
    assert row["discovery_source"] == "finding"
    assert row["scan_needed"] == 1


def test_upsert_host_is_idempotent(tmp_db: Path) -> None:
    eid = _engage(tmp_db, "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        first_id, first_created = yhdisc.upsert_host(conn, eid, "10.0.0.9", source="scope")
        second_id, second_created = yhdisc.upsert_host(
            conn, eid, "10.0.0.9", hostname="later", source="finding",
        )
    assert first_id == second_id
    assert first_created is True
    assert second_created is False
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute(
            "SELECT hostname, discovery_source FROM host WHERE id=?", (second_id,),
        ).fetchone()
    # Hostname coalesced in, discovery_source pinned to the FIRST source
    # (the audit trail — "we heard about this host from scope expansion first").
    assert row["hostname"] == "later"
    assert row["discovery_source"] == "scope"


def test_upsert_host_rejects_invalid_ipv4(tmp_db: Path) -> None:
    import pytest

    eid = _engage(tmp_db, "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn, pytest.raises(ValueError):
        yhdisc.upsert_host(conn, eid, "not.an.ip", source="finding")


def test_valid_ipv4_rejects_link_local_and_loopback() -> None:
    # 169.254.0.0/16 (incl. cloud metadata 169.254.169.254) must never become a
    # host row that gets queued for a full-port scan.
    assert yhdisc._valid_ipv4("169.254.169.254") is False
    assert yhdisc._valid_ipv4("127.0.0.1") is False
    assert yhdisc._valid_ipv4("10.0.0.5") is True


def test_scope_expansion_materialises_small_cidr(tmp_db: Path) -> None:
    """A /29 (6 hosts) is materialised in full — no operator surprise."""
    eid = _engage(tmp_db, "10.10.10.0/29")
    with yhdb.transaction(tmp_db) as conn:
        created, skipped = yhdisc.upsert_hosts_from_scope(conn, eid, "10.10.10.0/29")
    assert created == 6
    assert skipped == []
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM host WHERE engagement_id=?", (eid,),
        ).fetchone()[0]
    assert n == 6


def test_scope_expansion_skips_oversized_cidr(tmp_db: Path) -> None:
    """/16 is above the /20 default cap and gets skipped WITHOUT crashing."""
    eid = _engage(tmp_db, "10.0.0.0/16")
    with yhdb.transaction(tmp_db) as conn:
        created, skipped = yhdisc.upsert_hosts_from_scope(conn, eid, "10.0.0.0/16")
    assert created == 0
    assert len(skipped) == 1
    assert "too-large" in skipped[0]


def test_scope_expansion_force_bypasses_cap(tmp_db: Path) -> None:
    """--force expands even oversized ranges (e.g. an intentional /16)."""
    # Use a /22 for speed (1 022 hosts) and confirm force wins over the cap
    # by lowering the cap in-process for a moment.
    from yhwach import discovery as d

    original_cap = d._SCOPE_EXPAND_CAP
    d._SCOPE_EXPAND_CAP = 10  # tiny cap so /28 (14) exceeds it
    try:
        eid = _engage(tmp_db, "10.11.0.0/28")
        with yhdb.transaction(tmp_db) as conn:
            created, skipped = yhdisc.upsert_hosts_from_scope(
                conn, eid, "10.11.0.0/28", force=True,
            )
        assert skipped == []
        assert created == 14
    finally:
        d._SCOPE_EXPAND_CAP = original_cap


def test_observe_ip_respects_engagement_scope(tmp_db: Path) -> None:
    """observe_ip silently ignores out-of-scope IPs (the safe-to-spam contract)."""
    eid = _engage(tmp_db, "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        in_id = yhdisc.observe_ip(conn, eid, "10.0.0.42", source="finding")
        out_id = yhdisc.observe_ip(conn, eid, "172.16.5.5", source="finding")
    assert in_id is not None
    assert out_id is None


def test_observe_ip_ignores_invalid_input(tmp_db: Path) -> None:
    eid = _engage(tmp_db, "10.0.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        assert yhdisc.observe_ip(conn, eid, "", source="finding") is None
        assert yhdisc.observe_ip(conn, eid, "999.999.999.999", source="finding") is None
        assert yhdisc.observe_ip(conn, eid, "not an ip", source="finding") is None


def test_observe_ips_in_text_extracts_multiple(tmp_db: Path) -> None:
    """A finding's evidence blob can name several IPs — all materialise."""
    eid = _engage(tmp_db, "10.0.0.0/24,172.16.0.0/16")
    text = (
        "leaked config points to 10.0.0.55 and mentions 172.16.37.60 "
        "and out-of-scope 8.8.8.8"
    )
    with yhdb.transaction(tmp_db) as conn:
        ids = yhdisc.observe_ips_in_text(conn, eid, text, source="finding_evidence")
    assert len(ids) == 2  # the two in-scope IPs, not 8.8.8.8
    with yhdb.transaction(tmp_db) as conn:
        ips = {r["ip"] for r in conn.execute(
            "SELECT ip FROM host WHERE engagement_id=?", (eid,))}
    assert "10.0.0.55" in ips
    assert "172.16.37.60" in ips
    assert "8.8.8.8" not in ips


# ---------------------------------------------------------------------------
# Regression: tool_engage now materialises scope hosts
# ---------------------------------------------------------------------------


def test_engage_materialises_scope_cidr(tmp_db: Path) -> None:
    """The 'engage on 172.16.37.0/24 shows 0 hosts' bug is dead."""
    tmp_db.unlink()  # tool_engage owns its init
    msg = tool_engage(tmp_db, "siege", "172.16.37.0/29")
    assert "engagement 'siege' ready" in msg
    assert "queued for scan" in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "siege")
        rows = conn.execute(
            "SELECT ip, stage, discovery_source, scan_needed FROM host "
            "WHERE engagement_id=? ORDER BY ip", (eid,),
        ).fetchall()
    assert len(rows) == 6
    assert all(r["stage"] == "undiscovered" for r in rows)
    assert all(r["discovery_source"] == "scope" for r in rows)
    assert all(r["scan_needed"] == 1 for r in rows)


def test_engage_reports_skipped_oversized_ranges(tmp_db: Path) -> None:
    """A mixed scope (small + huge) materialises the small one and notes the skip."""
    tmp_db.unlink()
    msg = tool_engage(tmp_db, "big", "10.10.10.0/30,10.0.0.0/16")
    assert "engagement 'big' ready" in msg
    assert "skipped" in msg
    assert "too-large" in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "big")
        n = conn.execute(
            "SELECT COUNT(*) FROM host WHERE engagement_id=?", (eid,),
        ).fetchone()[0]
    assert n == 2  # /30 has 2 hosts; /16 skipped


# ---------------------------------------------------------------------------
# Regression: add_finding no longer errors on an unmaterialised in-scope host
# ---------------------------------------------------------------------------


def test_add_finding_auto_materialises_internal_host(tmp_db: Path) -> None:
    """The original bug: `yhwach_add_finding host=172.16.37.30` returned
    "[yhwach error] host ... not in lab" and the finding was lost. Now the
    host row is created on demand and the finding lands attributed correctly."""
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.37.0/29")
    # A host that scope-expansion didn't cover (bigger CIDR): mimic an IP
    # observed in a wider scope by re-engaging with the /24.
    tool_engage(tmp_db, "s", "172.16.37.0/24,192.168.56.0/24")
    msg = tool_add_finding(
        tmp_db, "s", title="wiki01 RAG bypass",
        severity="high", cls="AI_PROMPT_INJECTION",
        evidence="private-doc leak observed on 172.16.37.55:8000",
        host="172.16.37.55",
    )
    assert "finding" in msg and "not in lab" not in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        host_row = conn.execute(
            "SELECT stage, discovery_source FROM host "
            "WHERE engagement_id=? AND ip=?",
            (eid, "172.16.37.55"),
        ).fetchone()
    # scope expansion may have already created the row; if it did the
    # discovery_source is 'scope' — either way the row exists and the finding
    # is attached to the RIGHT host, not to a pivot.
    assert host_row is not None
    assert host_row["discovery_source"] in ("scope", "finding")


def test_add_finding_out_of_scope_still_rejected(tmp_db: Path) -> None:
    """Guard against typo/scope-drift — an IP truly outside scope still errors."""
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "10.0.0.0/24")
    msg = tool_add_finding(
        tmp_db, "s", title="stray", severity="low", cls="INFO",
        evidence="something", host="8.8.8.8",
    )
    assert "out of scope" in msg


def test_add_finding_evidence_spawns_lead_hosts(tmp_db: Path) -> None:
    """IPs mentioned in evidence become host rows too — no second tool call needed."""
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.0.0/16")
    tool_add_finding(
        tmp_db, "s", title="doc leak", severity="medium", cls="INFO_DISCLOSURE",
        evidence="config points to backup at 172.16.37.80 and monitor at 172.16.37.90",
    )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        rows = [r["ip"] for r in conn.execute(
            "SELECT ip FROM host WHERE engagement_id=? AND discovery_source=?",
            (eid, "finding_evidence"))]
    assert "172.16.37.80" in rows
    assert "172.16.37.90" in rows


# ---------------------------------------------------------------------------
# Regression: add_cred / add_loot / set_host / tag / add_interface all
# auto-materialise instead of erroring on an unknown-but-in-scope host.
# ---------------------------------------------------------------------------


def test_add_cred_source_host_auto_materialises(tmp_db: Path) -> None:
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.37.0/24")
    msg = tool_add_cred(
        tmp_db, "s", user="svc_wiki", secret="W1k1!Svc",
        source="dump", source_host="172.16.37.55",
    )
    assert "credential" in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        row = conn.execute(
            "SELECT c.source_host_id, h.ip FROM credential c "
            "LEFT JOIN host h ON h.id = c.source_host_id "
            "WHERE c.engagement_id=? AND c.identifier=?",
            (eid, "svc_wiki"),
        ).fetchone()
    assert row is not None
    assert row["source_host_id"] is not None
    assert row["ip"] == "172.16.37.55"


def test_add_loot_auto_materialises(tmp_db: Path) -> None:
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.37.0/24")
    msg = tool_add_loot(
        tmp_db, "s", summary="kdbx", host="172.16.37.70",
        path="C:/Users/mtorres/kp.kdbx", type="db",
    )
    assert "loot" in msg and "out of scope" not in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        row = conn.execute(
            "SELECT id FROM host WHERE engagement_id=? AND ip=?",
            (eid, "172.16.37.70"),
        ).fetchone()
    assert row is not None


def test_set_host_auto_materialises(tmp_db: Path) -> None:
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.37.0/24")
    msg = tool_set_host(tmp_db, "s", host="172.16.37.60", hostname="DC01",
                        os="windows", role="dc")
    assert "updated" in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        row = conn.execute(
            "SELECT hostname, os, role FROM host "
            "WHERE engagement_id=? AND ip=?", (eid, "172.16.37.60"),
        ).fetchone()
    assert row["hostname"] == "DC01"
    assert row["os"] == "windows"
    assert row["role"] == "dc"


def test_tag_auto_materialises(tmp_db: Path) -> None:
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.37.0/24")
    msg = tool_tag(tmp_db, "s", host="172.16.37.30", tag="dbhost01")
    assert "tagged" in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        n = conn.execute(
            "SELECT COUNT(*) FROM host WHERE engagement_id=? AND ip=?",
            (eid, "172.16.37.30"),
        ).fetchone()[0]
    assert n == 1


def test_add_interface_materialises_both_ips(tmp_db: Path) -> None:
    """A dual-homed host: the PRIMARY and the SECOND interface both get rows,
    because the second IP is often the next scan target on its own subnet."""
    tmp_db.unlink()
    tool_engage(tmp_db, "s", "172.16.37.0/24,192.168.56.0/24")
    msg = tool_add_interface(
        tmp_db, "s", host="192.168.56.10", ip="172.16.37.5",
        segment="172.16.37.0/24", primary=False,
    )
    assert "out of scope" not in msg
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "s")
        ips = {r["ip"] for r in conn.execute(
            "SELECT ip FROM host WHERE engagement_id=?", (eid,))}
    assert "192.168.56.10" in ips
    assert "172.16.37.5" in ips
