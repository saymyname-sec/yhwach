"""I32 — trivy / prowler ingestion.

trivy -> vulnerability rows on a host. prowler FAILs -> findings only for
attack-relevant checks (public exposure, IAM privesc, secret exposure, weak
auth); the CIS/PCI compliance matrix is dropped.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.cloudposture import parse_prowler, parse_trivy

_TRIVY = ('{"Results":[{"Target":"app:latest","Vulnerabilities":['
          '{"VulnerabilityID":"CVE-2023-1","PkgName":"openssl","InstalledVersion":"1.1",'
          '"FixedVersion":"1.2","Severity":"HIGH","Title":"openssl bug"}]}]}')
_PROWLER = (
    '[{"Status":"FAIL","CheckID":"s3_bucket_public_access","CheckTitle":"S3 bucket is public",'
    '"Severity":"high","ServiceName":"s3","ResourceId":"arn:aws:s3:::loot"},'
    '{"Status":"FAIL","CheckID":"cis_1_2","CheckTitle":"Ensure password policy uppercase",'
    '"ServiceName":"iam"},'
    '{"Status":"FAIL","CheckID":"iam_admin_wildcard","CheckTitle":"IAM policy allows *",'
    '"Severity":"high","ServiceName":"iam","ResourceId":"arn:aws:iam::1:policy/p"},'
    '{"Status":"PASS","CheckID":"x","CheckTitle":"public ok"}]'
)


# --- parsers ----------------------------------------------------------------


def test_parse_trivy() -> None:
    v = parse_trivy(_TRIVY)[0]
    assert v.cve == "CVE-2023-1"
    assert v.pkg == "openssl"
    assert v.fixed == "1.2"
    assert v.severity == "high"


def test_prowler_keeps_attack_relevant_drops_compliance() -> None:
    out = {f.check_id: f.tag for f in parse_prowler(_PROWLER)}
    assert out == {"s3_bucket_public_access": "cloud_public_exposure",
                   "iam_admin_wildcard": "cloud_iam_privesc"}
    # the CIS password-policy FAIL and the PASS row are both excluded
    assert "cis_1_2" not in out


def test_bad_json_empty() -> None:
    assert parse_trivy("nope") == []
    assert parse_prowler("{bad") == []


# --- ingest -----------------------------------------------------------------


def _eng_host(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/8", kind="cloud")
        conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                     "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,))
        return eid


def test_trivy_requires_host(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    with pytest.raises(ValueError, match="needs a host"):
        tool_interpret(tmp_db, "L", _TRIVY, kind="trivy")


def test_trivy_records_vulns_with_fix(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _TRIVY, kind="trivy", host="10.0.0.5")
    out = tool_query(tmp_db, "L", "vulns", fields=["cve", "source", "solution"])
    assert "CVE-2023-1" in out
    assert "trivy" in out
    assert "upgrade openssl to 1.2" in out


def test_prowler_records_only_attack_relevant(tmp_db: Path) -> None:
    eid = _eng_host(tmp_db)
    out = tool_interpret(tmp_db, "L", _PROWLER, kind="prowler")
    assert "2 attack-relevant FAIL" in out
    with yhdb.transaction(tmp_db) as conn:
        tags = sorted({r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag LIKE 'cloud_%'", (eid,))})
    assert tags == ["cloud_iam_privesc", "cloud_public_exposure"]


def test_trivy_reingest_idempotent(tmp_db: Path) -> None:
    eid = _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _TRIVY, kind="trivy", host="10.0.0.5")
    tool_interpret(tmp_db, "L", _TRIVY, kind="trivy", host="10.0.0.5")
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) n FROM vulnerability WHERE engagement_id=?",
                         (eid,)).fetchone()["n"]
    assert n == 1
