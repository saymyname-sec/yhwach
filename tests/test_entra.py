"""I33 — Entra / hybrid-identity detection + the cloud_tenant_in_scope gate.

Hybrid-identity producers (AD Connect sync account, Seamless-SSO computer, ADFS)
are detected from the on-prem AD graph. The report rule always fires; the
exploit-class rules are gated behind cloud_tenant_in_scope.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import knowledge as kn
from yhwach.entra import derive_entra_findings
from yhwach.parsers.cloud import parse_aws_sts


def _eng(path: Path, kind: str = "internal"):
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24", kind=kind)
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.10', 'enumerated', 't')", (eid,)).lastrowid
        return eid, int(hid)


# --- detection --------------------------------------------------------------


def test_detects_hybrid_producers(tmp_db: Path) -> None:
    eid, hid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_principal(conn, eid, "MSOL_ab12", home_host_id=hid)
        yhdb.add_principal(conn, eid, "AZUREADSSOACC$", type="computer", home_host_id=hid)
        yhdb.add_principal(conn, eid, "svc_adfs", spn="host/adfs.corp", home_host_id=hid)
        yhdb.add_principal(conn, eid, "jdoe", home_host_id=hid)
        counts = derive_entra_findings(conn, eid)
        tags = sorted({r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,))})
    assert counts == {"adconnect": 1, "sso": 1, "adfs": 1}
    assert tags == ["adconnect_host", "hybrid_identity"]


def test_detection_is_idempotent(tmp_db: Path) -> None:
    eid, hid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_principal(conn, eid, "MSOL_ab12", home_host_id=hid)
        derive_entra_findings(conn, eid)
        derive_entra_findings(conn, eid)
        n = conn.execute("SELECT COUNT(*) n FROM finding WHERE engagement_id=?", (eid,)).fetchone()["n"]
    assert n == 2   # adconnect_host + hybrid_identity, not duplicated


# --- the cloud_tenant_in_scope gate -----------------------------------------


def _cands(path: Path, eid: int) -> set[str]:
    with yhdb.transaction(path) as conn:
        return {c.technique_id for c in kn.candidates_for(conn, eid)}


def test_report_rule_fires_exploit_gated_on_prem(tmp_db: Path) -> None:
    eid, hid = _eng(tmp_db, kind="internal")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_principal(conn, eid, "MSOL_ab12", home_host_id=hid)
        derive_entra_findings(conn, eid)
    cands = _cands(tmp_db, eid)
    assert "hybrid_identity_investigate" in cands        # report rule always
    assert "adconnect_credential_extraction" not in cands  # exploit gated


def test_tenant_fact_ungates_exploit(tmp_db: Path) -> None:
    eid, hid = _eng(tmp_db, kind="internal")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_principal(conn, eid, "MSOL_ab12", home_host_id=hid)
        derive_entra_findings(conn, eid)
        yhdb.add_domain_fact(conn, eid, "cloud_tenant_in_scope", "true")
    assert "adconnect_credential_extraction" in _cands(tmp_db, eid)


def test_cloud_engagement_kind_ungates_exploit(tmp_db: Path) -> None:
    eid, hid = _eng(tmp_db, kind="cloud")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_principal(conn, eid, "MSOL_ab12", home_host_id=hid)
        derive_entra_findings(conn, eid)
    assert "adconnect_credential_extraction" in _cands(tmp_db, eid)


def test_aws_sts_sets_the_tenant_flag() -> None:
    res = parse_aws_sts('{"Account":"1","Arn":"arn:aws:iam::1:user/x"}')
    assert res.facts["cloud_tenant_in_scope"] == "true"


def test_exploit_rules_are_gated_risk() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    assert techs["adconnect_credential_extraction"].autonomy != "proceed"
    assert techs["hybrid_identity_investigate"].autonomy == "proceed"
