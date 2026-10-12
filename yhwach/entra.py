"""Entra / hybrid-identity detection (I33).

Flags the on-prem producers of a hybrid identity — the Azure AD Connect sync
account (MSOL_/Sync_/ADSync), the Seamless-SSO computer (AZUREADSSOACC$), and
ADFS service principals — from the AD identity graph a bloodhound/netexec ingest
already built. Detection raises report-class findings always; the exploit-class
rules (dump AD Connect creds, forge a Golden SAML / SSO silver ticket) are gated
behind cloud_tenant_in_scope so they never fire on a pure on-prem assessment.

Device-code and consent phishing are red-team social engineering and are
deliberately NOT modelled as pentest recall.
"""
from __future__ import annotations

import re
import sqlite3

from yhwach import db as yhdb

_MSOL = re.compile(r"^(MSOL_|Sync_|AAD_|ADSync)", re.I)
_SSO_ACC = "azureadssoacc$"


def derive_entra_findings(conn: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    """Scan principals for hybrid-identity producers; emit tagged findings.
    Idempotent (add_finding dedupes on location+tag). Returns per-kind counts."""
    counts = {"adconnect": 0, "sso": 0, "adfs": 0}
    rows = conn.execute(
        "SELECT id, name, domain, spn, home_host_id FROM principal WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    for r in rows:
        name = r["name"] or ""
        host_id = r["home_host_id"]
        if _MSOL.match(name):
            yhdb.add_finding(
                conn, host_id, None, "T1078.004",
                "Azure AD Connect sync account", "high",
                f"{name} is the AD Connect/DirSync account — it can DCSync on-prem AD and "
                "holds the cloud sync credential (Azure AD Connect server)",
                tag="adconnect_host", location=name, engagement_id=engagement_id)
            # also a generic hybrid-identity lead so the report rule fires
            yhdb.add_finding(
                conn, host_id, None, "T1078.004", "Hybrid identity present", "medium",
                f"hybrid-identity producer: {name}", tag="hybrid_identity",
                location=name, engagement_id=engagement_id)
            counts["adconnect"] += 1
        elif name.lower() == _SSO_ACC:
            yhdb.add_finding(
                conn, host_id, None, "T1550", "Seamless SSO computer account", "high",
                "AZUREADSSOACC$ — its NT hash forges a Kerberos silver ticket to "
                "autologon.microsoftazuread-sso.com (cloud access)",
                tag="hybrid_identity", location=name, engagement_id=engagement_id)
            counts["sso"] += 1
        elif (r["spn"] and "adfs" in (r["spn"] or "").lower()) or "adfs" in name.lower():
            yhdb.add_finding(
                conn, host_id, None, "T1606.002", "ADFS service principal", "medium",
                f"{name} — ADFS token-signing key enables Golden SAML to the tenant",
                tag="hybrid_identity", location=name, engagement_id=engagement_id)
            counts["adfs"] += 1
    return counts
