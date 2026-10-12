"""I43 — missing network service kinds + protocol-aware classification.

The classifier is now protocol-aware (SNMP on 161/udp is never confused with
161/tcp), covers the classic internal-engagement services, and each gets a
triage rule — read-only by default, with the dangerous moves (NFS mount, SMTP
open-relay, IPMI hash dump, printer login) gated.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import actions_ref
from yhwach import db as yhdb
from yhwach import knowledge as kn
from yhwach.probes.traditional import classify_service

# --- protocol-aware classification ------------------------------------------


def test_udp_services_classified_only_on_udp() -> None:
    assert classify_service(None, 161, "udp") == "snmp"
    assert classify_service(None, 161, "tcp") is None   # not SNMP on TCP
    assert classify_service(None, 623, "udp") == "ipmi"
    assert classify_service(None, 69, "udp") == "tftp"


def test_tcp_network_services_classified() -> None:
    assert classify_service(None, 23) == "telnet"
    assert classify_service(None, 25) == "smtp"
    assert classify_service(None, 53) == "dns"
    assert classify_service(None, 111) == "rpcbind"
    assert classify_service(None, 2049) == "nfs"
    assert classify_service(None, 135) == "msrpc"
    assert classify_service(None, 5900) == "vnc"
    assert classify_service(None, 9100) == "printer"
    assert classify_service(None, 902) == "esxi"


def test_product_fallback_classifies_nonstandard_ports() -> None:
    assert classify_service("Postfix smtpd", 9999) == "smtp"
    assert classify_service("VMware ESXi SOAP", 9999) == "esxi"
    assert classify_service("ISC BIND", 5300) == "dns"
    assert classify_service("RealVNC Enterprise", 15900) == "vnc"


def test_default_proto_is_tcp() -> None:
    # No proto arg behaves exactly as before (tcp).
    assert classify_service(None, 445) == "smb"


# --- triage rules load with correct gating ----------------------------------

_READ_ONLY = ["snmp_triage", "dns_triage", "rpcbind_triage", "msrpc_triage",
              "telnet_triage", "mail_triage", "vnc_triage", "esxi_triage"]
_GATED = ["nfs_triage", "smtp_triage", "ipmi_triage", "printer_triage"]


def test_all_triage_rules_load() -> None:
    techs = {t.id for t in kn.load_techniques()}
    assert set(_READ_ONLY + _GATED) <= techs


def test_read_only_rules_are_auto_and_gated_rules_need_go_ahead() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    for rid in _READ_ONLY:
        assert techs[rid].autonomy == "proceed", rid
    for rid in _GATED:
        assert techs[rid].autonomy != "proceed", rid


def test_triage_actions_have_command_templates() -> None:
    cmds = actions_ref.commands()
    for action_id in ("snmp_walk", "dns_axfr", "rpc_info", "rpc_dump",
                      "nfs_showmount", "vnc_auth_check", "esxi_version"):
        assert action_id in cmds, action_id
    # a gated action still renders its command (shown, but the rule gates it)
    r = actions_ref.render("ipmi_dumphashes", host="10.0.0.5")
    assert r["risk"] == "propose"


# --- end to end: an SNMP surface lights up the triage move ------------------


def test_snmp_surface_yields_a_candidate(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 161, 'udp', 'SNMP', 't')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(svc), "snmp", "none", "{}")
        cands = {c.technique_id for c in kn.candidates_for(conn, eid)}
    assert "snmp_triage" in cands
