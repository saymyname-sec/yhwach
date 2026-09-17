"""BloodHound output -> AD findings with chaining tags.

Two input shapes are accepted, both JSON:

1. **Normalized AD facts** (the BloodHound-MCP / Cypher-wrapper contract) — a list
   of `{kind, principal, detail?}`, e.g.
   `[{"kind": "kerberoastable", "principal": "svc_sql@CORP", "detail": "MSSQLSvc/.."}]`.
   This is the stable interface: any BloodHound query maps onto it.

2. **SharpHound collection files** (`users_*.json` / `computers_*.json`) — the
   parser opportunistically reads `.data[].Properties.{hasspn,dontreqpreauth,
   unconstraineddelegation}` so a raw collection also lights up chains.

Each fact becomes an `ExtractedFinding` carrying the `findings_include` tag the
AD attack rules gate on (see playbooks/ad.yaml). Attach the results to the DC
host on ingest — that's where these attacks target.
"""
from __future__ import annotations

import json

from yhwach.interpret import ExtractedFinding

# fact kind -> (class, severity, title-prefix)
_KIND_MAP: dict[str, tuple[str, str, str]] = {
    "kerberoastable": ("T1558.003", "high", "Kerberoastable account"),
    "asreproastable": ("T1558.004", "high", "AS-REP roastable account"),
    "unconstrained_delegation": ("T1558", "high", "Unconstrained delegation"),
    "constrained_delegation": ("T1558", "high", "Constrained delegation"),
    "dcsync": ("T1003.006", "critical", "DCSync rights"),
    "acl_abuse": ("T1222", "high", "Abusable ACL edge"),
    "da_path": ("T1078", "high", "Path to Domain Admins"),
    "gpp_password": ("T1552.006", "high", "GPP password"),
    # GenericWrite / WriteDACL / AddKeyCredentialLink over a Tier-0 principal:
    # write msDS-KeyCredentialLink -> PKINIT -> NT hash (shadow credential).
    "shadow_cred_target": ("T1556", "critical", "Shadow-credential target (writable msDS-KeyCredentialLink)"),
    # Coercion / NTLM-relay facts (find_computers_webclient_running,
    # find_dcs_vulnerable_ntlm_relay, find_computers_no_smb_signing).
    "webclient_running": ("T1187", "high", "WebClient running (HTTP coercion -> ADCS ESC8)"),
    "ntlm_relay_dc": ("T1557.001", "high", "DC vulnerable to NTLM relay (LDAP signing not enforced)"),
    "no_smb_signing": ("T1557.001", "medium", "SMB signing not required (relay target)"),
}


def _fact_finding(kind: str, principal: str | None, detail: str | None) -> ExtractedFinding:
    cls, sev, title = _KIND_MAP.get(kind, ("T1087", "medium", kind.replace("_", " ")))
    who = principal or "(domain)"
    ev = f"{who}" + (f" — {detail}" if detail else "")
    return ExtractedFinding(cls, f"{title}: {who}", sev, ev[:180], tag=kind)


def _from_sharphound(data: dict) -> list[ExtractedFinding]:
    out: list[ExtractedFinding] = []
    kind = (data.get("meta", {}) or {}).get("type", "")
    for obj in data.get("data", []) or []:
        props = (obj.get("Properties") or {}) if isinstance(obj, dict) else {}
        name = props.get("name") or props.get("distinguishedname") or "(object)"
        if kind == "users":
            if props.get("hasspn"):
                out.append(_fact_finding("kerberoastable", name, "SPN set"))
            if props.get("dontreqpreauth"):
                out.append(_fact_finding("asreproastable", name, "no Kerberos pre-auth"))
        elif kind == "computers":
            if props.get("unconstraineddelegation"):
                out.append(_fact_finding("unconstrained_delegation", name, None))
    return out


def parse_bloodhound(text: str) -> list[ExtractedFinding]:
    """Parse BloodHound output (normalized facts list or SharpHound JSON)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []

    # SharpHound collection file: {"meta": {...}, "data": [...]}
    if isinstance(data, dict) and "data" in data and "meta" in data:
        return _from_sharphound(data)

    # Normalized facts: a bare list, or {"facts": [...]}
    facts = data.get("facts") if isinstance(data, dict) else data
    if not isinstance(facts, list):
        return []
    out: list[ExtractedFinding] = []
    for f in facts:
        if not isinstance(f, dict):
            continue
        kind = f.get("kind")
        if not kind:
            continue
        out.append(_fact_finding(kind, f.get("principal"), f.get("detail")))
    return out
