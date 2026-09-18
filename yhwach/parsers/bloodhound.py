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
from dataclasses import dataclass, field

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
    # Domain/forest trust (map_domain_trusts) -> SID-history / inter-realm forge.
    "domain_trust": ("T1482", "high", "Domain/forest trust"),
    # Write/link control over a GPO -> push a scheduled task / local-admin right.
    "gpo_control": ("T1484.001", "high", "Controllable GPO (write / link edit)"),
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


# ---------------------------------------------------------------------------
# Structured graph extraction — the same input, but yielding principal / privilege
# / edge rows so the world model gets the AD *structure*, not only findings.
# Names are resolved to principal ids by the ingest handler.
# ---------------------------------------------------------------------------

@dataclass
class BhPrincipal:
    name: str
    domain: str | None = None
    type: str = "user"          # user | group | computer
    flags: str | None = None    # spn,dont_require_preauth,unconstrained_deleg,adminCount
    spn: str | None = None


@dataclass
class BhGraph:
    principals: list[BhPrincipal] = field(default_factory=list)
    # (principal_name, right, target)
    privileges: list[tuple[str, str, str | None]] = field(default_factory=list)
    # (src_name, dst_name, kind) — names resolved to principal ids on ingest
    edges: list[tuple[str, str, str]] = field(default_factory=list)


# fact kind -> principal flag it implies (when the fact is a property of an account)
_FLAG_FOR = {
    "kerberoastable": "spn",
    "asreproastable": "dont_require_preauth",
    "unconstrained_delegation": "unconstrained_deleg",
    "constrained_delegation": "constrained_deleg",
}
# fact kind -> (right, edge_kind) for graph-shaped facts
_RIGHT_FOR = {
    "dcsync": "DCSync",
    "acl_abuse": "GenericAll",
    "gpp_password": None,
}


def _split_name(principal: str | None) -> tuple[str, str | None]:
    """'svc_sql@CORP.LOCAL' / 'CORP\\svc_sql' -> (name, domain)."""
    if not principal:
        return "(unknown)", None
    p = principal.strip()
    if "@" in p:
        n, d = p.split("@", 1)
        return n, d or None
    if "\\" in p:
        d, n = p.split("\\", 1)
        return n, d or None
    return p, None


def parse_bloodhound_graph(text: str) -> BhGraph:
    """Extract principals / privileges / edges from BloodHound output.

    Complements parse_bloodhound (which yields findings): this yields the graph
    rows. Safe to call on the same input; returns an empty graph on junk."""
    g = BhGraph()
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return g

    if isinstance(data, dict) and "data" in data and "meta" in data:
        _graph_from_sharphound(data, g)
        return g

    facts = data.get("facts") if isinstance(data, dict) else data
    if not isinstance(facts, list):
        return g
    for f in facts:
        if not isinstance(f, dict) or not f.get("kind"):
            continue
        _graph_from_fact(f["kind"], f.get("principal"), f.get("detail"), g)
    return g


def _graph_from_fact(kind: str, principal: str | None, detail: str | None, g: BhGraph) -> None:
    name, domain = _split_name(principal)
    ptype = "computer" if "delegation" in kind else "user"
    if kind in _FLAG_FOR:
        spn = detail if kind == "kerberoastable" else None
        g.principals.append(BhPrincipal(name, domain, ptype, flags=_FLAG_FOR[kind], spn=spn))
        return
    if kind in _RIGHT_FOR:
        g.principals.append(BhPrincipal(name, domain, "user"))
        right = _RIGHT_FOR[kind]
        if right:
            g.privileges.append((name, right, detail))
        return
    if kind == "da_path":
        g.principals.append(BhPrincipal(name, domain, "user"))
        g.edges.append((name, "Domain Admins", "PathToDA"))


def _graph_from_sharphound(data: dict, g: BhGraph) -> None:
    kind = (data.get("meta", {}) or {}).get("type", "")
    for obj in data.get("data", []) or []:
        props = (obj.get("Properties") or {}) if isinstance(obj, dict) else {}
        raw = props.get("name") or props.get("distinguishedname") or "(object)"
        name, domain = _split_name(raw)
        flags: list[str] = []
        if kind == "users":
            if props.get("hasspn"):
                flags.append("spn")
            if props.get("dontreqpreauth"):
                flags.append("dont_require_preauth")
            if props.get("admincount"):
                flags.append("adminCount")
            g.principals.append(BhPrincipal(
                name, domain, "user", ",".join(flags) or None,
                spn=(props.get("serviceprincipalnames") or [None])[0]
                if isinstance(props.get("serviceprincipalnames"), list) else None))
        elif kind == "computers":
            if props.get("unconstraineddelegation"):
                flags.append("unconstrained_deleg")
            g.principals.append(BhPrincipal(name, domain, "computer", ",".join(flags) or None))
        elif kind == "groups":
            g.principals.append(BhPrincipal(name, domain, "group"))
