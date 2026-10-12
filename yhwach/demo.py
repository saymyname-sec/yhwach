"""G6c — `yhwach demo --kind X`: build a synthetic, offline engagement so a new
user can explore yhwach (brief / status / next / path / query) without a target,
a network, or a scanner. Seeds are hand-built world models — representative shape,
no traffic, no secrets that mean anything.

Five seeds cover the postures that differ most: `lab` (armed, scored, an AI
surface), `internal` (AD, record-only, a provided account with a path to the DC),
`web` (app-layer authz/IDOR), `cloud` (k8s/aws grants), and `bounty` (external
program with a duplicate-risk submission). Everything here uses only the public
db helpers — it never opens a socket.
"""
from __future__ import annotations

import sqlite3

from yhwach import db as yhdb
from yhwach import reuse, scope

SEED_KINDS = ("lab", "internal", "web", "cloud", "bounty")
_TS = "2026-01-01T00:00:00Z"


def _host(conn: sqlite3.Connection, eid: int, ip: str, hostname: str, *,
          stage: str = "enumerated", os: str | None = None, alive: str = "alive") -> int:
    return int(conn.execute(
        "INSERT INTO host (engagement_id, ip, hostname, os, stage, alive, first_seen) "
        "VALUES (?,?,?,?,?,?,?)", (eid, ip, hostname, os, stage, alive, _TS)).lastrowid)


def _svc(conn: sqlite3.Connection, hid: int, port: int, proto: str = "tcp") -> int:
    return int(conn.execute(
        "INSERT INTO service (host_id, port, proto, discovered_at) VALUES (?,?,?,?)",
        (hid, port, proto, _TS)).lastrowid)


def _surface(conn: sqlite3.Connection, hid: int, sid: int | None, kind: str,
             auth: str = "none") -> None:
    yhdb.upsert_surface(conn, hid, sid, kind, auth, "{}")


# --- seeds ------------------------------------------------------------------


def _seed_lab(conn: sqlite3.Connection, lab: str) -> int:
    eid = yhdb.upsert_engagement(conn, lab=lab, scope="10.10.10.0/24", kind="lab",
                                 started_at=_TS, points_target=20, points_max=40)
    scope.sync_from_string(conn, eid, "10.10.10.0/24")
    h = _host(conn, eid, "10.10.10.5", "target01", stage="foothold", os="linux")
    _surface(conn, h, _svc(conn, h, 11434), "ollama")      # a standalone AI host
    _surface(conn, h, _svc(conn, h, 80), "http")
    _svc(conn, h, 22)
    yhdb.add_finding(conn, h, None, "ai_prompt_injection",
                     "System-prompt override via unsanitised chat input", "high",
                     "model echoed the injected canary", tag="prompt_injection")
    yhdb.add_finding(conn, h, None, "web_lfi", "LFI in ?page=", "medium",
                     "path traversal returned /etc/passwd", tag="lfi")
    yhdb.add_objective(conn, eid, "user flag", host_id=h, points=10, captured=True)
    yhdb.add_objective(conn, eid, "root flag", host_id=h, points=20)
    yhdb.add_credential(conn, eid, "ubuntu", "s3cret", "password", "ssh_lab",
                        source_host_id=h, provenance="discovered")
    return eid


def _seed_internal(conn: sqlite3.Connection, lab: str) -> int:
    eid = yhdb.upsert_engagement(conn, lab=lab, scope="10.10.0.0/16", kind="internal",
                                 domain="CORP.LOCAL", dc_ip="10.10.0.1", started_at=_TS)
    scope.sync_from_string(conn, eid, "10.10.0.0/16")
    dc = _host(conn, eid, "10.10.0.1", "dc01", os="windows")
    web = _host(conn, eid, "10.10.0.10", "web01", os="windows")
    files = _host(conn, eid, "10.10.0.20", "file01", os="windows")
    for n in range(4):                                     # a few more so the brief has bulk
        _host(conn, eid, f"10.10.0.{30 + n}", f"ws{n:02d}", stage="scanned")
    for hid in (dc, web, files):
        _surface(conn, hid, _svc(conn, hid, 445), "smb")
    _surface(conn, dc, _svc(conn, dc, 389), "ldap")
    _surface(conn, web, _svc(conn, web, 80), "http")

    svc_backup, _ = yhdb.add_principal(conn, eid, "svc_backup", domain="CORP.LOCAL",
                                       type="user", spn="MSSQL/db01.corp.local")
    yhdb.add_principal(conn, eid, "Domain Admins", domain="CORP.LOCAL", type="group")

    # a PROVIDED (assumed-breach) account that is admin on the DC — the owned source.
    # The identifier matches the principal name (bare sAMAccountName) so pathfind's
    # ownership join (identifier == principal.name) sees it as owned.
    provided, _ = yhdb.add_credential(conn, eid, "svc_backup", "Winter2026!",
                                      "password", "client_provided",
                                      provenance="provided", principal_id=svc_backup)
    yhdb.record_cred_access(conn, eid, provided, dc, result="admin", service_kind="smb")
    # a DUMPED hash — manual, must never be swept
    yhdb.add_credential(conn, eid, "CORP.LOCAL\\admin", "aad3b435:31d6cfe0", "ntlm",
                        "secretsdump", source_host_id=files,
                        provenance="discovered", spray_policy="manual")

    yhdb.add_finding(conn, None, None, "ad_kerberoastable",
                     "svc_backup is kerberoastable (has an SPN)", "medium",
                     "krb5tgs hash obtained", tag="kerberoastable", engagement_id=eid)
    yhdb.add_finding(conn, dc, None, "ad_smb_signing_off", "SMB signing not required",
                     "medium", "nxc smb flagged signing False", tag="smb_signing_off")
    yhdb.add_domain_fact(conn, eid, "MachineAccountQuota", "10", domain="CORP.LOCAL")
    yhdb.add_objective(conn, eid, "Domain Controller (crown jewel)", host_id=dc,
                       kind="crown_jewel")
    reuse.derive_reuse_edges(conn, eid)                    # principal:svc_backup -> host:dc
    return eid


def _seed_web(conn: sqlite3.Connection, lab: str) -> int:
    eid = yhdb.upsert_engagement(conn, lab=lab, scope="app.example.com,*.example.com",
                                 kind="web", client="Example Corp", started_at=_TS)
    scope.sync_from_string(conn, eid, "app.example.com,*.example.com")
    h = _host(conn, eid, "203.0.113.10", "app.example.com")
    sid = _svc(conn, h, 443)
    _surface(conn, h, sid, "http", auth="form")
    yhdb.add_web_app(conn, h, "https://app.example.com", service_id=sid,
                     scheme="https", title="Example App", tech="nginx,react")
    yhdb.add_domain(conn, eid, "app.example.com", type="domain", ip="203.0.113.10", host_id=h)
    yhdb.add_finding(conn, h, None, "web_idor", "IDOR on /api/orders/{id}", "high",
                     "order 1002 readable as user A", tag="idor_candidate",
                     location="/api/orders/{id}")
    yhdb.add_finding(conn, h, None, "web_graphql", "GraphQL introspection enabled", "low",
                     "__schema returned", tag="graphql", location="/graphql")
    return eid


def _seed_cloud(conn: sqlite3.Connection, lab: str) -> int:
    eid = yhdb.upsert_engagement(conn, lab=lab, scope="*.svc.cluster.local",
                                 kind="cloud", client="Example Corp", started_at=_TS)
    scope.sync_from_string(conn, eid, "*.svc.cluster.local")
    yhdb.add_finding(conn, None, None, "k8s_pod_create", "SA can create pods in 3 namespaces",
                     "high", "kubectl auth can-i create pods: yes", tag="pod_create_permission",
                     engagement_id=eid)
    yhdb.add_finding(conn, None, None, "k8s_sa_token", "Mountable SA token reaches kube-api",
                     "medium", "serviceaccount token present", tag="k8s_sa_token",
                     engagement_id=eid)
    yhdb.add_domain_fact(conn, eid, "aws_account", "123456789012")
    yhdb.add_domain_fact(conn, eid, "privileged_pods", "4")
    return eid


def _seed_bounty(conn: sqlite3.Connection, lab: str) -> int:
    eid = yhdb.upsert_engagement(conn, lab=lab, scope="*.target.example,api.target.example",
                                 kind="bounty", client="target.example VDP", started_at=_TS)
    scope.sync_from_string(conn, eid, "*.target.example,api.target.example")
    h = _host(conn, eid, "198.51.100.7", "api.target.example")
    sid = _svc(conn, h, 443)
    _surface(conn, h, sid, "http")
    yhdb.add_web_app(conn, h, "https://api.target.example", service_id=sid, scheme="https")
    yhdb.add_domain(conn, eid, "api.target.example", type="domain", ip="198.51.100.7", host_id=h)
    fid, _ = yhdb.add_finding(conn, h, None, "web_sqli", "Error-based SQLi in /v1/search",
                              "critical", "sleep(5) observed", tag="sqli",
                              location="/v1/search?q=")
    yhdb.add_submission(conn, eid, program="target.example VDP", finding_id=fid,
                        endpoint="/v1/search", param="q", cls="sqli", status="reported")
    return eid


_SEEDS = {
    "lab": _seed_lab,
    "internal": _seed_internal,
    "web": _seed_web,
    "cloud": _seed_cloud,
    "bounty": _seed_bounty,
}


def build_demo(conn: sqlite3.Connection, kind: str, *, lab: str | None = None) -> dict:
    """Seed a synthetic engagement of `kind` into `conn`. Returns a summary dict."""
    if kind not in _SEEDS:
        raise ValueError(f"no demo seed for {kind!r}; have {SEED_KINDS}")
    lab = lab or f"demo-{kind}"
    eid = _SEEDS[kind](conn, lab)
    counts = {
        "hosts": conn.execute("SELECT COUNT(*) FROM host WHERE engagement_id=?",
                              (eid,)).fetchone()[0],
        "findings": conn.execute("SELECT COUNT(*) FROM finding WHERE engagement_id=?",
                                 (eid,)).fetchone()[0],
        "creds": conn.execute("SELECT COUNT(*) FROM credential WHERE engagement_id=?",
                              (eid,)).fetchone()[0],
    }
    return {"engagement_id": eid, "lab": lab, "kind": kind,
            "armed": yhdb.engagement_armed(conn, eid), **counts}
