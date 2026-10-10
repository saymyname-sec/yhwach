"""Enumeration-coverage analysis — the structural answer to under-enumeration.

Under-enumeration is the top failure mode in security engagements: a host is
called "enumerated" after a default top-1000 TCP scan, the scored AI surface is
parked on 11434/9200/49xxx, and it is never seen. The world model could not
catch this because it only stored what was *found*, never what was *scanned*.

`scan_coverage` rows (written by the nmap ingest, see parsers/nmap.ScanMeta)
close that gap, and this module turns them into a per-host verdict plus the
exact command that would close each gap. The verdict is **advisory**: it is
surfaced in `yhwach gaps`, in the operator handoff, and as a warning when a host
is advanced to `enumerated` — it does not block the FSM, because a stage refusal
here would strand a real engagement whose scans came in out of band.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from yhwach.db import coverage_for_engagement

# Stages where enumeration depth still changes what you find. A host that is
# already pivoted/done is not re-scanned for coverage's sake.
ACTIVE_STAGES = ("undiscovered", "scanned", "enumerated", "foothold", "looted")

# A UDP sweep of the top 100 is the accepted floor (SNMP/TFTP/IKE live there).
UDP_FLOOR = 100

# Surface kinds that owe a per-service triage pass before a host is truly
# "enumerated". Sourced conceptually from data/service_matrix.yaml (the single
# source of truth); kept as a literal set here so coverage has no YAML dependency
# at import time. A surface of one of these kinds with no finding / cred-attempt /
# recon-attempt against it is the structural form of "you saw it but never
# checked it" — the completeness half of "check every path".
SERVICE_ENUM_KINDS: frozenset[str] = frozenset({
    # data stores
    "redis", "redis_sentinel", "memcached", "mongodb", "elasticsearch", "kibana",
    "kafka", "rabbitmq", "zookeeper", "postgres", "mysql", "mssql",
    # cloud-native control plane
    "apiserver", "kubelet", "kubelet_ro", "etcd", "docker_api", "docker_registry",
    "consul", "argocd", "harbor",
    # web / CI-CD apps
    "grafana", "gitlab", "jenkins", "gitea", "n8n", "nexus", "confluence",
    "keycloak", "minio", "teamcity", "sonarqube", "superset", "metabase",
    "jupyterhub", "nextcloud", "artifactory", "jira",
    # AI surfaces
    "chatbot", "openai_compat", "ollama", "vectordb", "mcp", "gradio", "a2a", "rag",
})

# Per-kind pointer for the triage a service_enum gap wants closed. A missing key
# falls back to a generic recall line; never references an unbuilt ref pack.
_ENUM_REF: dict[str, str] = {
    "redis": "redis-cli INFO/KEYS (unauth) -> default-creds -> version->CVE -> loot",
    "mongodb": "mongosh --eval 'db.adminCommand({listDatabases:1})' (unauth) -> loot",
    "elasticsearch": "curl /_cat/indices (unauth) -> version->CVE -> loot",
    "apiserver": "kubectl auth can-i --list --as=system:anonymous -> secrets/pods",
    "kubelet": "curl -k https://<ip>:10250/pods -> /run exec",
    "etcd": "etcdctl get / --prefix (unauth) -> /registry/secrets",
    "docker_api": "curl http://<ip>:2375/_ping + /version -> host-root-equivalent",
    "chatbot": "system-prompt leak -> tool/agency map -> injection (yhwach ref owasp-llm)",
    "mcp": "tools/list -> a privileged tool is the target",
}


@dataclass
class Gap:
    """One missing piece of enumeration, with the command that closes it."""
    kind: str        # full_tcp | version | udp | none | service_enum
    detail: str
    fix: str


@dataclass
class HostCoverage:
    ip: str
    stage: str
    gaps: list[Gap] = field(default_factory=list)
    tcp_ports: int = 0
    tcp_full: bool = False
    tcp_version: bool = False
    udp_ports: int = 0

    @property
    def complete(self) -> bool:
        return not self.gaps

    @property
    def summary(self) -> str:
        if self.complete:
            return "full-tcp + versions + udp top-100"
        return "; ".join(g.detail for g in self.gaps)


def enum_gaps(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
    include_complete: bool = False,
) -> list[HostCoverage]:
    """Per-host enumeration verdict, worst first (most gaps, then by IP).

    Hosts with no coverage rows at all are reported too — "never scanned by a
    run Yhwach saw" is itself the loudest gap.
    """
    rows = coverage_for_engagement(conn, engagement_id)
    by_host: dict[str, list[sqlite3.Row]] = {}
    for r in rows:
        by_host.setdefault(r["host_ip"], []).append(r)

    placeholders = ",".join("?" * len(ACTIVE_STAGES))
    hosts = conn.execute(
        f"SELECT id, ip, stage FROM host WHERE engagement_id = ? AND stage IN ({placeholders}) "
        "ORDER BY ip",
        (engagement_id, *ACTIVE_STAGES),
    ).fetchall()

    out: list[HostCoverage] = []
    for h in hosts:
        ip = h["ip"]
        if host_ip is not None and ip != host_ip:
            continue
        cov = _verdict(ip, h["stage"], by_host.get(ip, []))
        # Per-service completeness: a discovered surface that was never triaged.
        cov.gaps.extend(_service_enum_gaps(conn, h["id"]))
        if cov.complete and not include_complete:
            continue
        out.append(cov)
    out.sort(key=lambda c: (-len(c.gaps), c.ip))
    return out


def _service_enum_gaps(conn: sqlite3.Connection, host_id: int) -> list[Gap]:
    """Surfaces on this host (kind in SERVICE_ENUM_KINDS) that show no triage.

    A surface is "triaged" when, scoped to it, there is at least one of: a
    finding on that surface, a credential_access of that service kind, or an
    attempt whose rule/technique targets that kind (recon prefix). Otherwise the
    surface was seen but never checked — a service_enum gap. Advisory only.
    """
    rows = conn.execute(
        "SELECT id, kind FROM surface WHERE host_id = ?", (host_id,)
    ).fetchall()
    gaps: list[Gap] = []
    for s in rows:
        kind = s["kind"]
        if kind not in SERVICE_ENUM_KINDS:
            continue
        triaged = (
            conn.execute(
                "SELECT 1 FROM finding WHERE surface_id = ? LIMIT 1", (s["id"],)
            ).fetchone()
            or conn.execute(
                "SELECT 1 FROM credential_access WHERE host_id = ? AND service_kind = ? LIMIT 1",
                (host_id, kind),
            ).fetchone()
            or conn.execute(
                "SELECT 1 FROM attempt WHERE host_id = ? AND "
                "(playbook_rule_id LIKE ? OR technique_id LIKE ?) LIMIT 1",
                (host_id, f"{kind}%", f"{kind}%"),
            ).fetchone()
        )
        if not triaged:
            gaps.append(Gap(
                "service_enum",
                f"{kind} surface not triaged (no finding / cred / recon attempt)",
                _ENUM_REF.get(kind, f"triage {kind}: unauth -> default-creds -> version->CVE -> loot"),
            ))
    return gaps


def _verdict(ip: str, stage: str, rows: list[sqlite3.Row]) -> HostCoverage:
    cov = HostCoverage(ip=ip, stage=stage)
    if not rows:
        cov.gaps.append(Gap(
            "none", "no scan coverage recorded",
            f"nmap -p- -sV -T4 -oX scan_{ip}.xml {ip}   # then: yhwach ingest"))
        return cov

    tcp = [r for r in rows if r["proto"] == "tcp"]
    udp = [r for r in rows if r["proto"] == "udp"]
    cov.tcp_ports = max((r["port_count"] for r in tcp), default=0)
    cov.tcp_full = any(r["full_range"] for r in tcp)
    cov.tcp_version = any(r["version_scan"] for r in tcp)
    cov.udp_ports = max((r["port_count"] for r in udp), default=0)

    if not cov.tcp_full:
        widest = f"widest TCP scan seen: {cov.tcp_ports} ports" if cov.tcp_ports \
            else "no TCP scan seen"
        cov.gaps.append(Gap(
            "full_tcp", f"NOT full-ported ({widest})",
            f"nmap -p- -T4 -oX fullport_{ip}.xml {ip}"))
    if not cov.tcp_version:
        cov.gaps.append(Gap(
            "version", "no service/version scan (-sV)",
            f"nmap -sV -oX versions_{ip}.xml {ip}"))
    if cov.udp_ports < UDP_FLOOR:
        cov.gaps.append(Gap(
            "udp", f"UDP top-{UDP_FLOOR} not covered (seen: {cov.udp_ports} ports)",
            f"sudo nmap -sU --top-ports {UDP_FLOOR} -oX udp_{ip}.xml {ip}"))
    return cov


# Hosts that have actually been reached (scanned or further). Undiscovered hosts
# are the *scan queue* (tracked by scan_needed / "pending scan"), not a coverage
# gap — scoping the honesty view to started hosts keeps it actionable instead of
# echoing a fresh scope expansion of 254 unscanned IPs.
STARTED_STAGES = ("scanned", "enumerated", "foothold", "looted")


def started_gaps(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    host_ip: str | None = None,
) -> list[HostCoverage]:
    """`enum_gaps` restricted to hosts that have been reached (scanned+), worst
    first. This is the "how thorough is what I've started" view; `enum_gaps`
    itself still reports undiscovered hosts (the loudest gap of all)."""
    return [
        c
        for c in enum_gaps(conn, engagement_id, host_ip=host_ip)
        if c.stage in STARTED_STAGES
    ]


@dataclass
class CoverageScore:
    """The world-model honesty metric: of the hosts you've reached, how many are
    fully enumerated (full-TCP + versions + UDP top-100 + every service triaged)."""

    considered: int          # started hosts (scanned+)
    complete: int            # of those, fully enumerated
    pending_scan: int        # hosts never scanned (scan_needed=1) — the queue
    service_enum_gaps: int   # discovered surfaces still untriaged, across started hosts

    @property
    def pct(self) -> int | None:
        """Percentage of reached hosts that are fully enumerated, or **None**
        when nothing has been reached yet.

        This used to return 100 for an empty engagement, so the one number whose
        job is to stop the memory lying about completeness opened every lab with
        a green all-clear — on the board, in `yhwach coverage` and over MCP.
        None is "no basis for an opinion"; callers render it as `n/a`, never as
        a score.
        """
        if not self.considered:
            return None
        return round(100 * self.complete / self.considered)


def coverage_score(conn: sqlite3.Connection, engagement_id: int) -> CoverageScore:
    """Aggregate the per-host verdict into one honesty score. Pure reads."""
    covs = [
        c
        for c in enum_gaps(conn, engagement_id, include_complete=True)
        if c.stage in STARTED_STAGES
    ]
    complete = sum(1 for c in covs if c.complete)
    se_gaps = sum(1 for c in covs for g in c.gaps if g.kind == "service_enum")
    pending = conn.execute(
        "SELECT COUNT(*) FROM host WHERE engagement_id=? AND scan_needed=1",
        (engagement_id,),
    ).fetchone()[0]
    return CoverageScore(
        considered=len(covs),
        complete=complete,
        pending_scan=int(pending),
        service_enum_gaps=se_gaps,
    )


def render_gaps(gaps: list[HostCoverage], *, limit: int | None = None,
                considered: int | None = None) -> list[str]:
    """Compact operator-facing lines (shared by the CLI, the handoff and recall).

    `considered` splits the empty case. With no gaps AND no hosts reached, "every
    active host is covered" is vacuously true and reads as an all-clear at hour
    zero; pass the reached-host count so that case says so instead. Callers that
    omit it keep the old wording.
    """
    if not gaps:
        if considered == 0:
            return ["(nothing reached yet — no host has been scanned)"]
        return ["(none — every active host is full-ported, versioned and UDP-swept)"]
    shown = gaps if limit is None else gaps[:limit]
    lines: list[str] = []
    for c in shown:
        lines.append(f"  ! {c.ip:<16} [{c.stage}]  {c.summary}")
        for g in c.gaps:
            lines.append(f"      $ {g.fix}")
    if limit is not None and len(gaps) > limit:
        lines.append(f"  … +{len(gaps) - limit} more (yhwach gaps)")
    return lines


def gaps_as_dicts(gaps: list[HostCoverage]) -> list[dict]:
    """JSON-shaped view for `--json` output."""
    return [
        {
            "ip": c.ip,
            "stage": c.stage,
            "complete": c.complete,
            "tcp_ports": c.tcp_ports,
            "tcp_full": c.tcp_full,
            "tcp_version": c.tcp_version,
            "udp_ports": c.udp_ports,
            "gaps": [{"kind": g.kind, "detail": g.detail, "fix": g.fix} for g in c.gaps],
        }
        for c in gaps
    ]
