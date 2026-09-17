"""Enumeration-coverage analysis — the structural answer to under-enumeration.

Under-enumeration is the top failure mode in OSAI-style engagements: a host is
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


@dataclass
class Gap:
    """One missing piece of enumeration, with the command that closes it."""
    kind: str        # full_tcp | version | udp | none
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
        f"SELECT ip, stage FROM host WHERE engagement_id = ? AND stage IN ({placeholders}) "
        "ORDER BY ip",
        (engagement_id, *ACTIVE_STAGES),
    ).fetchall()

    out: list[HostCoverage] = []
    for h in hosts:
        ip = h["ip"]
        if host_ip is not None and ip != host_ip:
            continue
        cov = _verdict(ip, h["stage"], by_host.get(ip, []))
        if cov.complete and not include_complete:
            continue
        out.append(cov)
    out.sort(key=lambda c: (-len(c.gaps), c.ip))
    return out


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


def render_gaps(gaps: list[HostCoverage], *, limit: int | None = None) -> list[str]:
    """Compact operator-facing lines (shared by the CLI, the handoff and recall)."""
    if not gaps:
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
