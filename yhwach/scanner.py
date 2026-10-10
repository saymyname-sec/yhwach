"""Auto full-scan orchestrator — the "always full-port + -sV, no exceptions" fix.

Fixes the gap where websrv:8001 (an API on a non-default port) sat
undiscovered because the operator only ran ``nmap -p 22,445,1433,3389,5985``
across the internal /24 and never followed up with a per-host ``-p-``. Now:

  * Every scope-materialised host (from :mod:`yhwach.discovery`) lands with
    ``scan_needed=1``.
  * ``yhwach_scan`` (or its ``pending`` variant) walks the queue, runs
    ``nmap -sV -sC -p-`` (+ optional UDP top-100), ingests the result via
    the same code path as ``yhwach_ingest kind=nmap`` (so the sprayer's
    per-new-service hook fires automatically), then clears ``scan_needed=0``
    on that host.
  * ``yhwach_gaps`` surfaces ``scan_needed=1`` hosts prominently so the
    operator sees the queue depth in the brief.

Design decisions
----------------

* **Nmap is a subprocess, no HexStrike dependency.** Keeps the module
  self-contained and testable — HexStrike is optional infrastructure; the
  scanner works whether or not it's up. Same 12s-ish philosophy as sprayer:
  every scan has a per-host wall-clock cap so the batch keeps flowing.
* **Modes are named after operator intent, not nmap flags.**
    ``quick`` = ``-sV -sC --top-ports 1000`` (fast baseline);
    ``full``  = ``-sV -sC -p-`` (the "no missed ports" guarantee);
    ``udp``   = ``-sU --top-ports 100`` (the other coverage floor).
  The scanner writes each output to ``<workspace>/recon/<ip>_<mode>.xml``
  so re-ingest is a matter of re-reading the file, no re-scanning.
* **Idempotency:** a host with ``scan_needed=0`` is skipped by
  ``scan_pending`` (unless ``force=True``). ``scan_host`` on one target
  always runs — the caller is being explicit.
* **Concurrency:** ``scan_pending`` runs hosts sequentially by default.
  Parallelism is off unless the caller asks for it — sshuttle-style pivots
  fall over when multiple heavy nmaps hit them.

Public API
----------

``scan_host(conn, eid, ip, mode='full') -> ScanResult``
    Run one nmap, ingest it, flip ``scan_needed=0``.

``scan_pending(conn, eid, max_hosts=8, mode='full') -> list[ScanResult]``
    Walk the queue until ``max_hosts`` scans complete or the queue drains.
"""
from __future__ import annotations

import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from yhwach import config as yhconfig

# Where scans land. Resolved from the workspace config (env-overridable via
# $YHWACH_RECON_DIR / $YHWACH_HOME) so recon files sit under the operator's
# workspace, not a hard-coded path.
_RECON_DIR = yhconfig.recon_dir()

# Per-scan wall-clock ceilings (seconds). A single stuck host must never
# stall the batch. Full-range TCP takes longer than top-1000, so budget
# accordingly. Values conservative for a lab; a real engagement can raise
# them via the mode argument.
_TIMEOUTS = {
    "quick": 180,   # top-1000 -sV -sC
    "full":  900,   # -p- -sV -sC (15 min ceiling)
    "udp":   600,   # -sU --top-ports 100
}

# Command templates. ``{ip}`` and ``{out}`` are the only substitutions.
# --host-timeout gives nmap its OWN internal ceiling; the subprocess
# timeout is the outer guard. --min-rate 800 keeps a /24 sweep bounded.
_CMDS = {
    "quick": [
        "nmap", "-sT", "-Pn", "-sV", "-sC",
        "--top-ports", "1000",
        "--host-timeout", "150s",
        "-oX", "{out}", "{ip}",
    ],
    "full": [
        "nmap", "-sT", "-Pn", "-sV", "-sC",
        "-p-", "--min-rate", "800",
        "--host-timeout", "800s",
        "-oX", "{out}", "{ip}",
    ],
    "udp": [
        "nmap", "-sU", "-Pn", "--top-ports", "100",
        "--host-timeout", "500s",
        "-oX", "{out}", "{ip}",
    ],
}


@dataclass
class ScanResult:
    """One host × one mode outcome. Returned by scan_host and included in
    scan_pending's list."""
    ip: str
    mode: str
    success: bool
    output_path: Path | None
    hosts_ingested: int = 0
    services_ingested: int = 0
    detail: str = ""


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _ingest_scan_file(
    conn: sqlite3.Connection,
    engagement_id: int,
    xml_path: Path,
) -> tuple[int, int]:
    """Run the file through the same code path as ``yhwach_ingest kind=nmap``.

    Reuses ``parsers.nmap.parse_nmap`` + ``insert_hosts`` so the sprayer's
    new-service hook fires when :func:`scan_host` is called from the MCP
    layer (the transaction is shared through ``conn``).
    """
    from yhwach.parsers.nmap import insert_hosts, parse_nmap, parse_scan_meta

    text = xml_path.read_text(encoding="utf-8", errors="replace")
    meta = parse_scan_meta(text)
    parsed = parse_nmap(text)
    return insert_hosts(conn, engagement_id, parsed, meta)


def _clear_scan_needed(
    conn: sqlite3.Connection, engagement_id: int, ip: str,
) -> None:
    """Flip ``scan_needed=0`` for a host after a successful full/quick scan.

    ``full`` clears the flag definitively. ``quick`` also clears (the flag
    only means "we owe a first scan"); the coverage rows from
    ``record_coverage`` still tell ``yhwach_gaps`` that a full-port pass
    is missing so nothing gets missed.
    """
    conn.execute(
        "UPDATE host SET scan_needed = 0, last_updated = ? "
        "WHERE engagement_id = ? AND ip = ?",
        (_now(), engagement_id, ip),
    )


def scan_host(
    conn: sqlite3.Connection,
    engagement_id: int,
    ip: str,
    *,
    mode: str = "full",
    output_dir: Path | None = None,
) -> ScanResult:
    """Run one nmap against ``ip``, ingest, clear scan_needed.

    Returns a :class:`ScanResult` — never raises for a scan failure (the
    ``success`` flag + ``detail`` carry the reason). Configuration errors
    (unknown mode, missing nmap) still raise because they're operator bugs.
    """
    if mode not in _CMDS:
        raise ValueError(f"unknown mode {mode!r} (use quick|full|udp)")
    if not shutil.which("nmap"):
        raise RuntimeError("nmap not on PATH — apt install nmap")

    out_dir = output_dir or _RECON_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / f"{ip.replace('/', '_')}_{mode}.xml"

    cmd = [tok.format(ip=ip, out=str(xml_path)) for tok in _CMDS[mode]]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_TIMEOUTS[mode], check=False,
        )
    except subprocess.TimeoutExpired:
        return ScanResult(
            ip=ip, mode=mode, success=False, output_path=None,
            detail=f"timeout after {_TIMEOUTS[mode]}s",
        )

    if proc.returncode != 0 and not xml_path.exists():
        return ScanResult(
            ip=ip, mode=mode, success=False, output_path=None,
            detail=(proc.stderr or proc.stdout or "nmap failed")[:200].strip(),
        )
    if not xml_path.exists():
        return ScanResult(
            ip=ip, mode=mode, success=False, output_path=None,
            detail="nmap exited 0 but wrote no XML",
        )

    hosts, services = _ingest_scan_file(conn, engagement_id, xml_path)
    if mode in ("quick", "full"):
        _clear_scan_needed(conn, engagement_id, ip)

    return ScanResult(
        ip=ip, mode=mode, success=True, output_path=xml_path,
        hosts_ingested=hosts, services_ingested=services,
        detail=f"ingested {hosts} host / {services} service row(s)",
    )


def pending_hosts(
    conn: sqlite3.Connection, engagement_id: int, *, limit: int | None = None,
) -> list[str]:
    """IPs where ``scan_needed=1`` — the queue :func:`scan_pending` walks.

    Sorted by first_seen so a fresh scope expansion drains oldest-first,
    matching the order the operator would expect from a manual walk.
    """
    q = ("SELECT ip FROM host WHERE engagement_id=? AND scan_needed=1 "
         "ORDER BY first_seen, ip")
    if limit is not None:
        q += f" LIMIT {int(limit)}"
    return [r["ip"] for r in conn.execute(q, (engagement_id,)).fetchall()]


def scan_pending(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    max_hosts: int = 8,
    mode: str = "full",
    output_dir: Path | None = None,
) -> list[ScanResult]:
    """Drain the ``scan_needed=1`` queue up to ``max_hosts`` targets.

    Sequential by design — parallel nmaps through a pivot are the fastest
    way to wedge sshuttle. Callers who want more speed can invoke
    :func:`scan_host` themselves with their own threading strategy.
    """
    results: list[ScanResult] = []
    for ip in pending_hosts(conn, engagement_id, limit=max_hosts):
        results.append(
            scan_host(conn, engagement_id, ip, mode=mode, output_dir=output_dir),
        )
    return results
