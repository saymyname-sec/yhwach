"""nmap XML parser -> host / service rows.

Handles the standard nmap XML output (`-oX`). Small surface area on purpose:
IP, hostname, an OS-class hint from the <os> block if present, and every port
with its service/version info. Only 'open' ports are recorded by default
(`open|filtered` opt-in via `include_open_filtered=True`).
"""
from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class ParsedService:
    port: int
    proto: str
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    cpe: str | None = None


@dataclass
class ParsedHost:
    ip: str
    hostname: str | None = None
    os_hint: str | None = None
    services: list[ParsedService] = field(default_factory=list)


@dataclass
class ScanCoverage:
    """One protocol's port coverage in a single nmap run."""
    proto: str            # tcp | udp
    ports: str            # the range as reported: '1-65535', '1-1000', 'top-100'
    port_count: int = 0
    full_range: bool = False


@dataclass
class ScanMeta:
    """Run-level facts about *what was scanned* — not what was found.

    The world model used to be blind here: a `-p 1-1000` scan and a `-p-` scan
    produced identical host rows, so 'enumerated' could never be checked against
    reality. This is the missing half.
    """
    args: str | None = None
    version_scan: bool = False
    coverage: list[ScanCoverage] = field(default_factory=list)


FULL_TCP_PORTS = 65535

_ARGS_RE = re.compile(r"\bas:\s*(?P<args>nmap .+?)\s*$", re.IGNORECASE)
_TOPPORTS_RE = re.compile(r"--top-ports\s+(\d+)")
_PORTSPEC_RE = re.compile(r"(?:^|\s)-p\s*(?P<spec>[-\dTU:,*]+)")


def _count_port_spec(spec: str) -> tuple[int, bool]:
    """(port_count, is_full_range) for an nmap port spec like '1-65535' or '22,80'.

    Unparseable fragments are skipped rather than guessed at — an unknown spec
    reports what it could count, and `full_range` only ever goes True on real
    1-65535 coverage.
    """
    total = 0
    for part in spec.split(","):
        part = part.strip().lstrip("TU:")
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo_i = int(lo) if lo.strip().isdigit() else 1
            hi_i = int(hi) if hi.strip().isdigit() else FULL_TCP_PORTS
            if hi_i >= lo_i:
                total += hi_i - lo_i + 1
        elif part.isdigit():
            total += 1
    return total, total >= FULL_TCP_PORTS


def _meta_from_args(args: str) -> ScanMeta:
    """Derive coverage from an nmap command line (the only source for `-oN`)."""
    meta = ScanMeta(args=args.strip())
    meta.version_scan = bool(re.search(r"(?:^|\s)-(?:sV|A)\b", args))
    proto = "udp" if re.search(r"(?:^|\s)-sU\b", args) else "tcp"

    top = _TOPPORTS_RE.search(args)
    if top:
        n = int(top.group(1))
        meta.coverage.append(ScanCoverage(proto, f"top-{n}", n, False))
        return meta
    spec = _PORTSPEC_RE.search(args)
    if spec:
        raw = spec.group("spec")
        if raw.strip() == "-":
            meta.coverage.append(ScanCoverage(proto, "1-65535", FULL_TCP_PORTS, True))
        else:
            count, full = _count_port_spec(raw)
            if count:
                meta.coverage.append(ScanCoverage(proto, raw, count, full))
        return meta
    # No port flag at all: nmap's default is its top 1000.
    meta.coverage.append(ScanCoverage(proto, "top-1000", 1000, False))
    return meta


def parse_scan_meta(text: str) -> ScanMeta:
    """Extract run-level scan coverage from nmap XML (`-oX`) or normal (`-oN`) output.

    XML is authoritative: `<scaninfo>` states the exact range per protocol, and a
    `method="probed"` service element proves a version scan ran even when the
    args are absent. Normal output only carries the command line, so coverage is
    derived from the flags.
    """
    head = text.lstrip()[:256].lower()
    if head.startswith("<?xml") or "<nmaprun" in head:
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return ScanMeta()
        args = root.get("args")
        meta = ScanMeta(args=args)
        meta.version_scan = bool(args and re.search(r"(?:^|\s)-(?:sV|A)\b", args))
        if not meta.version_scan:
            # A probed service element is proof of -sV even if args are missing.
            meta.version_scan = any(
                s.get("method") == "probed" for s in root.iter("service"))
        for si in root.findall("scaninfo"):
            proto = si.get("protocol") or "tcp"
            services = si.get("services") or ""
            if not services:
                continue
            count, full = _count_port_spec(services)
            num = si.get("numservices")
            if num and num.isdigit():
                count = max(count, int(num))
                full = full or count >= FULL_TCP_PORTS
            meta.coverage.append(ScanCoverage(proto, services, count, full))
        if not meta.coverage and args:
            derived = _meta_from_args(args)
            meta.coverage = derived.coverage
        return meta

    for line in text.splitlines()[:5]:
        m = _ARGS_RE.search(line)
        if m:
            return _meta_from_args(m.group("args"))
    return ScanMeta()


def parse_nmap_xml(
    xml_path: Path | str,
    *,
    include_open_filtered: bool = False,
) -> list[ParsedHost]:
    """Parse an nmap XML file into a list of ParsedHost objects."""
    root = ET.parse(str(xml_path)).getroot()
    return _parse_root(root, include_open_filtered=include_open_filtered)


def parse_nmap_xml_text(
    xml_text: str,
    *,
    include_open_filtered: bool = False,
) -> list[ParsedHost]:
    """Parse nmap XML from a string (e.g. HexStrike's `-oX -` stdout)."""
    root = ET.fromstring(xml_text)
    return _parse_root(root, include_open_filtered=include_open_filtered)


_HOST_RE = re.compile(
    r"^Nmap scan report for (?:(?P<host>[^\s()]+) \((?P<ip1>[\d.]+)\)|(?P<ip2>[\d.:a-fA-F]+))")
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|open\|filtered)\s+"
    r"(?P<svc>\S+)(?:\s+(?P<ver>.*\S))?")


def parse_nmap_normal(text: str, *, include_open_filtered: bool = False) -> list[ParsedHost]:
    """Parse normal (`-oN`) nmap output — the human-readable table format.

    Best-effort but robust for the common shape: `Nmap scan report for <host> (<ip>)`
    followed by `PORT STATE SERVICE VERSION` rows. Removes the need to convert
    `-oN` to `-oX` before ingesting."""
    hosts: list[ParsedHost] = []
    cur: ParsedHost | None = None
    for line in text.splitlines():
        m = _HOST_RE.match(line)
        if m:
            ip = m.group("ip1") or m.group("ip2")
            cur = ParsedHost(ip=ip, hostname=m.group("host"))
            hosts.append(cur)
            continue
        if cur is None:
            continue
        low = line.strip().lower()
        if low.startswith(("os details:", "running:", "os cpe:")) and not cur.os_hint:
            cur.os_hint = line.split(":", 1)[1].strip()
            continue
        pm = _PORT_RE.match(line.strip())
        if pm:
            if pm.group("state") != "open" and not include_open_filtered:
                continue
            svc = pm.group("svc")
            ver = pm.group("ver")
            cur.services.append(ParsedService(
                port=int(pm.group("port")), proto=pm.group("proto"),
                product=svc if svc and svc != "?" else None, version=ver))
    return [h for h in hosts if h.services or h.hostname]


def parse_nmap(text: str, *, include_open_filtered: bool = False) -> list[ParsedHost]:
    """Auto-detect XML (`-oX`) vs normal (`-oN`) nmap output and parse either."""
    head = text.lstrip()[:256].lower()
    if head.startswith("<?xml") or "<nmaprun" in head:
        return parse_nmap_xml_text(text, include_open_filtered=include_open_filtered)
    return parse_nmap_normal(text, include_open_filtered=include_open_filtered)


def _parse_root(root, *, include_open_filtered: bool = False) -> list[ParsedHost]:
    hosts: list[ParsedHost] = []

    for host_elem in root.findall("host"):
        # Skip hosts nmap marked as down.
        status = host_elem.find("status")
        if status is not None and status.get("state") == "down":
            continue

        ip: str | None = None
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if ip is None:
            continue

        hostname: str | None = None
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                hostname = first.get("name")

        os_hint: str | None = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            match = os_elem.find("osmatch")
            if match is not None:
                os_hint = match.get("name")

        host = ParsedHost(ip=ip, hostname=hostname, os_hint=os_hint)

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None:
                    continue
                s = state.get("state")
                if s == "open" or (s == "open|filtered" and include_open_filtered):
                    portid = port.get("portid")
                    if portid is None:
                        continue
                    proto = port.get("protocol") or "tcp"
                    service_elem = port.find("service")
                    product = version = banner = cpe = None
                    if service_elem is not None:
                        product = service_elem.get("product") or service_elem.get("name")
                        version = service_elem.get("version")
                        banner = service_elem.get("extrainfo")
                        # First application/OS CPE nmap emitted for the service.
                        cpe_elem = service_elem.find("cpe")
                        if cpe_elem is not None and cpe_elem.text:
                            cpe = cpe_elem.text.strip()
                    host.services.append(
                        ParsedService(int(portid), proto, product, version, banner, cpe)
                    )

        hosts.append(host)

    return hosts


def insert_hosts(
    conn: sqlite3.Connection,
    engagement_id: int,
    hosts: list[ParsedHost],
    meta: ScanMeta | None = None,
) -> tuple[int, int]:
    """Insert parsed hosts + services into the DB.

    Idempotent per (engagement, ip) for hosts and per (host, port, proto) for services.
    Returns (hosts_touched, services_touched).

    With `meta` (from `parse_scan_meta`), the run's scan coverage — the port
    range it actually covered and whether it carried `-sV` — is recorded against
    every host it touched, which is what makes under-enumeration queryable
    (`yhwach gaps`). Coverage is a property of the *run*, so it applies to each
    host in that run's output.
    """
    now = _now_utc()
    hosts_touched = 0
    services_touched = 0

    for parsed in hosts:
        row = conn.execute(
            "SELECT id, stage FROM host WHERE engagement_id = ? AND ip = ?",
            (engagement_id, parsed.ip),
        ).fetchone()

        if row is None:
            cur = conn.execute(
                "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen, "
                "last_updated) VALUES (?, ?, ?, ?, 'scanned', ?, ?)",
                (
                    engagement_id,
                    parsed.ip,
                    parsed.hostname,
                    _os_class(parsed.os_hint),
                    now,
                    now,
                ),
            )
            host_id = int(cur.lastrowid)
        else:
            host_id = row["id"]
            # Advance undiscovered -> scanned; otherwise leave the stage alone.
            new_stage = "scanned" if row["stage"] == "undiscovered" else row["stage"]
            conn.execute(
                "UPDATE host SET hostname = COALESCE(?, hostname), "
                "os = COALESCE(?, os), stage = ?, last_updated = ? WHERE id = ?",
                (parsed.hostname, _os_class(parsed.os_hint), new_stage, now, host_id),
            )
        hosts_touched += 1

        for svc in parsed.services:
            conn.execute(
                "INSERT INTO service (host_id, port, proto, product, version, cpe, banner, "
                "discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(host_id, port, proto) DO UPDATE SET "
                "product = COALESCE(excluded.product, service.product), "
                "version = COALESCE(excluded.version, service.version), "
                "cpe     = COALESCE(excluded.cpe,     service.cpe), "
                "banner  = COALESCE(excluded.banner,  service.banner)",
                (host_id, svc.port, svc.proto, svc.product, svc.version, svc.cpe, svc.banner, now),
            )
            services_touched += 1
            # Mirror a versioned service into the software inventory so the
            # version -> CVE step has one place to look (listening + post-foothold).
            if svc.product and svc.version:
                svc_id = conn.execute(
                    "SELECT id FROM service WHERE host_id = ? AND port = ? AND proto = ?",
                    (host_id, svc.port, svc.proto),
                ).fetchone()
                _upsert_software(conn, host_id,
                                 service_id=svc_id["id"] if svc_id else None,
                                 name=svc.product, version=svc.version, cpe=svc.cpe, now=now)

        if meta is not None:
            from yhwach.db import record_coverage

            for cov in meta.coverage:
                record_coverage(
                    conn, host_id, proto=cov.proto, ports=cov.ports,
                    port_count=cov.port_count, full_range=cov.full_range,
                    version_scan=meta.version_scan, source=meta.args,
                )

    return hosts_touched, services_touched


def _upsert_software(conn, host_id, *, service_id, name, version, cpe, now):
    """Idempotent software-row upsert (host+name+version). Kept local to avoid a
    circular import of yhwach.db; mirrors db.add_software's dedupe key."""
    existing = conn.execute(
        "SELECT id FROM software WHERE host_id = ? AND name = ? AND version IS ?",
        (host_id, name, version),
    ).fetchone()
    if existing is not None:
        conn.execute("UPDATE software SET cpe = COALESCE(?, cpe), "
                     "service_id = COALESCE(?, service_id), updated_at = ? WHERE id = ?",
                     (cpe, service_id, now, existing["id"]))
        return
    conn.execute(
        "INSERT INTO software (host_id, service_id, name, version, cpe, kind, source, "
        "discovered_at) VALUES (?, ?, ?, ?, ?, 'service', 'nmap', ?)",
        (host_id, service_id, name, version, cpe, now),
    )


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _os_class(os_hint: str | None) -> str | None:
    """Classify an nmap OS hint into 'linux' / 'windows' / 'unknown'."""
    if not os_hint:
        return None
    low = os_hint.lower()
    if "windows" in low:
        return "windows"
    if any(k in low for k in ("linux", "ubuntu", "debian", "kali", "unix", "bsd")):
        return "linux"
    return "unknown"
