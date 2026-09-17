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


@dataclass
class ParsedHost:
    ip: str
    hostname: str | None = None
    os_hint: str | None = None
    services: list[ParsedService] = field(default_factory=list)


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
                    product = version = banner = None
                    if service_elem is not None:
                        product = service_elem.get("product") or service_elem.get("name")
                        version = service_elem.get("version")
                        banner = service_elem.get("extrainfo")
                    host.services.append(
                        ParsedService(int(portid), proto, product, version, banner)
                    )

        hosts.append(host)

    return hosts


def insert_hosts(
    conn: sqlite3.Connection,
    engagement_id: int,
    hosts: list[ParsedHost],
) -> tuple[int, int]:
    """Insert parsed hosts + services into the DB.

    Idempotent per (engagement, ip) for hosts and per (host, port, proto) for services.
    Returns (hosts_touched, services_touched).
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
                "INSERT INTO service (host_id, port, proto, product, version, banner, "
                "discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(host_id, port, proto) DO UPDATE SET "
                "product = COALESCE(excluded.product, service.product), "
                "version = COALESCE(excluded.version, service.version), "
                "banner  = COALESCE(excluded.banner,  service.banner)",
                (host_id, svc.port, svc.proto, svc.product, svc.version, svc.banner, now),
            )
            services_touched += 1

    return hosts_touched, services_touched


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
