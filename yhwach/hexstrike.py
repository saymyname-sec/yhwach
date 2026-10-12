"""HexStrike integration — delegate enumeration execution to a local HexStrike
server, ingest the results into Yhwach's world model.

HexStrike (https://github.com/hexstrike-ai/hexstrike-ai) exposes an
unauthenticated `/api/command` that runs a shell command and returns structured
output. Yhwach uses it to run nmap (and, later, nuclei/netexec) so the operator
doesn't shuffle output files by hand.

OPSEC: HexStrike's execute_command is unauthenticated RCE. Keep the server bound
to loopback (127.0.0.1) and reach it only locally or through your own tunnel —
never point Yhwach at a HexStrike exposed on an untrusted network.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
from urllib.parse import urlparse

import requests

DEFAULT_URL = "http://127.0.0.1:8888"

# A scan target is an IP, a CIDR, or a hostname label set — never a shell
# expression. We validate before interpolating into the command HexStrike runs.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,255}$")


def _validate_target(target: str) -> str:
    """Return the target if it is a plausible IP/CIDR/hostname, else raise.

    HexStrike's /api/command runs the string in a shell, so a target carrying
    shell metacharacters is remote command execution on the operator's box.
    """
    t = (target or "").strip()
    if not _TARGET_RE.match(t):
        raise HexStrikeError(f"refusing unsafe scan target: {target!r}")
    return t
# Command timeout for delegated tool runs (full-port nmap is slow); env-overridable.
DEFAULT_TIMEOUT = float(os.environ.get("YHWACH_HEXSTRIKE_TIMEOUT", "180"))


class HexStrikeError(RuntimeError):
    pass


class HexStrikeClient:
    def __init__(self, base_url: str = DEFAULT_URL, *, timeout: float = DEFAULT_TIMEOUT,
                 session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()

    def health(self) -> dict:
        r = self.session.get(f"{self.base_url}/health", timeout=10)
        r.raise_for_status()
        return r.json()

    def run_command(self, command: str, *, timeout: float | None = None) -> dict:
        """Run a command via HexStrike. Returns the structured result dict
        (stdout / stderr / return_code / success / ...)."""
        r = self.session.post(
            f"{self.base_url}/api/command",
            json={"command": command},
            timeout=timeout or self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def nmap_xml(
        self,
        target: str,
        *,
        ports: str | None = None,
        flags: str = "-sV -Pn -T4 --min-rate 900",
    ) -> str:
        """Run nmap through HexStrike and return the XML (from `-oX -`).

        When `ports` is None the scan covers ALL 65535 TCP ports (`-p-`), not
        nmap's top-1000 default. Rationale: targets routinely park the
        scored surface on a high port (e.g. an AI/LLM API on 8080, an ELK
        stack on 9200/5601, a management panel on 49xxx). A top-ports scan
        silently skips them and the operator never learns the host's real
        role. Full-port is the default for every new endpoint; pass an explicit
        `ports` spec only to deliberately narrow a re-scan.
        """
        safe_target = _validate_target(target)
        safe_ports = ""
        if ports:
            if not re.match(r"^[0-9,\-]{1,64}$", ports):
                raise HexStrikeError(f"refusing unsafe port spec: {ports!r}")
            safe_ports = f"-p {ports} "
        else:
            safe_ports = "-p- "
        cmd = f"nmap {flags} {safe_ports}--open -oX - {shlex.quote(safe_target)}"
        data = self.run_command(cmd)
        stdout = data.get("stdout", "")
        if not stdout.strip() and not data.get("success", False):
            raise HexStrikeError(f"nmap via HexStrike failed: {data.get('stderr', '')[:200]}")
        return stdout


def is_loopback(url: str) -> bool:
    """True only when the URL's HOST is loopback.

    A substring test matched `http://attacker/?localhost`; parse the host and
    check it is exactly localhost or an address in 127.0.0.0/8 / ::1.
    """
    try:
        host = (urlparse(url).hostname or "").strip()
    except ValueError:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
