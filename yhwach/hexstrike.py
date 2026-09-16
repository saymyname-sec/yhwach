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

import requests

DEFAULT_URL = "http://127.0.0.1:8888"


class HexStrikeError(RuntimeError):
    pass


class HexStrikeClient:
    def __init__(self, base_url: str = DEFAULT_URL, *, timeout: float = 180.0,
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
        nmap's top-1000 default. Rationale: OSAI targets routinely park the
        scored surface on a high port (e.g. an AI/LLM API on 8080, an ELK
        stack on 9200/5601, a management panel on 49xxx). A top-ports scan
        silently skips them and the operator never learns the host's real
        role. Full-port is the default for every new endpoint; pass an explicit
        `ports` spec only to deliberately narrow a re-scan.
        """
        portarg = f"-p {ports} " if ports else "-p- "
        cmd = f"nmap {flags} {portarg}--open -oX - {target}"
        data = self.run_command(cmd)
        stdout = data.get("stdout", "")
        if not stdout.strip() and not data.get("success", False):
            raise HexStrikeError(f"nmap via HexStrike failed: {data.get('stderr', '')[:200]}")
        return stdout


def is_loopback(url: str) -> bool:
    return "127.0.0.1" in url or "localhost" in url
