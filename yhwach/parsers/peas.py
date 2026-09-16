"""linPEAS / winPEAS output -> privesc findings.

PEAS output is huge and noisy. We extract only high-signal, unambiguous privesc
leads by pattern — sudo NOPASSWD, known-exploitable SUID (GTFObins), dangerous
capabilities, SeImpersonate, AlwaysInstallElevated, GPP/autologon creds, unquoted
service paths. Everything else stays for the operator to read in the raw file.
"""
from __future__ import annotations

import re

from yhwach.interpret import ExtractedFinding

# GTFObins SUID/privesc binaries worth flagging when the SUID bit is set.
_GTFO_SUID = {
    "find", "vim", "vi", "nmap", "bash", "sh", "less", "more", "nano", "cp", "mv",
    "python", "python2", "python3", "perl", "awk", "gawk", "tar", "zip", "gdb",
    "env", "make", "ruby", "lua", "node", "docker", "systemctl", "dmesg",
    "strace", "tcpdump", "openssl", "cpulimit", "ionice", "nice", "flock",
    "pkexec", "base64", "cat", "dd", "sed", "ed",
}


def parse_linpeas(text: str) -> list[ExtractedFinding]:
    out: list[ExtractedFinding] = []

    # sudo NOPASSWD
    if re.search(r"NOPASSWD", text):
        entries = re.findall(r"\(([^)]*)\)\s*NOPASSWD:\s*(\S+)", text)
        ev = "; ".join(f"({u}) {c}" for u, c in entries[:5]) or "NOPASSWD entry present"
        out.append(ExtractedFinding("CWE-250", "sudo NOPASSWD entry", "high", ev[:160]))

    # SUID GTFObins (match the SUID permission bit -rws...)
    suid = set()
    for m in re.finditer(r"-rws[rwxsS-]{6}.*?(/\S+)", text):
        b = m.group(1).rsplit("/", 1)[-1]
        if b in _GTFO_SUID:
            suid.add(b)
    if suid:
        out.append(ExtractedFinding(
            "CWE-250", "Exploitable SUID binary (GTFObins)", "high",
            "SUID: " + ", ".join(sorted(suid))[:150]))

    # capabilities
    caps = re.findall(r"(/\S+)\s*=\s*cap_(setuid|setgid|dac_override)", text)
    if caps:
        out.append(ExtractedFinding(
            "CWE-250", "Dangerous file capability", "high",
            "; ".join(f"{p} cap_{c}" for p, c in caps[:4])[:150]))

    # writable /etc/passwd or /etc/shadow
    if re.search(r"/etc/passwd.*(writable|is writable)", text, re.I) or \
            re.search(r"You have write privileges over /etc/passwd", text, re.I):
        out.append(ExtractedFinding(
            "CWE-732", "Writable /etc/passwd", "critical", "root via crafted passwd row"))

    # private keys / creds in files
    if re.search(r"BEGIN (RSA|OPENSSH|EC) PRIVATE KEY", text):
        out.append(ExtractedFinding(
            "CWE-522", "Private SSH key found on host", "high", "reuse for lateral SSH"))

    return out


def parse_winpeas(text: str) -> list[ExtractedFinding]:
    out: list[ExtractedFinding] = []

    if re.search(r"Se(Impersonate|AssignPrimaryToken)Privilege", text):
        out.append(ExtractedFinding(
            "CWE-250", "SeImpersonate/SeAssignPrimaryToken (Potato)", "high",
            "token-impersonation privesc to SYSTEM"))

    if re.search(r"AlwaysInstallElevated.*?1", text, re.S):
        out.append(ExtractedFinding(
            "CWE-250", "AlwaysInstallElevated enabled", "high",
            "malicious MSI runs as SYSTEM"))

    if re.search(r"No quotes and Space detected|Unquoted Service Path", text, re.I):
        out.append(ExtractedFinding(
            "CWE-428", "Unquoted service path", "high",
            "writable-directory hijack -> SYSTEM"))

    if re.search(r"cpassword", text, re.I):
        out.append(ExtractedFinding(
            "CWE-256", "GPP cpassword recoverable", "high",
            "decrypt with gpp-decrypt for domain creds"))

    if re.search(r"DefaultPassword\s*:\s*\S+|AutoLogon", text):
        out.append(ExtractedFinding(
            "CWE-256", "Autologon credentials in registry", "medium",
            "DefaultUserName/DefaultPassword set"))

    if re.search(r"Currently stored credentials|cmdkey", text, re.I) and "Target:" in text:
        out.append(ExtractedFinding(
            "CWE-522", "Stored credentials (cmdkey)", "medium",
            "runas /savecred against stored targets"))

    return out


def parse_peas(text: str, kind: str) -> list[ExtractedFinding]:
    if kind == "linpeas":
        return parse_linpeas(text)
    if kind == "winpeas":
        return parse_winpeas(text)
    raise ValueError(f"unknown peas kind: {kind}")
