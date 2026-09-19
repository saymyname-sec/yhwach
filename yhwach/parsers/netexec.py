"""NetExec (nxc / crackmapexec) output -> structured SMB facts.

NetExec is the workhorse for SMB triage: host posture (signing, SMBv1, OS/domain),
share enumeration with per-principal access, user enumeration, admin access
(`Pwn3d!`), and the password policy. Each maps to a first-class row so the world
model records *what we can reach and as whom*, not just prose.

The parser is line-oriented and tolerant of the `PROTO IP PORT NAME  [..] ...`
prefix nxc puts on every line. It returns an `NxcResult`; the ingest handler
inserts shares/principals/privileges/password_policy and emits chaining findings
(smb_signing_off, domain_users, admin_access).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from yhwach.interpret import ExtractedFinding


@dataclass
class ParsedShare:
    name: str
    access: str | None = None   # READ | WRITE | READ,WRITE | None
    remark: str | None = None


@dataclass
class ParsedPrincipal:
    name: str
    domain: str | None = None
    description: str | None = None
    flags: str | None = None


@dataclass
class NxcResult:
    signing: bool | None = None
    smbv1: bool | None = None
    os: str | None = None
    domain: str | None = None
    hostname: str | None = None
    shares: list[ParsedShare] = field(default_factory=list)
    principals: list[ParsedPrincipal] = field(default_factory=list)
    admin_users: list[str] = field(default_factory=list)   # creds flagged Pwn3d!
    password_policy: dict = field(default_factory=dict)
    findings: list[ExtractedFinding] = field(default_factory=list)


# Strip the leading "SMB 10.0.0.5 445 DC01 " protocol/target prefix from a line.
_PREFIX = re.compile(r"^\s*(?P<proto>SMB|LDAP|WINRM|RDP|SSH|MSSQL|FTP)\s+"
                     r"(?P<ip>[\d.]+|[\da-fA-F:]+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<rest>.*)$")

# Host banner: [*] Windows Server 2022 ... (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
_HOST = re.compile(r"\(name:(?P<name>[^)]*)\).*?\(domain:(?P<domain>[^)]*)\)"
                   r".*?\(signing:(?P<signing>True|False)\).*?\(SMBv1:(?P<smbv1>True|False)\)",
                   re.I)
# Share table row: NAME   PERMS   REMARK   (perms optional)
_SHARE = re.compile(r"^(?P<name>\S+)\s+(?P<perms>READ(?:,WRITE)?|WRITE|NO ACCESS)?\s*(?P<remark>.*)$",
                    re.I)
# User row: corp.local\svc_sql   badpwdcount: 0 desc: some description
_USER = re.compile(r"^(?:(?P<domain>[^\\/]+)[\\/])?(?P<user>[^\s\\/]+)\s*"
                   r"(?:badpwdcount:\s*\d+)?\s*(?:desc:\s*(?P<desc>.*))?$", re.I)
# Cred success:  [+] corp.local\svc_sql:Password! (Pwn3d!)
_CRED = re.compile(r"\[\+\]\s+(?:(?P<domain>[^\\/]+)[\\/])?(?P<user>[^:\s]+):(?P<pw>\S*)\s*"
                   r"(?P<pwn>\(Pwn3d!\))?", re.I)


def parse_netexec(text: str) -> NxcResult:  # noqa: C901 - line dispatcher, flat by design
    res = NxcResult()
    mode: str | None = None  # 'shares' | 'users' after the corresponding banner
    for raw in text.splitlines():
        pm = _PREFIX.match(raw)
        rest = pm.group("rest").strip() if pm else raw.strip()
        if pm and res.hostname is None:
            res.hostname = pm.group("name")
        low = rest.lower()

        hm = _HOST.search(rest)
        if hm:
            res.hostname = hm.group("name") or res.hostname
            res.domain = hm.group("domain") or res.domain
            res.signing = hm.group("signing").lower() == "true"
            res.smbv1 = hm.group("smbv1").lower() == "true"
            # OS string is everything before the first "(" in the banner.
            banner = rest.split("(name:")[0].replace("[*]", "").strip()
            res.os = banner or res.os
            continue

        cm = _CRED.search(rest)
        if cm and cm.group("user"):
            user = cm.group("user")
            if cm.group("pwn"):
                res.admin_users.append(user)
            continue

        # Section banners flip the mode for the rows that follow.
        if "enumerated shares" in low:
            mode = "shares"
            continue
        if "enumerated domain user" in low or "enumerated users" in low:
            mode = "users"
            continue
        if "dumping password info" in low:
            mode = "policy"
            m = re.search(r"for domain:\s*(\S+)", rest, re.I)
            if m and not res.domain:
                res.domain = m.group(1)
            continue

        if mode == "policy":
            _parse_policy_line(rest, res)
            # policy block is short; a blank/prefixless line ends it
            if not rest:
                mode = None
            continue

        if mode == "shares":
            _maybe_share(rest, res)
            continue
        if mode == "users":
            _maybe_user(rest, res)
            continue

    _finalize(res)
    return res


def _maybe_share(rest: str, res: NxcResult) -> None:
    if not rest or rest.lower().startswith(("share", "-----")):
        return
    m = _SHARE.match(rest)
    if not m:
        return
    perms = (m.group("perms") or "").upper().replace("NO ACCESS", "") or None
    res.shares.append(ParsedShare(
        name=m.group("name"), access=perms, remark=(m.group("remark") or "").strip() or None))


def _maybe_user(rest: str, res: NxcResult) -> None:
    if not rest or rest.startswith("[") or rest.lower().startswith("-guest"):
        return
    m = _USER.match(rest)
    if not m or not m.group("user"):
        return
    res.principals.append(ParsedPrincipal(
        name=m.group("user"), domain=m.group("domain"),
        description=(m.group("desc") or "").strip() or None))


def _parse_policy_line(rest: str, res: NxcResult) -> None:
    for label, key, cast in (
        (r"minimum password length", "min_length", int),
        (r"account lockout threshold", "lockout_threshold", _lockout_int),
        (r"reset account lockout counter", "lockout_window_min", _minutes_int),
        (r"password complexity", "complexity", _onoff_int),
    ):
        m = re.search(label + r"\s*:?\s*(?P<v>.+)$", rest, re.I)
        if m:
            val = cast(m.group("v").strip())
            if val is not None:
                res.password_policy[key] = val
            return


def _finalize(res: NxcResult) -> None:
    if res.signing is False:
        res.findings.append(ExtractedFinding(
            "T1557.001", "SMB signing disabled", "high",
            f"signing:False on {res.hostname or 'host'} — NTLM relay candidate",
            tag="smb_signing_off"))
    if res.smbv1:
        res.findings.append(ExtractedFinding(
            "T1210", "SMBv1 enabled", "medium",
            f"SMBv1 on {res.hostname or 'host'} — legacy/relay/EternalBlue surface"))
    if res.principals:
        res.findings.append(ExtractedFinding(
            "T1087.002", "Domain users enumerated", "medium",
            f"{len(res.principals)} users via NetExec — spray / AS-REP / kerberoast",
            tag="domain_users"))
    if res.admin_users:
        res.findings.append(ExtractedFinding(
            "T1078", "Local admin access (Pwn3d!)", "high",
            "admin via " + ", ".join(sorted(set(res.admin_users)))[:150],
            tag="admin_access"))
    writable = [s.name for s in res.shares if s.access and "WRITE" in s.access]
    if writable:
        res.findings.append(ExtractedFinding(
            "T1135", "Writable SMB share", "medium",
            "writable: " + ", ".join(writable[:6])[:150], tag="writable_share"))


def _lockout_int(v: str) -> int | None:
    if re.search(r"none|no lockout|0", v, re.I):
        return 0
    m = re.search(r"\d+", v)
    return int(m.group()) if m else None


def _minutes_int(v: str) -> int | None:
    m = re.search(r"\d+", v)
    return int(m.group()) if m else None


def _onoff_int(v: str) -> int | None:
    if re.search(r"on|enabled|1|true", v, re.I):
        return 1
    if re.search(r"off|disabled|0|false", v, re.I):
        return 0
    return None
