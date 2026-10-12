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
class ParsedCredSuccess:
    user: str
    proto: str | None = None   # smb | winrm | ldap | ssh | mssql | rdp | ftp
    port: int | None = None
    admin: bool = False        # (Pwn3d!)


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
    successes: list[ParsedCredSuccess] = field(default_factory=list)  # every [+] auth
    password_policy: dict = field(default_factory=dict)
    # I45 — domain-wide facts from NetExec modules (maq, ldap_signing, …) and
    # roastable hashes (krb5tgs/krb5asrep) to store as crackable credentials.
    domain_facts: dict = field(default_factory=dict)
    kerberos_hashes: list[dict] = field(default_factory=list)
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
            is_admin = bool(cm.group("pwn"))
            if is_admin:
                res.admin_users.append(user)
            proto = pm.group("proto").lower() if pm else None
            port = int(pm.group("port")) if pm and pm.group("port").isdigit() else None
            res.successes.append(ParsedCredSuccess(user=user, proto=proto, port=port,
                                                   admin=is_admin))
            continue

        # Module output (MAQ, roast hashes, ldap-checker) appears OUTSIDE the
        # shares/users/policy sections, so only match it between sections — a
        # share or user row is never misread as a domain fact.
        if mode is None and _maybe_module(rest, low, res):
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


_KRB5TGS_RE = re.compile(r"\$krb5tgs\$\S+")
_KRB5ASREP_RE = re.compile(r"\$krb5asrep\$\S+")


def _roast_user(h: str, kind: str) -> str | None:
    """The account a roast hash belongs to, for the credential identifier."""
    if kind == "krb5tgs":
        m = re.search(r"\$krb5tgs\$\d+\$\*([^$*]+)", h)
        return m.group(1) if m else None
    m = re.search(r"\$krb5asrep\$\d+\$([^@:$]+)", h)
    return m.group(1) if m else None


def _maybe_module(rest: str, low: str, res: NxcResult) -> bool:
    """Recognise a NetExec module/activity line and record a domain fact or a
    roastable hash. Returns True if the line was consumed. Token-based so it
    tolerates version-to-version format drift."""
    mq = re.search(r"MachineAccountQuota:\s*(\d+)", rest, re.I)
    if mq:
        res.domain_facts["machine_account_quota"] = mq.group(1)
        return True
    if "ldap" in low and "signing" in low:
        enforced = not re.search(r"not\s+enforced|not\s+required|disabled|none", low)
        res.domain_facts["ldap_signing"] = "enforced" if enforced else "not_enforced"
        return True
    if "channel binding" in low:
        if re.search(r"\bnever\b|not\s+set|disabled", low):
            val = "never"
        elif re.search(r"required|always", low):
            val = "required"
        elif "when supported" in low or "supported" in low:
            val = "when_supported"
        else:
            val = "unknown"
        res.domain_facts["channel_binding"] = val
        return True
    if "laps" in low and re.search(r"readable|password|\bset\b", low):
        res.domain_facts["laps"] = "present"
        return True
    kt = _KRB5TGS_RE.search(rest)
    if kt:
        res.kerberos_hashes.append({"kind": "krb5tgs", "hash": kt.group(0),
                                    "user": _roast_user(kt.group(0), "krb5tgs")})
        return True
    ka = _KRB5ASREP_RE.search(rest)
    if ka:
        res.kerberos_hashes.append({"kind": "krb5asrep", "hash": ka.group(0),
                                    "user": _roast_user(ka.group(0), "krb5asrep")})
        return True
    return False


def _finalize(res: NxcResult) -> None:
    facts = res.domain_facts
    maq = facts.get("machine_account_quota")
    if maq is not None and maq.isdigit() and int(maq) > 0:
        res.findings.append(ExtractedFinding(
            "T1078", f"MachineAccountQuota = {maq}", "medium",
            f"any authenticated user can add up to {maq} machine account(s) — "
            "RBCD / shadow-credential primitive", tag="maq_abuse"))
    if facts.get("ldap_signing") == "not_enforced":
        res.findings.append(ExtractedFinding(
            "T1557.001", "LDAP signing not enforced", "high",
            "LDAP signing not enforced — NTLM relay to LDAP candidate",
            tag="ldap_relay"))
    if facts.get("channel_binding") in ("never", "when_supported"):
        res.findings.append(ExtractedFinding(
            "T1557.001", "LDAP channel binding weak", "medium",
            f"channel binding = {facts['channel_binding']} — relay-to-LDAPS surface",
            tag="ldap_relay"))
    for kh in res.kerberos_hashes:
        if kh["kind"] == "krb5tgs":
            res.findings.append(ExtractedFinding(
                "T1558.003", "Kerberoastable account", "high",
                f"TGS hash for {kh.get('user') or 'an SPN account'} — crack offline "
                "(hashcat -m 13100)", tag="kerberoastable"))
        else:
            res.findings.append(ExtractedFinding(
                "T1558.004", "AS-REP roastable account", "high",
                f"AS-REP hash for {kh.get('user') or 'an account'} — crack offline "
                "(hashcat -m 18200)", tag="asreproastable"))
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
    # "none"/"no lockout"/"never" mean lockout is disabled -> 0. A bare "0"
    # means the same. But a threshold like 10/20/30/100 must NOT be read as 0
    # just because it contains the digit 0 — that silently disabled the
    # sprayer's only safety guard on the most common hardened-AD settings.
    s = v.strip()
    if re.search(r"\bnone\b|no\s*lockout|never|not?\s+set", s, re.I):
        return 0
    m = re.search(r"\d+", s)
    if m is None:
        return None
    return int(m.group())


def _minutes_int(v: str) -> int | None:
    m = re.search(r"\d+", v)
    return int(m.group()) if m else None


def _onoff_int(v: str) -> int | None:
    if re.search(r"on|enabled|1|true", v, re.I):
        return 1
    if re.search(r"off|disabled|0|false", v, re.I):
        return 0
    return None
