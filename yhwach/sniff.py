"""Signature sniffing for `yhwach_interpret` — classify pasted tool output so
it lands as typed rows without the operator naming a parser.

Conservative by design: it recognises the file-parser kinds (the common paste
cases) by cheap markers, first-match-wins, specific before generic. When nothing
matches it returns 'raw' so the caller falls back to loot + an INFO finding —
never a wrong guess. The ~70 interpret extractors stay reachable by naming an
explicit `kind='x:<action_id>'`; auto-sniffing every one of them would be a
guessing game, so it is deliberately not attempted here.
"""
from __future__ import annotations

import re

# (kind, compiled test). Order matters: specific first.
_SIGNS: list[tuple[str, re.Pattern]] = [
    ("nmap", re.compile(r"<nmaprun|Nmap scan report|Starting Nmap", re.I)),
    ("nessus", re.compile(r"<NessusClientData_v2|<ReportHost\b|pluginID=")),
    ("openvas", re.compile(r"<nvt\s+oid=|Greenbone|<get_results_response")),
    # nuclei JSONL: one object per line carrying a template-id + matched-at.
    ("nuclei", re.compile(r'"template-?id"\s*:|"matched-at"\s*:')),
    # bbot NDJSON events, then httpx JSONL (subfinder is too generic to sniff).
    ("bbot", re.compile(r'"type"\s*:\s*"(DNS_NAME|URL|OPEN_TCP_PORT|IP_ADDRESS)"')),
    ("httpx", re.compile(r'"webserver"\s*:|"cdn[_-]name"\s*:|"status[_-]code"\s*:.*"url"')),
    # Burp "Save items" XML, then HAR 1.2 (both are web-capture metadata).
    ("burp", re.compile(r"<items\b|<!DOCTYPE items|burpVersion", re.I)),
    ("har", re.compile(r'"log"\s*:\s*\{[^}]*"entries"|"creator"\s*:\s*\{[^}]*"name"')),
    ("certipy", re.compile(r"Certipy|Certificate Templates|\bESC\d{1,2}\b")),
    ("bloodhound", re.compile(r'"ObjectIdentifier"|SharpHound|"PrincipalSID"|"meta"\s*:')),
    ("winpeas", re.compile(r"winpeas|Windows Local Privilege Escalation|AllowAutomaticUpdates|"
                           r"SeImpersonatePrivilege", re.I)),
    ("linpeas", re.compile(r"linpeas|Linux Privesc|Basic information|\[\+\] \[CVE-", re.I)),
    # NetExec / CrackMapExec line protocol: PROTO <ip> <port> HOST [*]/[+]
    ("netexec", re.compile(r"^(SMB|LDAP|WINRM|RDP|MSSQL|FTP)\s+\d{1,3}(\.\d{1,3}){3}\s+\d+",
                           re.M)),
    ("netexec", re.compile(r"Pwn3d!|STATUS_LOGON_FAILURE")),
    # Content-discovery output (gobuster/ffuf/feroxbuster/dirb). Needs a url.
    ("web", re.compile(r"\(Status:\s*\d{3}\)|^\s*\d{3}\s+GET|\"results\"\s*:\s*\[", re.M)),
    # impacket-secretsdump NTDS/SAM: user:rid:lm:nt::: (specific — before potfile).
    ("secretsdump", re.compile(r"^[^:\s]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::", re.M)),
    # hashcat/john NT potfile: [$NT$]<32hex>:<plaintext> at line start.
    ("potfile", re.compile(r"^(?:\$NT\$)?[0-9a-fA-F]{32}:", re.M)),
]


def detect(text: str) -> str:
    """Return a parser kind, or 'raw' when nothing matches."""
    head = text[:20000]  # markers live near the top; keep it cheap
    for kind, pat in _SIGNS:
        if pat.search(head):
            return kind
    return "raw"
