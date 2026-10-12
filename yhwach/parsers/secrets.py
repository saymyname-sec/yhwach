"""Parsers for dumped secrets — impacket-secretsdump output and hashcat/john
potfiles (G2c).

Dumped NT hashes and cracked passwords land in the credential vault so the
credential-reuse graph can see them, but they are flagged ``spray_policy='manual'``
by the caller: spraying a dumped domain hash across the estate is the loud,
lockout-risking move. These functions only PARSE; the writing/flagging is the
ingest tool's job.

Deliberately conservative: only the unambiguous ``user:rid:lm:nt:::`` hash line
(NTDS/SAM) and the ``[$NT$]<32hex>:<plaintext>`` potfile line are recognised.
Kerberos keys, LSA cleartext and cached-domain lines are left for a later pass
rather than guessed at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# user[:rid]:lm:nt::: — the canonical secretsdump NTDS/SAM hash line. The user
# field may be DOMAIN\user or just user; RID is numeric; LM/NT are 32 hex.
_DUMP_LINE = re.compile(
    r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::",
)
# hashcat (-m 1000) `nt:plain` or john `$NT$nt:plain`. Plaintext runs to EOL.
_POT_LINE = re.compile(r"^(?:\$NT\$)?(?P<nt>[0-9a-fA-F]{32}):(?P<plain>.*)$")

_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"  # NT hash of the empty password


@dataclass(frozen=True)
class DumpedCred:
    identifier: str          # the account name, no domain
    domain: str | None       # realm/host prefix if the line carried one
    nt_hash: str             # lower-case NT hash
    rid: int | None
    is_machine: bool         # account name ends with '$'
    empty_password: bool     # NT hash is the empty-password hash


@dataclass(frozen=True)
class CrackedHash:
    nt_hash: str             # lower-case NT hash
    plaintext: str


def parse_secretsdump(text: str) -> list[DumpedCred]:
    """Every NTDS/SAM hash line, de-duplicated by (identifier, domain, nt_hash)."""
    out: list[DumpedCred] = []
    seen: set[tuple] = set()
    for raw in text.splitlines():
        m = _DUMP_LINE.match(raw.strip())
        if not m:
            continue
        user = m.group("user").strip()
        domain: str | None = None
        if "\\" in user:
            domain, user = user.split("\\", 1)
        nt = m.group("nt").lower()
        key = (user.lower(), (domain or "").lower(), nt)
        if key in seen:
            continue
        seen.add(key)
        out.append(DumpedCred(
            identifier=user,
            domain=domain or None,
            nt_hash=nt,
            rid=int(m.group("rid")),
            is_machine=user.endswith("$"),
            empty_password=(nt == _EMPTY_NT),
        ))
    return out


def parse_potfile(text: str) -> list[CrackedHash]:
    """Every `nt:plaintext` potfile line, de-duplicated by nt_hash (first wins)."""
    out: list[CrackedHash] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        m = _POT_LINE.match(line.strip())
        if not m:
            continue
        nt = m.group("nt").lower()
        if nt in seen:
            continue
        seen.add(nt)
        out.append(CrackedHash(nt_hash=nt, plaintext=m.group("plain")))
    return out
