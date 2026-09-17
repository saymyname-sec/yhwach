"""Engagement scope helpers — keep Yhwach pointed only at authorized targets.

Scope is a comma-separated list of IPs / CIDRs on the engagement. These helpers
validate it and check whether a scan target falls inside it, so `engage` rejects
a malformed scope and `enum` refuses an out-of-scope target before any traffic.
"""
from __future__ import annotations

import ipaddress


def is_ip_or_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token.strip(), strict=False)
        return True
    except ValueError:
        return False


def validate_scope(scope: str) -> list[str]:
    """Return the malformed scope tokens (empty list = all valid)."""
    bad: list[str] = []
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if tok and not is_ip_or_cidr(tok):
            bad.append(tok)
    return bad


def scope_networks(scope: str) -> list:
    nets = []
    for tok in (scope or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return nets


def in_scope(target: str, scope: str) -> bool:
    """True if `target` (an IP or CIDR) is contained in any scope network.

    An empty/unknown scope does not block (returns True). A non-IP target
    (hostname) returns False — the caller decides how to treat that."""
    nets = scope_networks(scope)
    if not nets:
        return True
    try:
        tnet = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return False
    return any(tnet.version == n.version and tnet.subnet_of(n) for n in nets)
