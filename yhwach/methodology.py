"""Per-asset methodology matrix (I35).

A checklist whose state is DERIVED, never operator-typed: each item is PRESENT
(the weakness exists), CHECKED (enumerated and not vulnerable), or UNKNOWN (no
evidence yet). Evidence comes from host_fact (per-host negative evidence) and
domain_fact (domain-wide), so an item leaves UNKNOWN only once enumeration has
actually touched it. AD first; WSTG/cloud checklists are later slices.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

PRESENT, CHECKED, UNKNOWN = "PRESENT", "CHECKED", "UNKNOWN"


@dataclass(frozen=True)
class Item:
    key: str
    label: str
    scope: str            # 'host' (host_fact) | 'domain' (domain_fact)
    fact_key: str
    present_when: tuple[str, ...]   # fact values that mean the weakness is PRESENT


# AD checklist. `present_when` values flag the weakness; any OTHER observed value
# means CHECKED (we looked, it's fine); absence means UNKNOWN (not yet checked).
_AD_CHECKLIST: list[Item] = [
    Item("smb_signing", "SMB signing not enforced", "host", "smb_signing", ("false",)),
    Item("smbv1", "SMBv1 enabled", "host", "smbv1", ("true",)),
    Item("spooler", "Print Spooler reachable", "host", "spooler", ("running", "true")),
    Item("webclient", "WebClient (WebDAV) running", "host", "webclient", ("running", "true")),
    Item("ldap_signing", "LDAP signing not enforced", "domain", "ldap_signing",
         ("not_enforced",)),
    Item("channel_binding", "LDAP channel binding weak", "domain", "channel_binding",
         ("never", "when_supported")),
    Item("machine_account_quota", "MachineAccountQuota > 0", "domain", "machine_account_quota",
         ()),   # numeric: handled specially below
]


def _state(item: Item, value: str | None) -> str:
    if value is None:
        return UNKNOWN
    if item.key == "machine_account_quota":
        return PRESENT if value.isdigit() and int(value) > 0 else CHECKED
    return PRESENT if value.lower() in item.present_when else CHECKED


def methodology_for_host(conn: sqlite3.Connection, engagement_id: int,
                         host_id: int) -> list[dict]:
    """Evaluate the AD checklist for one host. Returns [{key,label,state,value}]."""
    from yhwach import db as yhdb

    hfacts = yhdb.list_host_facts(conn, host_id)
    dfacts = {r["key"]: r["value"] for r in yhdb.list_domain_facts(conn, engagement_id)}
    out = []
    for item in _AD_CHECKLIST:
        value = hfacts.get(item.fact_key) if item.scope == "host" else dfacts.get(item.fact_key)
        out.append({"key": item.key, "label": item.label,
                    "state": _state(item, value), "value": value})
    return out


def coverage_counts(matrix: list[dict]) -> dict[str, int]:
    out = {PRESENT: 0, CHECKED: 0, UNKNOWN: 0}
    for row in matrix:
        out[row["state"]] = out.get(row["state"], 0) + 1
    return out
