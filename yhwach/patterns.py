"""Credential-pattern derivation — the "sa:Acme-SQL-SA!2026 sat there for
hours" fix.

Once one lab cred exposes a naming template — ``svc_wiki : W1k1!Svc#Acme2025``
carries a distinctive ``<Word>!<Role>#Acme2025`` shape — the same template is
usually reused on other service accounts (``svc_backup``, ``svc_sql``,
``svc_audit``, ``sa``). :func:`derive_candidates` extracts the shape from the
vault and generates *candidate* username/password pairs for the missing
accounts. The sprayer (PR-3) then eats those candidates the moment they land.

This is not a brute force — it produces a handful of high-probability
candidates per known cred, not a wordlist. The operator opts in via
``yhwach_derive --spray``; the default just prints the suggestions so the
operator can eyeball them first.

Signals we key on
-----------------

1. **Suffix tail** — anything after the last ``!``/``#`` — often a
   ``#<CorpTag><Year>`` pattern (``#Acme2025``). Reused verbatim.
2. **Year tokens** — 4-digit years appearing in the password. If we see two
   creds with different years we generate ``current_year+1`` as an
   additional candidate for older creds (post-rotation).
3. **Role tokens** — ``Svc``, ``Adm``, ``Ops``, ``Sys``, ``Dev`` inside the
   password. These usually swap when the username swaps
   (``svc_wiki`` → ``Svc`` in password; ``admin`` → ``Adm``).
4. **Prefix leetspeak** — the first-half of the password often echoes the
   username with common letter swaps (``svc_wiki`` → ``W1k1``). We do the
   simple ``a→@``, ``e→3``, ``i→1``, ``o→0``, ``s→5``.

We deliberately do NOT emit combinations of every-thing — the sprayer's
per-service backoff (PR-3, N=4) protects the estate, but a thousand candidate
passwords still burns time. Aim for ~5-10 candidates per known pattern.

Public API
----------

``derive_candidates(vault_rows) -> list[(username, password, source_cred)]``
    ``vault_rows`` is any iterable of dicts with ``identifier`` and ``secret``
    (typical caller: ``list_credentials`` rows). ``source_cred`` records
    which vault row seeded a given candidate so we can name it in the UI.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# Common service-account usernames worth trying when we don't have them.
# Ordered by rough frequency in enterprise AD lab-style estates.
_COMMON_SVC_USERS = (
    "svc_sql", "svc_backup", "svc_audit", "svc_wiki", "svc_ldap_sync",
    "svc_smtp_relay", "svc_admin", "svc_monitor", "svc_gitlab", "svc_ci",
    "sa", "administrator", "admin", "backup", "sqladmin",
)

# Role tokens we swap when the target username's role differs.
_ROLES = {
    "svc":  "Svc",
    "adm":  "Adm",
    "sys":  "Sys",
    "ops":  "Ops",
    "dev":  "Dev",
    "sql":  "SQL",
    "root": "Root",
    "web":  "Web",
    "app":  "App",
}

# Naive leet: swap letters (case-insensitive input, capitalised output first).
_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "5"})


@dataclass
class Candidate:
    username: str
    password: str
    source_cred: str   # identifier of the vault row that seeded this pattern
    reason: str        # short human-readable template name (audit trail)


def _leet(word: str) -> str:
    """Best-effort leet variant that keeps the first letter capitalised.

    ``svc_wiki`` -> ``W1k1``  (drops separators, leets, title-cased).
    """
    core = re.sub(r"[_\-\.]", "", word)
    if not core:
        return word
    return (core[0].upper() + core[1:].lower()).translate(_LEET)


def _extract_suffix_tail(pw: str) -> str | None:
    """The tail after the LAST ``#`` or ``!`` — often ``#Acme2025``."""
    m = re.search(r"[#!][A-Za-z0-9]{4,}$", pw)
    return m.group(0) if m else None


def _extract_year(pw: str) -> str | None:
    """First 20xx / 19xx four-digit year found in the password."""
    m = re.search(r"(19|20)\d{2}", pw)
    return m.group(0) if m else None


def _extract_role_token(pw: str, username: str) -> str | None:
    """A canonical role word from the password (``Svc``, ``Adm``, ...) —
    only matched when it also appears in the username."""
    uname_l = username.lower()
    for key, canonical in _ROLES.items():
        if key in uname_l and re.search(canonical, pw):
            return canonical
    return None


def _target_role_for(username: str) -> str | None:
    """Which role token to substitute for a candidate username."""
    uname_l = username.lower()
    for key, canonical in _ROLES.items():
        if key in uname_l:
            return canonical
    return None


def _generate_from(cred_identifier: str, cred_secret: str,
                   target_username: str) -> list[Candidate]:
    """The template engine. Given one known cred, produce candidates for one
    target username.
    """
    if not cred_secret:
        return []
    out: list[Candidate] = []
    suffix = _extract_suffix_tail(cred_secret)
    year = _extract_year(cred_secret)
    source_role = _extract_role_token(cred_secret, cred_identifier)
    target_role = _target_role_for(target_username)

    # 1) Role swap: replace source_role with target_role in the whole password.
    if source_role and target_role and source_role != target_role:
        out.append(Candidate(
            username=target_username,
            password=cred_secret.replace(source_role, target_role),
            source_cred=cred_identifier,
            reason=f"role-swap {source_role}->{target_role}",
        ))

    # 2) Prefix-leet swap: replace the leet-of-source-username at the start
    #    of the password with the leet-of-target-username.
    src_leet = _leet(cred_identifier.split("_")[-1])
    tgt_leet = _leet(target_username.split("_")[-1])
    if src_leet and tgt_leet and src_leet != tgt_leet and cred_secret.startswith(src_leet):
        out.append(Candidate(
            username=target_username,
            password=tgt_leet + cred_secret[len(src_leet):],
            source_cred=cred_identifier,
            reason=f"prefix-leet {src_leet}->{tgt_leet}",
        ))

    # 3) Both together: role-swap AND prefix-leet.
    if source_role and target_role and source_role != target_role:
        candidate = cred_secret.replace(source_role, target_role)
        if src_leet and tgt_leet and src_leet != tgt_leet and candidate.startswith(src_leet):
            out.append(Candidate(
                username=target_username,
                password=tgt_leet + candidate[len(src_leet):],
                source_cred=cred_identifier,
                reason=f"role+leet {source_role}->{target_role}, {src_leet}->{tgt_leet}",
            ))

    # 4) Year rotation: same password with year+1.
    if year:
        next_year = str(int(year) + 1)
        out.append(Candidate(
            username=target_username,
            password=cred_secret.replace(year, next_year),
            source_cred=cred_identifier,
            reason=f"year-rotate {year}->{next_year}",
        ))

    # 5) Suffix reuse: minimal template — target's-name-leet + suffix.
    if suffix and tgt_leet:
        out.append(Candidate(
            username=target_username,
            password=f"{tgt_leet}{suffix}",
            source_cred=cred_identifier,
            reason=f"suffix reuse {suffix!r}",
        ))

    return out


def derive_candidates(
    vault_rows: Iterable[dict],
    *,
    targets: Iterable[str] | None = None,
) -> list[Candidate]:
    """Generate spray candidates for missing service accounts.

    ``vault_rows`` should have ``identifier`` and ``secret`` keys (any dict
    or sqlite3.Row works). ``targets`` overrides the built-in service-user
    list — omit it for the default sweep.

    Deduplicated by (username, password). Ordered by source cred, then by
    reason, so the operator sees a consistent list.
    """
    target_names = list(targets) if targets is not None else list(_COMMON_SVC_USERS)
    vault_list = list(vault_rows)
    known_ids = {r["identifier"] for r in vault_list}

    seen: set[tuple[str, str]] = set()
    out: list[Candidate] = []
    for row in vault_list:
        secret = row["secret"] or ""
        cred_id = row["identifier"]
        for target in target_names:
            if target in known_ids:
                # We already have this user's cred — skip generation.
                continue
            for cand in _generate_from(cred_id, secret, target):
                key = (cand.username, cand.password)
                if key in seen:
                    continue
                seen.add(key)
                out.append(cand)
    return out
