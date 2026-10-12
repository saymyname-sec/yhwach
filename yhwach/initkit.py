"""G6b — `yhwach init --kind K`: the two things an operator needs to wire a new
engagement to an MCP client.

1. **MCP registration** with absolute paths — the `claude mcp add` line and the
   settings.json block, with the DB path resolved so copy-paste just works.
2. A **per-kind instruction fragment** (`CLAUDE.md` / `AGENTS.md`) that frames how
   the client should behave for *this* kind of engagement. A bounty is not a CTF:
   posture, stealth, scope discipline and the objective all differ. This replaces
   the old one-size exam-doctrine global router.

Pure and unit-testable; the CLI resolves paths and does the file I/O.
"""
from __future__ import annotations

import json
import os
import shutil

from yhwach.db import ENGAGEMENT_KINDS, default_active_mode

# Per-kind posture. `armed` here is only the *default* — arming is always a
# deliberate `yhwach arm` in a terminal, never something the client can do.
_PROFILE: dict[str, dict[str, str]] = {
    "lab": {
        "stealth": "Speed over stealth — this is practice. Own every host.",
        "objective": "Foothold → loot → pivot → domain. Proof is the deliverable.",
        "scope": "the lab CIDR(s) you passed to `yhwach engage`",
    },
    "ctf": {
        "stealth": "Speed over stealth — capture objectives fast; screenshot each win.",
        "objective": "Flags / scored objectives. The standalone AI host has no prereqs.",
        "scope": "the target box(es)",
    },
    "internal": {
        "stealth": "Stealth matters — AD lockout, EDR and logging are live. Prefer "
                   "low-and-slow; never a spray storm (dumped/cracked creds are "
                   "`manual` and are never swept — spray one named cred deliberately).",
        "objective": "A path to the crown jewels via VALIDATED access; build the "
                      "credential-reuse graph (`yhwach_reuse`) as you go.",
        "scope": "exactly the internal ranges on the SOW — nothing else",
    },
    "external": {
        "stealth": "You are on the public internet — rate-limit, no noisy scanning, "
                   "respect the testing window.",
        "objective": "A foothold from the perimeter; move internal only if the SOW "
                      "scopes it.",
        "scope": "the external IPs/domains on the SOW",
    },
    "web": {
        "stealth": "App-layer only — no host lateral movement. Captured traffic is "
                   "metadata only (method/param-names/auth/status), never bodies.",
        "objective": "Authorization / IDOR / injection chains on the in-scope app. "
                      "Use the authz matrix (`yhwach_authz`); an unobserved cell is "
                      "not a denial.",
        "scope": "the app origin(s) and API — not the whole host",
    },
    "cloud": {
        "stealth": "Enumerate with least noise. A role or principal NAME is not a "
                   "permission — validate the grant before claiming it.",
        "objective": "Privilege/paths from validated grants only. Tenant-abuse "
                      "techniques stay gated behind `cloud_tenant_in_scope`.",
        "scope": "the account / subscription / tenant on the SOW",
    },
    "redteam": {
        "stealth": "OPSEC is the objective — assume the full detection stack. Prefer "
                   "signed/native binaries, minimise footprint, no spray storms. "
                   "Record every artifact you drop so cleanup is complete.",
        "objective": "The agreed flag/impact with the fewest, quietest moves. Track "
                      "plants and artifacts for teardown (`yhwach_artifact`/`_plant`).",
        "scope": "the SOW ranges plus the rules of engagement",
    },
    "bounty": {
        "stealth": "Stay strictly in program scope. No DoS, rate-limit, metadata-only "
                   "capture. Out-of-scope assets are forbidden, not just discouraged.",
        "objective": "Reproducible, in-scope findings. Check "
                      "`yhwach_submission` duplicate-risk before you report.",
        "scope": "exactly the program's in-scope assets",
    },
    "retest": {
        "stealth": "Touch only the previously-reported findings; confirm-only, minimal "
                   "actions. No new exploitation beyond the original scope.",
        "objective": "Confirm each prior finding is fixed or still open. Nothing new.",
        "scope": "the assets from the original report",
    },
}


def mcp_registration(db_path: str | os.PathLike, *, server_name: str = "yhwach") -> dict:
    """The MCP server registration for this DB, with an absolute DB path.

    Returns {add_command, config} — a ready `claude mcp add …` line and the
    equivalent settings.json `mcpServers` block.
    """
    abs_db = os.path.abspath(str(db_path))
    yhwach_bin = shutil.which("yhwach") or "yhwach"
    add_command = (
        f"YHWACH_DB={abs_db} claude mcp add {server_name} -- {yhwach_bin} mcp"
    )
    config = {
        "mcpServers": {
            server_name: {
                "command": yhwach_bin,
                "args": ["mcp"],
                "env": {"YHWACH_DB": abs_db},
            }
        }
    }
    return {"add_command": add_command, "config": config}


def instruction_fragment(kind: str | None) -> str:
    """The per-kind CLAUDE.md/AGENTS.md body (Markdown)."""
    k = kind or "lab"
    if k not in _PROFILE:
        raise ValueError(f"unknown kind {kind!r}; expected one of {ENGAGEMENT_KINDS}")
    p = _PROFILE[k]
    posture = default_active_mode(k)
    posture_line = (
        "This kind starts **armed** (active tools send traffic as soon as you act)."
        if posture == "armed" else
        "This kind starts **record-only**: scan/enum/probe/spray are refused until a "
        "human runs `yhwach arm`. You cannot arm it — ask the operator to."
    )
    return f"""\
# Engagement instructions — kind: {k}

Yhwach is the memory and the safety gate; **you are the brain**. It never calls a
model and holds the only record — your chat history is not the record, the DB is.

## Each turn
`yhwach_status` → `yhwach_brief` (map + leads + the full recall menu) → reason →
act → fold the result back (`yhwach_interpret` for tool output, `yhwach_attempt`
for a tried move) → repeat. After a `/clear`, run `yhwach_status` first.

## Posture for this kind
{posture_line}

- **Scope:** {p['scope']}. Every active move passes one scope chokepoint
  (exclude-wins); an empty scope refuses everything.
- **Stealth / conduct:** {p['stealth']}
- **Objective:** {p['objective']}

## Invariants (enforced in Python, not up to you)
- Dumped hashes and cracked passwords are `manual` and are never swept — spray only
  a named credential, deliberately.
- Captured web traffic is metadata only; never store request/response bodies.
- Canaries are neutral; the operator's verdict on a payload is the fact of record.
- The board is local-only and never binds `0.0.0.0`.
"""


def render(kind: str | None, db_path: str | os.PathLike, *, agents: bool = False) -> dict:
    """Everything `yhwach init` prints: the filename, the fragment, and the
    registration (as text + JSON)."""
    reg = mcp_registration(db_path)
    return {
        "filename": "AGENTS.md" if agents else "CLAUDE.md",
        "fragment": instruction_fragment(kind),
        "add_command": reg["add_command"],
        "config_json": json.dumps(reg["config"], indent=2),
    }
