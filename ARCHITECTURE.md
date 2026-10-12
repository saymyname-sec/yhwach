# Architecture

Yhwach is an **advisor with a memory**, not an autonomous agent. It never calls a
model. The supported way to run it is as an **MCP server** (`yhwach mcp`) that an
MCP client — [Claude Code](https://docs.claude.com/en/docs/claude-code) or
[Codex CLI](https://github.com/openai/codex) — drives. **The client is the brain;
yhwach is the world model, the recall menu, and the safety gate it reasons over.**
Yhwach itself needs **no API key**.

> There is also a legacy, **experimental** runtime where yhwach calls a model itself
> (`yhwach run`, the `[agent]` extra). It is unsupported and slated for removal — see
> [`docs/experimental/`](docs/experimental/). Everything below describes the supported
> advisor picture. (`AGENT.md` has long-form design history, but describes the
> removed self-driving runtime — this file is the current source of truth.)

## The one big idea

Prose can't be queried. Yhwach makes the engagement **queryable**: a **SQLite world
model is the single source of truth**, deterministic Python advances and gates it,
and the LLM (your MCP client) is used only for judgment — rank a move, craft a
payload, interpret output — never for bookkeeping. **A fact isn't real until it's a
typed row.** Your chat history is not the record; the DB is. After a `/clear` or a
handover, `yhwach_status` then `yhwach_brief` replay the engagement from the rows.

## The parts

```
MEMORY     the yhwach core — world model (hosts/services/findings/creds/evidence),
           the attempt ledger, the recall brief, and the engagement ledgers
           (notice · activity · artifact · submission)
KNOWLEDGE  a matcher-only recall MENU (playbooks/*.yaml via knowledge.py) — it
           surfaces every applicable technique per host; the client ranks
SAFETY     typed scope (one assert_target chokepoint) · record-only by default ·
           arm/disarm as a human CLI act (never an MCP arg) · spray policy
TOOLS      nmap · HexStrike · probes · ingestion parsers — output routed into rows
UI         a read-only board over memory (localhost only; never binds 0.0.0.0)
```

The MCP client orients, reasons, acts, and **folds the result back** each turn:

**`yhwach_brief` / `yhwach_path` / `yhwach_gaps` → reason → act → `yhwach_interpret`/`yhwach_attempt` → repeat.**

## Deterministic where it must be

The host FSM
(`undiscovered → scanned → enumerated → foothold → looted → pivoted → done`),
chaining (`findings_include`), the safety tiers (`read_only` runs; everything else
is gated and, outside a lab/ctf, requires an explicit `yhwach arm`), scope
enforcement (exclude-wins, empty scope refuses), coverage (`service_enum` /
scan-coverage gaps), and credential spray policy (dumped hashes and cracked
passwords are `manual` and are **never** swept) are all deterministic Python. The
client is trusted for judgment, not for the invariants.

## Knowledge = a recall menu, not a ranker

The technique catalog (`playbooks/*.yaml`, matched by `yhwach/knowledge.py`) is a
**matcher-only recall menu**: it surfaces *every* applicable technique for a host so
the client selects from a complete menu. The old EV **ranker** was removed in
`7ebc4e0`; its knowledge was kept, its scalar ranking was not — the client ranks now.
Each surfaced technique can carry an **actionable emit** (`data/actions.yaml`): a
ready command with `$YH_SECRET` placeholders (never a secret at the wire) and a
fold-back hint (`yhwach_interpret kind=x:<id>`).

Offline knowledge feeds (bundled, no network needed on an engagement host): the
playbook rules, the CVE map (`yhwach vulns`), and the `yhwach ref` packs
(default-creds, AD CS ESC1–16, gtfobins, lolbas, wadcoms, lessons, plus the service
matrix and tag registry). Every discovered service owes a triage pass, enforced
advisorily by the `service_enum` coverage gap; `yhwach audit` reports coverage by
standard (ATT&CK / OWASP-LLM / ATLAS / CWE / CVE).

## Running it

Register yhwach as an MCP server and let the client be the brain:

```bash
YHWACH_DB=$YHWACH_DATA_DIR/state/yhwach.db claude mcp add yhwach -- yhwach mcp
```

The same memory is reachable from the CLI (`yhwach brief`, `yhwach status`, …) for
scripting and smoke tests. See the [README](README.md) for the full picture and
[docs/setup.md](docs/setup.md) for machine prep.
