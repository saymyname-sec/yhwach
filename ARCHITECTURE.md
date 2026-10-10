# Architecture

> **The architecture lives in [`AGENT.md`](AGENT.md)** — it is the source of truth
> for how yhwach is built (the five parts, the memory invariant, the runtime, the
> knowledge model). This file is a short orientation; read `AGENT.md` for depth.

## The one big idea

Prose can't be queried. Yhwach makes the engagement queryable: a **SQLite world
model is the single source of truth**, deterministic Python advances and gates it,
and the LLM is used only for judgment (rank a move, craft a payload, interpret
output) — never for bookkeeping. A fact isn't real until it's a typed row.

## The five parts (see AGENT.md)

```
ORCHESTRATOR  the control loop — turn cycle, budgets, dispatch, gating, halting
BRAIN         the LLM in a loop — a doer (picks moves) + a separate judge (phase done?)
MEMORY        the yhwach core — world model + attempt ledger + recall brief + notebook
TOOLS         nmap · HexStrike · probes · a gated shell — output routed through parsers
UI            a read view over memory + a kill/approve control channel (DB-mediated)
```

Deterministic where it must be — the host FSM
(`undiscovered → scanned → enumerated → foothold → looted → pivoted → done`),
chaining (`findings_include`), safety tiers (`read_only` vs. gated), and coverage
(`service_enum` / scan-coverage gaps). Model-driven where it pays.

## Knowledge = a recall menu, not a ranker

The technique catalog (`playbooks/*.yaml`, matched by `yhwach/knowledge.py`) is a
**matcher-only recall menu**: it surfaces *every* applicable technique for a host so
the brain selects from a complete menu. The old EV **ranker** ("the decider":
`planner.py`, the `plan` / `selftest` commands) was removed in `7ebc4e0`; its
knowledge was kept, its scalar ranking was not — the brain does the ranking now.

Offline knowledge feeds (bundled, no network needed on an engagement host): the playbook
rules, the CVE map (`yhwach vulns`), and the `yhwach ref` packs (default-creds,
AD CS ESC1–16, gtfobins, lolbas, wadcoms, lessons, plus the service matrix and
tag registry). Every discovered service also owes a triage pass, enforced advisorily
by the `service_enum` coverage gap, and `yhwach audit` reports coverage by standard
(ATT&CK / OWASP-LLM / ATLAS / CWE / CVE).

## Running it

Two modes (see the [README](README.md#two-ways-to-run-it)): **Claude Code over MCP —
no API key** (`yhwach mcp`; the CLI session is the operator, yhwach never calls a
model), or **self-driving `yhwach run` — with an API key** (yhwach's own brain
drives the loop; read-only auto, exploit gated). The self-driving brain calls the
model through a provider adapter — Anthropic (`ANTHROPIC_API_KEY`) by default or
OpenAI (`OPENAI_API_KEY`) via `--provider openai`, chosen at runtime. Every audit
event is stamped with the persona + rule-set hash for replay.
