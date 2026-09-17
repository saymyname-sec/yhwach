# Architecture

## The one big idea

Prose can't be queried. Yhwach makes the engagement queryable: a SQLite world model is the single source of truth, a Python engine advances it deterministically, and the LLM operator is called only for judgment — never for bookkeeping.

## Layers

```
+-------------------------------------------------------------------+
| Presentation    report . MCP server . status  (notebook -> Obsidian, operator) |
+-------------------------------------------------------------------+
| Handoff         context block (persona + state + candidates + commands) |
+-------------------------------------------------------------------+
| Planning        rule engine . playbooks . EV ranker . autonomy tier |
+-------------------------------------------------------------------+
| Judgment        the operator (host LLM) reasons over the handoff  |
+-------------------------------------------------------------------+
| Execution       nmap . HexStrike (REST) . local subprocess        |
+-------------------------------------------------------------------+
| Ingestion       parsers -> typed observations + chaining tags     |
+-------------------------------------------------------------------+
| Domain          SQLite world model + strict schemas               |
+-------------------------------------------------------------------+
```

Each engine layer is unit-testable in isolation. **The Judgment layer is not
Yhwach code** — Yhwach never calls a model. It emits the handoff (`yhwach next
--contract`) and the operator (Claude Code on Kali) reasons over it and acts
back through the CLI / MCP tools. The persona travels in the handoff so the
reasoning frame is Yhwach's, not the host CLI's.

## Host state machine

```
undiscovered -> scanned -> enumerated -> foothold -> looted -> pivoted -> done
```

Stage order is **monotonic** — the engine refuses to move a host backwards
(except to `blocked`, and `advance --force` overrides). Two transitions carry an
**enforced entry predicate** today:

- `foothold -> looted`: refused without a `proof` row that has a screenshot
  (`yhwach proof`).
- `looted -> pivoted`: refused without a `tunnel` / reachable subnet via that
  host (`yhwach pivot`).

Other transitions are operator-driven (`yhwach advance`) — the richer predicates
below are the design target, not yet enforced (Phase 6):

- `scanned -> enumerated`: `has_full_tcp AND has_versions AND udp_top100_done`.

Under-enumeration — the top failure mode in OSAI engagements — is the invariant
these predicates are meant to make structural.

## The operator loop

Yhwach is not a headless runner; the operator drives it turn by turn. Each cycle:

```text
yhwach next --contract      # engine: emit the handoff (persona + state + candidates + commands)
   -> operator (host LLM) reasons over it, picks the move
yhwach run --task N --go    # engine: run read-only actions, extract findings + chaining tags
   -> operator runs proposal/exploit steps by hand, writes the Obsidian note
yhwach ingest / probe / advance / proof / pivot / cred   # feed results back
yhwach plan                 # re-rank from the advanced world model
```

Read-only recon runs itself; exploitation is render-only (Yhwach proposes, the
operator executes). The `autonomy` tier on each task (proceed / propose / ask)
tells the operator which is which.

## Judgment shapes (operator-side, not engine calls)

The operator's reasoning takes three shapes, described by `persona/operator.md`
and `persona/contract.md`:

- **RANK(state slice, candidates) -> ordered list with rationale**
- **CRAFT(target, technique) -> a concrete payload**
- **INTERPRET(raw output, expected signals) -> a typed finding, or none**

These are the *operator's* contract, not typed calls Yhwach makes — Yhwach emits
the handoff and reads back structured results through its CLI/MCP tools. The one
piece that runs in the engine is the **deterministic half of INTERPRET**:
`interpret.py` turns unambiguous tool output (an Ollama model list, a Kerberoast
hash, `signing:False`) into `finding` rows + chaining tags with no model
involved. Ambiguous judgment stays the operator's.

## Rules — playbooks as data

Knowledge is declarative YAML, not prose. Adding a technique = adding a rule.

```yaml
- id: ollama_unauth_generate
  when:   { surface: ollama, auth: none }
  emits:
    - action: probe_ollama_models
  maps:   [LLM06]
  points: 15
  risk:   read_only
  routes: /osai-mcp-attack
  source: osai/07 . README:AI-ports
  authorized_only: true
```

## Cross-cutting primitives

- **`technique_exhaustion`** — a technique that succeeds is marked consumed for the engagement; the ranker won't resurface it (OSAI labs do not reuse infra flaws twice).
- **`credential_reuse`** — the one thing that is *never* exhausted; every recovered credential stays in play against every host in scope.
- **`lore_denylist`** — known OffSec dev artifacts (cloudbase-init and friends) tagged and filtered from ranker output.
- **`findings_include` chaining** — a finding carries a `tag` (set by the interpret extractors / ingest parsers); a rule with `findings_include: <tag>` fires only once a host carries it. This is how post-foothold + AD chains (kerberoast, DCSync, ADCS, chrome/DPAPI loot) light up.
- (Declared in `_primitives.yaml`, not yet code: `high_ev_leads` auto-P0 for Chrome DPAPI / KeePass / unattend.xml, and the OPSEC invariants — Phase 6.)
- **`engagement_notebook`** — reaching an objective always takes a note (Kapi's rule). The notebook is an **Obsidian vault**, written by the operator through the Obsidian MCP in full detail (commands, payloads, evidence), and it is the single source of truth for write-ups. Yhwach's DB is the queryable world model and never stores notes; `advance`/`cred` print a reminder, the persona (`persona/notebook.md`) carries the structure. See [persona/notebook.md](persona/notebook.md).

## Independence from host CLI

Yhwach's persona is a strict system prompt bundled with the engine (`persona/operator.md`) and travels inside the `yhwach next --contract` handoff. Whatever CLI, host, or client the operator runs on, Yhwach's frame is what shapes the reasoning — the host is just a shell.

Determinism:

- `yhwach persona` prints the exact persona in effect plus its SHA-256 — proof of which frame shaped a judgment.
- The planner is fully deterministic (no model): the golden fixtures (`yhwach selftest`) lock its ranking. Change a rule or the persona and rebaseline the fixtures by hand.
- Note: the `event` table reserves `persona_hash` / `rules_hash` columns and a replay/regression story, but the engine does not populate or replay them today — that's a future item, not a shipped guarantee.
