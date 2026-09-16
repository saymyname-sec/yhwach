# Architecture

## The one big idea

Prose can't be queried. Yhwach makes the engagement queryable: a SQLite world model is the single source of truth, a Python engine advances it deterministically, and the LLM operator is called only for judgment — never for bookkeeping.

## Layers

```
+-------------------------------------------------------------+
| Presentation    report render . Obsidian sync . TUI status  |
+-------------------------------------------------------------+
| Orchestration   the loop . autonomy gates (proceed/propose/ask) |
+-------------------------------------------------------------+
| Planning        rule engine . playbooks . EV ranker         |
+-------------------------------------------------------------+
| Judgment        LLM calls (RANK / CRAFT / INTERPRET)        |
+-------------------------------------------------------------+
| Execution       tool adapters (nmap, HexStrike MCP, msf MCP)|
+-------------------------------------------------------------+
| Ingestion       parsers -> typed observations               |
+-------------------------------------------------------------+
| Domain          SQLite world model + strict schemas         |
+-------------------------------------------------------------+
```

Each layer is unit-testable in isolation.

## Host state machine

```
undiscovered -> scanned -> enumerated -> foothold -> looted -> pivoted -> done
```

Each transition has an **entry predicate** (a SQL check) and an **exit action**. The engine refuses to advance a host until its predicate is met.

Examples:

- `scanned -> enumerated`: `has_full_tcp AND has_versions AND udp_top100_done`.
- `foothold -> looted`: `screenshot_exists FOR host.proof_row AND creds_dumped_to_vault`.
- `looted -> pivoted`: `ligolo_tunnel_up OR new_subnet_reachable`.

Under-enumeration — the top failure mode in OSAI engagements — becomes a data invariant, not a habit.

## The loop

```python
while engine.has_open_tasks():
    task = planner.next()                    # deterministic EV rank from state
    if task.autonomy == "proceed":           # read-only, recon
        result = executor.run(task)
    elif task.autonomy == "propose":         # exploitation
        result = propose_and_run(task)       # emits Autonomy Contract, acts on go
    else:                                    # ask
        result = ask_operator(task)          # scope edges, destructive
    observations = ingest(result)            # parsers -> typed rows
    engine.apply(observations)               # world model advances
    render.sync()                            # Obsidian + report
```

## LLM call shapes

Three, and only three:

- **RANK(state_slice, hypotheses) -> ordered_list_with_rationale**
- **CRAFT(target_context, technique) -> structured_payload**
- **INTERPRET(raw_output, expected_signals) -> typed_finding_or_null**

Every call:

- receives Yhwach's persona as system prompt (see `persona/operator.md`)
- receives only the SQL-selected slice of state relevant to the call
- must return output matching the JSON contract (see `persona/contract.md`)
- is logged to `event` with input hash + output for replay and regression testing

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
- **`high_ev_leads`** — Chrome DPAPI, KeePass, unattend.xml, PS history: seen -> auto-P0.
- **`lore_denylist`** — known OffSec dev artifacts (cloudbase-init and friends) tagged and filtered from ranker output.

## Independence from host CLI

Yhwach's persona is a strict system prompt bundled with the engine (`persona/operator.md`). Whatever CLI, host, or client executes the LLM call, Yhwach's frame overrides the host's own personality. The operator persona is the deterministic contract; the host is just a shell.

Determinism knobs:

- Persona file is content-hashed. A persona change flags all determinism tests for rebaseline.
- Playbook rules are content-hashed. Changing a rule flags dependent fixtures.
- LLM call inputs are hashed. Same-hash call may replay from cache during test runs.
