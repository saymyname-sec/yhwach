# Actions

Actions are the executable primitives that playbook rules reference by id (a rule's `emits:`
list). There are two kinds:

1. **Inline registry actions** — the common case. Defined in
   [`yhwach/actions.py`](../yhwach/actions.py) as entries in `ACTION_REGISTRY` (95 today).
   Each maps an id to one or more command templates.
2. **Standalone exploit scripts** — heavier, self-contained programs kept in this directory
   (e.g. [`activemq_openwire_rce.py`](activemq_openwire_rce.py) for CVE-2023-46604). These carry
   a header block and are run by the operator, not auto-executed.

List the registry from the CLI:

```bash
yhwach actions                    # all
yhwach actions --risk read_only   # filter by tier
```

## Inline registry actions

Each entry is an `Action(id, commands, risk, runnable, outputs, note)`:

- **`commands`** use `string.Template` `$VARS` (not `str.format`, so JSON payload braces need no
  escaping). Context vars: `$IP $PORT $SCHEME $URL $ENDPOINT $MODEL`, plus `$OSAI` for the
  operator's OSAI script dir.
- **`risk`** — `read_only` | `propose` | `destructive`.
- **`runnable`** — `False` means render-only even if read-only (needs external files/wordlists/
  setup).
- **`outputs`** — parser hint (`nmap` | `http` | `winpeas` | `linpeas` | `raw`) for finding
  extraction.

### Execution policy — Yhwach proposes, the operator executes

- `read_only` **and** `runnable` → Yhwach may run it under `yhwach run --task N --go`; output is
  captured to `loot/` and passed to deterministic finding extraction.
- `propose` / `destructive`, or anything render-only → **printed only**. The operator runs it
  with judgment.

Adding an inline action = adding an entry to `ACTION_REGISTRY`, keyed by the id the playbook rule
emits. Every action id referenced by `playbooks/*.yaml` must have an entry.

## Standalone exploit scripts

Scripts in this directory carry a header block so their provenance and contract are explicit:

```python
# yhwach-action: <id>
# yhwach-inputs: <comma-separated arg names>
# yhwach-outputs: <parser_kind>          # nmap | http | winpeas | linpeas | raw
# authorized_only: true
```

These are exploitation-tier and self-contained; the operator invokes them directly (they are not
run by `yhwach run`). `activemq_openwire_rce.py` is the reference example — self-learned from the
Iron Crown challenge lab, with its OPSEC/routing caveats documented in the module docstring.

## Authorization

Every action serves rules that are `authorized_only: true`. Do not add actions, payloads, or
example targets that reference production systems or unauthorized engagements. See
[../AUTHORIZATION.md](../AUTHORIZATION.md).
