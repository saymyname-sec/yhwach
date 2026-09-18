# Architecture

## The one big idea

Prose can't be queried. Yhwach makes the engagement queryable: a SQLite world model is the single source of truth, a Python engine advances it deterministically, and the LLM operator is called only for judgment — never for bookkeeping.

## Layers

```
+---------------------------------------------------------------------+
| Presentation    report . MCP server . status  (notebook -> Obsidian) |
+---------------------------------------------------------------------+
| Handoff         context block (persona + state + candidates)         |
+---------------------------------------------------------------------+
| Memory          attempt ledger . scan coverage . recall brief        |
+---------------------------------------------------------------------+
| Planning        rule engine . playbooks . EV ranker . autonomy tier  |
+---------------------------------------------------------------------+
| Judgment        the operator (host LLM) reasons over the handoff     |
+---------------------------------------------------------------------+
| Execution       nmap . HexStrike (REST) . local subprocess           |
+---------------------------------------------------------------------+
| Ingestion       parsers -> typed observations + chaining tags        |
+---------------------------------------------------------------------+
| Domain          SQLite world model + strict schemas                  |
+---------------------------------------------------------------------+
```

The **Memory** layer is what the handoff reads back: the attempt ledger tells the
Planning layer which moves are already burned (and decays their EV), and the
recall brief re-seeds an operator whose own context was lost.

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

Other transitions are operator-driven (`yhwach advance`).

`scanned -> enumerated` has a third, **advisory** predicate:
`has_full_tcp AND has_versions AND udp_top100_done`. The `scan_coverage` table
records what each ingested nmap run actually covered (port range, `-sV`, UDP)
rather than only what it found, so the engine can evaluate it — `yhwach gaps`
names every host that fails it and prints the scan that closes the gap, the
handoff carries an ENUM GAPS block, and `advance --to enumerated` warns.

It warns rather than refuses on purpose: scans legitimately arrive out of band
(an operator-run nmap that was never ingested, a HexStrike run mid-flight), and a
hard refusal there would strand a real engagement on a bookkeeping technicality.
The two predicates that decide *points* — `looted` needs proof, `pivoted` needs a
tunnel — stay hard gates.

## The operator loop

Yhwach is not a headless runner; the operator drives it turn by turn. Each cycle:

```text
yhwach recall               # engine: catch-up brief (only after a context reset / new session)
yhwach next --contract      # engine: emit the handoff (persona + state + dead ends + candidates)
   -> operator (host LLM) reasons over it, picks the move
yhwach run --task N --go    # engine: run read-only actions, extract findings + chaining tags
   -> operator runs proposal/exploit steps by hand, writes the Obsidian note
yhwach outcome --task N --result <r> --why '<line>'     # close the loop: what happened
yhwach ingest / probe / advance / proof / pivot / cred   # feed results back
yhwach plan                 # re-rank from the advanced world model (+ EV decay from failures)
```

The `outcome` step is what makes the loop *converge*. Without it the queue only ever grows: a move
the operator tried and abandoned stays `pending`, returns to the top of the next handoff, and a
model whose context has been compacted re-proposes it. `outcome` is also the only signal the engine
has that a technique landed — it consumes the technique automatically on `success`.

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
- **`high_ev_leads`** — findings whose tag historically yields a credential/DA path (dcsync, kerberoastable, adcs_vuln, chrome/DPAPI/GPP/AWS loot) are surfaced as a **P0 LEADS** block above the ranked queue (`primitives.p0_leads`).
- **`attempt_ledger`** — the negative half of `technique_exhaustion`. `yhwach outcome` appends every
  resolved move (success / fail / blocked / partial) with a one-line reason. Success consumes the
  technique and closes the task; fail/blocked retire the task, halve that rule's EV on that host at
  the next `plan` (recomputed, never a persisted mutation), and surface in the handoff's **DEAD
  ENDS** block. This is the engine's memory of what the operator already burned — the one thing a
  compacted LLM context cannot reconstruct.
- **`scan_coverage`** — what was *scanned*, not what was found. Makes the under-enumeration
  invariant queryable (`yhwach gaps`); see the FSM section above.
- **`engagement_notebook`** — reaching an objective always takes a note (Kapi's rule). The notebook is an **Obsidian vault**, written by the operator through the Obsidian MCP in full detail (commands, payloads, evidence), and it is the single source of truth for write-ups. Yhwach's DB is the queryable world model and never stores notes; `advance`/`cred` print a reminder, the persona (`persona/notebook.md`) carries the structure. See [persona/notebook.md](persona/notebook.md).

## Attack-surface model (schema v1)

The world model started as *what listens* (host / service / surface). Schema v1
extends it to *what the next attack path is*, without changing the engine's
shape:

- **software / vulnerability** — versioned components (listening *and* post-foothold:
  kernel, sudo, CMS) with CPE, and version→CVE hypotheses carrying a lifecycle
  (`potential → confirmed → exploited`) plus exploit refs.
- **principal / membership / privilege / edge** — the AD identity graph. `edge`
  addresses nodes as `principal:<id>` / `host:<id>`; `db.shortest_path` (a plain
  BFS, exposed as `yhwach path`) answers "route from what I own → Domain Admins".
- **web_app / web_path / domain** — the web surface: tech stack, discovered
  dirs/params, vhosts.
- **host_interface / loot / share / password_policy / objective** — the per-host
  "note everything" layer (multi-homing, files, SMB/NFS access, lockout policy that
  gates safe spraying, point-bearing goals).

Two design rules keep this from bloating the engine:

1. **Tables are the record; findings are the trigger.** New facts are inserted as
   rows, but where a fact should drive the next move an ingest path *also* emits a
   tagged `finding` (`smb_signing_off`, `domain_users`, `admin_access`,
   `writable_share`, …), so the existing `findings_include` planner chaining picks
   it up with no new matcher.
2. **DB drives the notebook.** `yhwach export-notes` regenerates the vault's
   structured tables (and per-host notes) from these rows inside
   `<!-- yhwach:auto -->` fences; the operator writes only prose. The DB stays the
   single source of truth for facts, the vault for the write-up.

## Knowledge (declarative, offline)

Yhwach's knowledge is data, not code — four feeds, all bundled so an exam host
needs no network:

- **Playbook rules** (`playbooks/*.yaml`) — the technique catalog. schema-v1 facts
  are activated by rules in `lateral.yaml` (writable_share, admin_access),
  `web.yaml` (web_login/upload/git/api/backup), and `cve.yaml` (exploitable_cve).
- **CVE knowledge base** (`data/cve_map.yaml`) — a curated CPE/version→CVE map.
  `yhwach vulns` (yhwach/vulns.py) matches `software` rows offline, records
  `vulnerability` rows, and emits `exploitable_cve` findings for the exploit rule.
  Curated, not a blanket feed, so a match is a lead not noise.
- **Reference packs** (`data/{default_creds,adcs_esc,gtfobins}.yaml`) — lookups the
  operator queries with `yhwach ref`; also referenced from the login/privesc actions.
- **Attack graph in the brief** — `yhwach next` renders the shortest `edge` path from
  an owned node (foothold+ host, or a principal we hold a credential for) to
  Domain/Enterprise Admins, so the goal is visible alongside the ranked candidates.

## Independence from host CLI

Yhwach's persona is a strict system prompt bundled with the engine (`persona/operator.md`) and travels inside the `yhwach next --contract` handoff. Whatever CLI, host, or client the operator runs on, Yhwach's frame is what shapes the reasoning — the host is just a shell.

Determinism:

- `yhwach persona` prints the exact persona in effect plus its SHA-256 — proof of which frame shaped a judgment.
- The planner is fully deterministic (no model): the golden fixtures (`yhwach selftest`) lock its ranking. Change a rule or the persona and rebaseline the fixtures by hand.
- Note: the `event` table reserves `persona_hash` / `rules_hash` columns and a replay/regression story, but the engine does not populate or replay them today — that's a future item, not a shipped guarantee.
