# Agent Architecture

> **Status: target-state blueprint.** This describes the agent yhwach is becoming,
> not (yet) what the code does. Where it disagrees with `README.md` or
> `ARCHITECTURE.md`, this document wins — those still describe the deleted
> ranker engine (see [History](#history-what-changed-and-why)).

## The pivot in one line

**yhwach is the memory of an autonomous red-team agent.** It used to be a
deterministic ranker engine that a human drove turn by turn. It is becoming an
AI agent that drives itself, with the old world model demoted to its memory
core and the AI — not a scalar ranker — making the decisions.

## The five parts

```
+-------------------------------------------------------------------+
|  ORCHESTRATOR   the control loop (deterministic Python)           |
|  owns: turn cycle, budgets, dispatch, gating, halting             |
+----------------+--------------------------------+-----------------+
                 | builds context v      ^ writes results
+----------------+-----------+  +---------+-----------------------+
|  BRAIN (doer + judge)      |  |  MEMORY  = yhwach core          |
|  reasons over the brief,   |  |  world model + attempt ledger + |
|  picks moves, rules "done" |  |  recall + notebook (walled)     |
+----------------+-----------+  +---------------------------------+
                 | actions v
+----------------+--------------------------------------------------+
|  TOOLS / EXECUTORS   nmap . HexStrike . probes . gated shell      |
|  workers (sub-agents) fan out here, each with a memory slice      |
+-------------------------------------------------------------------+
        UI reads memory (a view) and writes control (kill/approve)
```

1. **Orchestrator** — the piece that did not exist before (the human was it).
   Deterministic. Owns the loop, budgets, worker dispatch, autonomy gates, and
   the halting decision's *mechanics* (it asks the judge; it does not decide).
2. **Brain** — the LLM in a loop. Two roles, always both present:
   - **Doer** — reasons over the brief, picks and orders the next move(s),
     emits a typed action. Many run in parallel (one per host/surface).
   - **Judge** — a *separate* invocation that rules "is this phase done?" from
     memory evidence. Kept apart from the doers so a tired worker never grades
     its own homework.
3. **Memory** — the yhwach core, walled. Source of truth. Nothing is "known"
   until it is a typed row here.
4. **Tools / executors** — HexStrike, nmap, probes, and a gated shell escape
   hatch. Workers live at this layer when a task fans out.
5. **UI** — a read view over memory + a control channel (kill a worker, approve
   a gated action). Communicates with the orchestrator *only through the DB*.

## Memory is sacred (the one hard invariant)

`yhwach.memory` = the world model, attempt ledger, scan coverage, recall brief.

- **Single source of truth.** A fact is not real until it is a typed row.
- **Every tool output must land here as a finding** (via `ingest`/`interpret`/
  `parsers`). A tool the brain can call whose output does *not* become a finding
  is a drift generator — the exact failure yhwach exists to kill.
- Everything else in the repo is reusable machinery that reads from / writes to
  memory. It is not memory and does not get memory's protections.

## World-model completeness — the auto-materialisation gate

Corollary of "memory is sacred": every IP the operator learns about, from any
signal, must become a `host` row **the same turn** — otherwise the UI, the
brief, and every downstream tool operate on a partial world. This was the
"10 IPs learned, 2 in the UI" bug on a prior engagement — internal
hosts got mentioned in findings' evidence but never materialised, so gaps
analysis silently missed a /24 and findings were mis-attributed to the pivot.

`yhwach.discovery` owns the fix:

- **Every discovery signal funnels through `observe_ip`** — engage's scope
  expansion, an nmap parser, an operator naming a host, a `source_host` on a
  credential, IPv4 literals in a finding's evidence blob. Any code path that
  learns of an IP is required to observe it. Adding a new one without an
  observe call is a review-blocker.
- **`host.discovery_source`** records HOW the row was first named
  (`scope | nmap | finding | cred | cert_san | operator | …`), so a mis-fired
  auto-materialisation can always be traced back to its trigger.
- **`host.scan_needed`** is the queue flag the scanner reads. The default is
  `1` on every new row so a host that materialises through *any* signal is
  automatically queued for a first full-scan.
- **In-scope only.** Out-of-scope IPs are still refused — the observer's
  contract is "safe to spam", not "spray the internet". The refusal message
  is `out of scope for lab '<lab>'`; the old "not in lab" wording is gone.

## Auto-scan gate — hosts owe a full pass before they're "enumerated"

Corollary of "memory is sacred", again: a host tagged `scanned` while its
`scan_needed=1` is a lie. `yhwach.scanner` drains the queue:

- **Modes are named after operator intent**, not nmap flags:
    `quick` = `-sV -sC --top-ports 1000` (baseline);
    `full`  = `-sV -sC -p-`               (the "no missed ports" promise);
    `udp`   = `-sU --top-ports 100`.
- **`quick`/`full` clear `scan_needed`; `udp` does not** — UDP is additive
  coverage; the "first TCP pass owed" promise stays intact.
- Every scan ingests through the same code path as `yhwach_ingest kind=nmap`,
  so downstream hooks (the sprayer's new-service handler) fire naturally for
  every service discovered.
- `yhwach_gaps`'s header names the pending count. A brief that reports
  "254 pending scan" is the visible receipt that the world model is honest
  about what it still owes.

## Auto-spray gate — a cred is not "stored" until it has been tried

Corollary: a credential in the vault whose `credential_access` is empty is a
loaded chamber with the safety on. `yhwach.sprayer` fires on every add and
every new service:

- **On `add_cred`** — spray the new cred × every matching service.
- **On `ingest_nmap`** (new services) — spray the vault × every new service.
- **On `yhwach_spray`** — the manual matrix (filters: host, protocol, cred).
- Every attempt writes into `credential_access` (`fail` rows included), so
  the second spray of the same (cred, service) pair short-circuits on the
  cached row unless `force=True`.
- Per-service backoff after N consecutive fails prevents a firewalled port
  from burning the batch.
- `PROTOCOL_MATCHERS` is the authoritative kind→protocols map — an adapter
  that isn't listed there is never called (kerberos/dpapi are deliberately
  excluded — dedicated tooling and offline blobs, not live-auth).

A sprayer exception is caught in `tool_add_cred` and surfaced as
`(autospray error: <type>)`; the cred **still lands** in the vault. Losing
intel to a broken adapter is worse than a noisy tool report.

## Per-service enumeration gate — a surface is not "enumerated" until it is triaged

Corollary of "memory is sacred", one level deeper than the auto-scan gate: a
host can be full-ported, `-sV`'d and UDP-swept and *still* under-enumerated if a
discovered **service** was never actually checked. Scan-coverage answers "did we
look at the host?"; this answers "did we check each thing we found?" — the
structural form of *"check every path"*.

- **`yhwach.coverage` emits a `service_enum` gap** for any `surface` whose kind
  is service-enumerable (`SERVICE_ENUM_KINDS`) and that carries no triage signal:
  no finding on it, no `credential_access` of its kind, no recon attempt against
  it. It is **advisory** (surfaced in `yhwach gaps`), never an FSM block — same
  contract as the scan-coverage verdict.
- **`data/service_matrix.yaml` is the single source of truth** for service
  identity (`kind → ports → classify → surface → rules → ref pack → taxonomy`).
  `classify_service` matches a port **or** the `-sV` product string (so a
  datastore on a non-standard port is still classified), and `SERVICE_ENUM_KINDS`
  is sourced from this matrix — add a row and it is automatically in the verdict.
- **The triage a gap wants:** unauth check → default-creds (`yhwach ref
  default-creds`) → version→CVE (`yhwach vulns`) → loot. For the per-service
  recall menu, `yhwach ref services -q <kind>` (and, as they land, the
  `datastores` / `k8s-enum` / `ai-infra` packs).

## Enumeration & privesc checklists — check every path

The recall menu emits *which* techniques apply; these checklists are the *order*
and the *completeness bar*. A host is "enumerated" only when `yhwach gaps` shows
no `service_enum` gap for it. Every checklist points at a `yhwach ref` pack
(offline) rather than inlining data.

**Per-stage spine.** 1) Estate scan — full-TCP + `-sV` + UDP top-100 (the
coverage floor); `-sV` matters twice, its product string classifies a datastore
on a non-standard port. 2) Per-service triage — for every classified surface run
the WHOLE menu: unauth → default-creds (`yhwach ref default-creds`) → version→CVE
(`yhwach vulns`) → loot; the service isn't done until its `service_enum` gap
clears. 3) Loot before pivot — datastore rows, config secrets, tokens are
`credential_reuse` fuel. 4) Privesc — on any foothold run winPEAS/linPEAS. 5)
Pivot per subnet; **AI last if gated, first if open**.

**Per-service** (`yhwach ref services -q <kind>`):
- **Datastores** — redis 6379 `INFO`/`KEYS` unauth; mongo 27017 `listDatabases`;
  ES 9200 `/_cat/indices`; memcached 11211 `stats`; kafka 9092 `kcat -L`; MSSQL
  `sa` + `xp_dirtree` UNC = NetNTLMv2 capture. Then version → `yhwach vulns`.
- **SMB/LDAP/AD** (`ref wadcoms -q <phase>`) — null→anon→authed shares / rid-brute
  / pass-pol; LDAP anon; kerbrute; BloodHound; `certipy find -vulnerable`. **Read
  the lockout policy before spraying** — the one move that burns accounts.
- **AD CS** (`ref esc`) — `certipy find` FIRST (one pass emits every ESC); map the
  printed `signal`. Direct-req 1/2/3/6/13/15 · coercion 8/11 · victim-write
  9/10/14/16 · CA-control 5/7/12. Capture the target `-sid`.
- **k8s / cloud** (`ref services -q apiserver|kubelet|etcd|docker_api`; scripts:
  `ref arsenal -q kubernetes|cloud`) — apiserver anon `can-i --list`; kubelet
  `/pods`+`/run`; etcd `/registry/secrets`; docker 2375 = host-root-equivalent;
  AWS IMDSv2 → role creds → `sts`/S3/IAM.
- **UDP/SNMP** — 161 community strings (`public`/`private`) via onesixtyone/snmpwalk.

**Windows privesc — highest-ROI-to-SYSTEM first** (`ref lolbas`, `ref esc`):
`whoami /priv` (SeImpersonate→GodPotato/PrintSpoofer; SeBackup/Restore→`reg save`
SAM+SYSTEM→secretsdump; SeDebug) → AlwaysInstallElevated → service misconfig
(unquoted / writable) → autoruns & SYSTEM tasks → DLL hijack → LSA secrets /
autologon → SAM/SYSTEM → DPAPI / Credential Manager / Vault → creds-in-files →
browser / PuTTY / Firefox / unattend.xml. `ref lolbas -q credentials|execute|awl`
before dropping a flagged binary (comsvcs.dll MiniDump, reg save, ntdsutil IFM).

**Linux privesc — ROI order** (`ref gtfobins`): `sudo -l` → writable
`/etc/passwd`|`/etc/shadow` → SUID/SGID GTFObins → capabilities → group
(docker/lxd/disk/shadow) → cron → systemd units → `$PATH`/`LD_PRELOAD` → NFS
`no_root_squash` → version-gated kernel/sudo/polkit CVEs **last** (they crash
boxes) → harvest creds (SSH keys, `.bash_history`, `.aws`, kubeconfig) for reuse.

**AI-surface testing — ordered, each mapped (OWASP LLM / ATLAS)** (full chains +
payloads: `yhwach ref ai-attacks -q <rag_poisoning|mcp_attack|a2a_attack|vector_db|cloud_loot|prompt_injection>`)**:** 1) fingerprint
version first; 2) unauth-by-default (ollama/vLLM/vector-DB/MCP); 3) map tool /
agency (MCP `tools/list`); 4) exploit tool args (`$(...)`, `../`, SQLi through a
tool); 5) excessive agency (state-changing tool on an injected request); 6)
insecure output handling → stored XSS; 7) indirect injection via an ingested
source; 8) system-prompt leak → mine for creds → `credential_reuse`; 9)
sensitive-data leak (recall_conversation cross-session); 10) vector-DB dump /
embedding inversion. A state-changing craft is `risk: propose`; all
`authorized_only`.

## Knowledge: the catalog is a recall menu, not a ranker

The 181-entry technique catalog (`playbooks/*.yaml`) was restored from history
(commit `731327f`) **without** the EV ranker. Its job changed:

- **Recall (the AI cannot do this reliably).** A deterministic matcher emits
  *every* applicable technique for a host — so the brain *selects from a
  complete menu* instead of *remembering* the menu. This is the one thing the
  rule engine genuinely beats the AI at, and the reason the catalog is worth
  keeping.
- **Chaining.** `findings_include` lights up post-foothold / AD chains
  (kerberoast, DCSync, ADCS) deterministically once a host carries the tag.
- **Safety tags.** `risk: read_only` vs. gated is deterministic and **never**
  delegated to the AI's judgment.
- **Ranking (the AI does this better).** The doer brain orders the candidates
  from the notes, leads, dead ends, and creds in hand. The old `points:` EV
  scalar survives only as a hint the brain may ignore — never as sort order.

> The YAML was never the problem — the scalar ranker on top of it was. We kept
> the baby (curated knowledge) and left the bathwater (the decider) in history.

## Taxonomy & tags — the three axes the memory is indexed on

Every fact in memory is keyed on three **orthogonal** axes. Keeping them distinct
is what lets the same knowledge serve recall, the memory index, and the audit
lens (coverage-by-tactic, standards-aligned reporting):

- **Surface** — `surface.kind` / rule `surface:` — *what it is*. Canonicalised in
  `data/service_matrix.yaml`.
- **State / chaining** — `finding.tag` / rule `findings_include` — *what we
  proved*; the key that unlocks the next move. Registry: `data/tags.yaml`
  (`yhwach ref tags`). **Invariant:** every chaining tag has a producer (a
  parser/interpret/probe that emits it) *and* a consumer (a rule that keys on
  it), or it is dead — enforced by `tests/test_tag_graph.py`. The winPEAS-sourced
  `high_ev_leads` triggers are the documented dead set until their parser
  producer lands.
- **Taxonomy** — `finding.class` / rule `maps:` — *what it means*: public IDs
  (`ATT&CK T#### · ATLAS-AML.T#### · LLM01-10 · CWE- · CVE-`). This is the
  audit backbone; every finding should carry the full set, not one bare id.

**Lessons pull off the state axis:** `data/lessons.yaml` (`yhwach ref lessons`)
keys past-lab knowledge on `trigger_tag`, so a matching finding tag surfaces the
lesson in the brief — no git archaeology.

## Tools: free to run anything, first-class only when parsed

Three tiers of tool reach:

| Tier | What | Output becomes a finding? |
|---|---|---|
| **First-class** (~30-40) | curated: nmap, netexec, ldapsearch, certipy, bloodhound, AI probes | yes — has a parser |
| **Free shell** (all of Kali) | gated `run_shell` escape hatch | no — stored raw, reasoned over in-context |
| **Promotion** | write a parser for a tool the brain keeps reaching for | it graduates to first-class |

- **MCP for reach, typed actions for memory.** Point-bearing / state-changing
  tools are wrapped as typed actions (`actions/*.py`) that call the tool *and*
  parse *and* emit findings. HexStrike MCP may be exposed directly for
  read-only enumeration, but its output is routed back through `interpret`
  before it is trusted.
- The tool *catalog* is vendored/pinned, not trusted live from an MCP server's
  self-description (prompt-injection surface on hostile engagements).

### Arsenal — vendored offensive tooling (`arsenal/`, indexed by `yhwach ref arsenal`)

The pre-staged offensive kit lives **inside the repo** at `arsenal/` (resolved by
`yhwach/arsenal.py` — vendored copy first, legacy/apt path as fallback). It maps onto
the three tiers above, not beside them:

- **Canonical deliverers (first-class).** The battle-tested foothold/pivot path,
  rendered by actions so the command is never hand-crafted: **`gen_cs_shell.sh`**
  (`yhwach revshell --os win` — C# revshell that lands on Win11 with AV on) and
  **`svcmon.exe`** (`yhwach pivot` — obfuscated ligolo agent). Linux: `gen_linux_shell.sh`,
  ligolo (`/usr/bin/ligolo-agent`, apt) or chisel.
- **Quick-wins (free-shell tier).** The `arsenal/AIScripts/` surface-specific shortcuts
  (k8s/gitlab/cloud/nexus enum, vector-db dump/inversion, model/RAG poisoning, A2A MITM).
  **A quick-win is opportunistic, never a substitute for exhaustive manual enumeration
  with the full Kali toolset** (HexStrike + free shell) — "no script matched" ≠ "nothing
  to do". The `service_enum` coverage gate still governs completeness.

Both surfaces are indexed offline: **`yhwach ref arsenal`** (script → purpose · surface ·
invocation · tier) and **`yhwach ref ai-attacks`** (the RAG/MCP/A2A/vector-db/cloud chains,
OWASP-LLM/ATLAS-mapped). AGENT.md points at those packs rather than inlining commands.

## Runtime & connectivity

**Decision: yhwach calls the model through a provider adapter, authenticated
with an API key.** Not the Claude Code CLI, not "through MCP" — those are
different wires (below). The *adapter* auth model (API key, unattended) is
fixed; the *vendor* is not — **Anthropic is the default, OpenAI is a drop-in
alternative** selected at runtime (`--provider` / `YHWACH_PROVIDER` / a model
id), so swapping keys never touches code.

An agent has **two connections**, and they are not the same:

```
  wire 1: who CALLS the model                wire 2: what the model can DO
  orchestrator ──────────────▶ CLAUDE ──────────────▶ yhwach memory + tools
   (auth: ANTHROPIC_API_KEY)   (brain)     (SDK tool defs + MCP toolset)
```

- **Wire 1 — model caller = a provider adapter + API key.** `brain.py` stays
  vendor-agnostic and delegates to a `Provider` (`yhwach/providers/`): the
  default `AnthropicProvider` constructs `anthropic.Anthropic()` (reads
  `ANTHROPIC_API_KEY`) and calls `client.messages.create(...)`; `OpenAIProvider`
  constructs `openai.OpenAI()` (reads `OPENAI_API_KEY`) and calls
  `client.chat.completions.create(...)`. The adapter is chosen by
  `providers.resolve_provider` at runtime. Chosen over the CLI and the Agent
  SDK because the auto-runner needs: parallel workers (many concurrent calls,
  each a memory slice), per-worker token/wall-clock **budgets** (`usage` +
  native `task_budget`), and **model tiering** (a `model=` string per call).
  The **API key** (not an interactive login profile) is the right auth because
  yhwach runs unattended and parallel on Kali — the non-interactive automation
  case. A stored `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` env var (or a service
  account / WIF) — never a hardcoded key, never committed.
- **Wire 2 — tools = SDK tool defs + the existing MCP server.** `mcp_server.py`
  already exposes yhwach over MCP; the brain reaches it as an `mcp_toolset`.
  **Rule: memory-writing actions are passed as direct SDK tool defs**
  (`actions/*.py`) so the parse→finding step is guaranteed; **MCP is for
  read-only reach.** A tool whose output skips the parser is a drift generator.

- **Model tiering (per call, not per product):** cheap/fast model for
  RANK & INTERPRET (`claude-haiku-4-5` / `claude-sonnet-5`), the strong model
  for CRAFT & the judge (`claude-opus-5`). Adaptive thinking on
  (`thinking: {type: "adaptive"}`); effort raised for judge/craft. Each provider
  carries its own role→model map, so OpenAI has an equivalent tiering; an
  explicit `--model` overrides it for every role.
- **Prompt caching:** the stable prefix — persona (`operator.md`) + the
  applicable slice of the technique catalog — is cached; the volatile per-host
  brief goes after the cache breakpoint. This is a direct cost lever for an
  auto-runner making many calls that share the persona.
- **The Claude Code CLI is not in the runtime loop** — it is only a *developer*
  tool for building yhwach. The old "host CLI drives the operator" model is
  exactly what the SDK-driven orchestrator replaces.

## The loop

```
recon (auto, read-only)
  orchestrator: for each host, matcher -> candidate techniques
  doer brains:  reason over brief -> pick move -> run tool -> write finding
  repeat until ->
JUDGE: "enumeration done?" -> evidence-backed verdict (cites memory rows)
  NOT DONE -> keep dispatching on what's left
  DONE     -> SYNTHESIS pass -> "State + Next Steps" report -> CHECKPOINT (human)
exploitation (gated: human go/no-go per the report)
  ... -> JUDGE -> report -> post-ex / pivot -> final report
```

- **AI decides "done", but with a receipt.** The judge is handed the memory
  state (coverage, FSM stages, gaps, the candidate queue) plus the
  deterministic facts, and must return a verdict that *cites evidence*. A
  verdict that can't point to rows is rejected and re-asked. The deterministic
  facts (e.g. "3 hosts still unscanned") are fed in as evidence the judge must
  reckon with — **not** a gate that overrides it. Overriding a known fact is
  then a deliberate, auditable act the human sees at the checkpoint.
- **Phase reports are queries, not essays.** The "State + Next Steps" report is
  regenerated from memory (like the existing `export-notes` fences). Same facts,
  two renderings: the machine-facing next-step queue (the candidate list) and
  the human-facing decision doc (judge verdict + attack graph + ranked leads).
- **The report is the auto/human boundary.** Read-only recon runs free;
  exploitation waits for the human at the report. Safety envelope and "stop
  unnecessary jobs" unify here.

## Workers (fan-out)

- One main brain plans and dispatches per-host / per-surface **sub-agents**.
- Each worker gets a **memory slice** (its host's state + relevant creds +
  applicable techniques), never the whole world model — prevents context bloat
  and cross-contamination. Memory is already host-scoped, so this is a "scope to
  host X" mode on the brief builder.
- **Credentials are the exception** — never exhausted, shared globally (the
  existing `credential_reuse` primitive). A recovered cred is a global event all
  workers see.

## Budgets, safety, replay

- **Budgets are memory rows.** Per-engagement and per-worker token / wall-clock
  / action budgets, enforced by the orchestrator, read by the halting policy.
  This is what makes "leave it running" safe.
- **Safety stays deterministic.** Scope enforcement (`scope.py`), the loopback
  guard, autonomy tiers, and the read-only-vs-gated classification live in the
  orchestrator/action layer. **Never** delegated to the brain.
- **Replay.** The `event` table already reserves `persona_hash` / `rules_hash`.
  For an auto-runner this graduates from nice-to-have to essential: replaying
  *why* the agent did X is both the debugging lifeline and the engagement write-up
  evidence.

## Module map (as built)

A flat re-layering (the repo is flat — `db.py`, `brief.py`, … — so the agent
modules are flat too, not a nested `agent/` package). All of the below is built
and tested unless marked otherwise.

```
yhwach/
  # memory core (the walled source of truth + its read views) — pre-existing
  db.py · brief.py · context.py · ingest.py · coverage.py · notes.py
  # world-model completeness (see gates above)
  discovery.py       # auto-materialise hosts on every discovery signal
  scanner.py         # drain the scan_needed=1 queue with -p- -sV
  sprayer.py         # cred × service auto-spray (per-protocol adapters)
  patterns.py        # derive spray candidates from known vault templates
  # knowledge — the recall menu
  knowledge.py       # matcher-only candidate generator over playbooks/*.yaml
  nextmoves.py       # fused "what next + what am I about to miss" view (CLI/MCP/UI) over the menu
  pathfind.py        # owned -> objective / Domain Admins shortest paths (renders db.shortest_path)
  # the agent runtime (this branch)
  brain.py           # wire 1: provider-agnostic model caller; context in -> typed Action out
  providers/         # wire 1 adapters: base (Provider) + anthropic (default) + openai; resolve_provider
  policy.py          # budgets, autonomy gates, halting — deterministic
  actions.py         # validate an Action against the menu, gate, execute -> memory
  judge.py           # phase-complete verdict from evidence (separate brain)
  orchestrator.py    # the control loop; convergence + kill checks
  workers.py         # per-host fan-out (memory slices), engagement-level judge
  synthesis.py       # "State + Next Steps" report (query over memory)
  control.py         # kill + approvals via the event table (UI <-> loop)
  dryrun.py          # deterministic no-key doer/judge (demo + tests)
  ui.py              # optional FastAPI board: read view + kill/approve (extra: ui)
  # tools / executors — pre-existing
  hexstrike.py · probes/ · parsers/ · interpret.py   (+ actions/*.py templates)
  persona/           # operator.md, contract.md, notebook.md — the brain's frame
```

Entry point: **`yhwach run --lab X [--dry-run] [--fan-out] [--allow-gated]`**.
Board: **`yhwach ui --lab X`**.

Buried in history, not restored: `planner.py` (EV ranker), the scoring half of
`playbooks.py`, `test_planner.py`, `test_playbooks.py`.

## Resolved / still open

Resolved this branch:
- **UI stack** — FastAPI + htmx polling a server-rendered fragment over the DB
  (no build step, no client state). Attack-graph view can come later if it earns
  it. Built in `ui.py`.
- **Model tiering** — implemented in `brain.py`: doer/judge -> Opus, interpret ->
  Haiku, rank -> Sonnet; overridable per call.
- **Kill / approvals** — DB-mediated control channel (`control.py`), so the loop
  is cooperatively cancellable and gated moves wait for a human, cross-process.

Done: **read-only tool runner** — `runners.py` (`HexStrikeRunner`) executes the
read-only enumeration `emits` actions (SMB/LDAP/AD null-session recon, AI-surface
HTTP probes, spec/version fingerprints) through HexStrike and pipes output through
the `interpret` extractors into typed findings. Wired via `yhwach run
--hexstrike-url ...`. An unwired technique records a `partial` "not wired" attempt
— never a faked success. (This project is scoped to authorized lab enumeration,
so the runner executes read-only recon directly; the autonomy gating remains in
code and still queues exploit/destructive moves.)

Resolved by the senior-pentest audit pass:
- **Loop robustness** — a brain refusal / hallucinated action / runner failure
  no longer crashes the run; each is recorded and the loop continues or halts
  cleanly (`orchestrator.run`).
- **Phase progression** — the loop advances a worked host `scanned -> enumerated`,
  so the judge/brief see progress and phases can transition.
- **Token budget + scope guard** — `brain.decide` meters real token usage into
  the budget; the executor refuses out-of-scope hosts (`scope.in_scope`).
- **Runner breadth** — the read-only command map covers the remotely-runnable
  extractors (LDAP anon, Jenkins, GitLab, Gradio, n8n, …); non-remote ones are
  documented as belonging to other paths.
- **CRAFT path** — `craft_and_run`: the brain writes a payload (prompt injection /
  SSTI / tool abuse), the runner delivers it via a shell-safe HexStrike curl and
  interprets the response. The AI-pentest core.
- **Eval harness** — `tests/test_eval.py` runs the whole loop against a fixture
  lab and asserts the planted flaws are found: a measurable improvement number.

Still open:
- **Lessons memory** — *done:* the `learn(...)` commit knowledge (gitea RCE,
  GodPotato, KeePass loot, ...) lives in `data/lessons.yaml`, keyed by
  `trigger_tag` and queryable with `yhwach ref lessons`. `reference.lessons_for(tags)`
  now unions the lessons whose `trigger_tag` intersects the engagement's open
  finding tags + surface kinds, and `brief.build_brief` surfaces them inline as a
  `## LESSONS` section (also `yhwach brief --section lessons`).
- **Vault-reuse runner** — cred-gated AD techniques (kerberoast, LAPS, gpohound)
  have extractors but need a recovered credential fed from the vault to run.
- **Exploit-tier runners** — exploit/destructive `emits` have no runner (they
  queue as approvals); only read-only + CRAFT deliver today.

(Resolved since: **parallel workers** — `yhwach run --parallel N` runs each worker
on its own WAL-safe DB connection, so `workers.py` is no longer sequential-only.)

## History: what changed and why

- `731327f` — `yhwach brief`, the AI-legible engagement map.
- `7ebc4e0` — **removed the decider.** Deleted `planner.py`, the scoring
  `playbooks.py`, the 12 `playbooks/*.yaml` catalogs, and 1021 lines of ranker
  tests. Correct call on the ranker; collateral damage on the knowledge.
- *(this branch)* — **restored the knowledge and built the agent on top.** Brought
  back the (now 181-entry) catalog as the AI's recall menu (`knowledge.py`), then built
  the runtime: brain, policy, actions, judge, orchestrator, workers, synthesis,
  control, UI — with a deterministic dry-run path and CI fixed
  (`yhwach brief` replaced the dead smoke commands).
