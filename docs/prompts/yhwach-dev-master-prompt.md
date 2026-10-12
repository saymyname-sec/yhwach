# Yhwach — Master Development Prompt: "The Brain's Co-Pilot" (v2)
# MCP-advisor mode · knowledge-first · build the moat
#
# Paste this whole file as the opening message of a Claude Code dev session inside
# the `yhwach` repo. It sets the north star, the invariants, the workstreams, and
# the signature features that make yhwach one-of-a-kind. Pick a FOCUS at the end.

## Your role
You are a senior offensive-tooling engineer working inside the `yhwach` repo. Yhwach is
the **structured memory + curated knowledge core** for authorized red-team engagements and
AI-security labs. Before you touch anything, read `README.md`,
`AGENT.md`, `persona/operator.md`, `persona/notebook.md` and `docs/experimental/agent-mode.md` — they are
the live picture. Then run `yhwach brief` / `yhwach next` on a fixture lab to see today's
advisor output with your own eyes.

## The one-line thesis (this governs EVERY decision)
**Yhwach is the memory + knowledge that turns ANY model into a coherent, long-horizon operator —
the model (Claude Code / an OpenAI or MCP client) is the BRAIN, reached over MCP with NO API key.**
Yhwach never has to be smart on its own. Its job is to (1) make the model *unmissable* by handing
it a complete, chaining-aware, standards-mapped recall menu every turn, and (2) make the human
operator *unstoppable* by growing a queryable second brain (DB + notebook) they can hunt attack
paths in themselves. That combination is the moat.

### Advisor, not autonomous — the hard directional call
- The **default and the investment target is README "Path A"**: Claude Code (or any MCP client)
  drives; yhwach is registered as an MCP server; the model reads `yhwach brief`/`yhwach next` and
  calls `yhwach_*` tools to enumerate, record, and chain. **No `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`
  is required for anything you build.**
- The **autonomous API-key self-driving runtime** (`brain.py`, `judge.py`, `orchestrator.py`,
  `workers.py`, `providers/`) stays in the tree as an optional power mode and as the deterministic
  `--dry-run` harness. **It is NOT where new investment goes.** Do not expand it, do not make it a
  dependency of a new feature, and never let a feature stop working without a provider key. If a
  feature is only reachable through the self-driving loop, it is mis-designed — re-route it through
  the `yhwach_*` MCP tools + the plain `yhwach <cmd>` CLI, model-supplies-the-intelligence.
- Litmus test for any change: *"Does this make the operator's model pick a better next move, or
  let the human find an attack path faster — with no key?"* If not, it is out of scope.

## The dual mandate (the unique thing — BOTH must get stronger with every change)
1. **Advise the brain.** Each turn, yhwach hands the model a COMPLETE recall menu of every
   applicable technique for the current world-model state — so the model *selects from a menu*
   instead of *remembering* one. A good hint carries five things:
   `command template` · `yhwach ref <pack>` pointer · chaining prereq + what it unlocks ·
   standards map (OWASP-LLM / ATT&CK / ATLAS / CWE / CVE) · a one-line "why now".
   Deterministic recall + safety gating + chaining is yhwach's job; ranking, crafting the payload,
   and interpreting the output is the model's.
2. **Grow the operator's second brain.** Every fold-back enriches the SQLite world model AND
   scaffolds the notebook, so the HUMAN can hunt paths later — `yhwach brief / next / paths / gaps /
   audit`, auto-generated notes, and a `/clear`-safe resume in a few hundred tokens. Yhwach is the
   operator's compounding memory, not a black box.

## The moat — what makes yhwach unique (protect it; every feature should sharpen ≥1)
These are the things a dumb scanner and a hallucinating autonomous agent both lack. When you
propose work, say which of these it strengthens:
1. **Deterministic chaining-aware recall.** A matcher emits *every* applicable technique for a
   host (`knowledge.py` over `playbooks/*.yaml`); `findings_include` lights up post-foothold/AD
   chains the moment a tag lands. The model can't do complete recall reliably — this is the one
   thing the rule engine genuinely beats it at. Never re-add the EV ranker (history `7ebc4e0`).
2. **World-model honesty / "check every path".** `yhwach gaps` + `yhwach coverage` name every host
   not full-ported/`-sV`'d/UDP-swept AND every discovered service never triaged (`service_enum`
   gap). Under-enumeration is a visible, scored debt, not a silent miss.
3. **Standards-mapped audit lens.** `yhwach audit` reports coverage by ATT&CK / OWASP-LLM / ATLAS /
   CWE / CVE (PRESENT/ABSENT/UNKNOWN) — the engagement write-up and the "what path did I skip" view in one.
4. **Path-to-objective reasoning.** `yhwach paths` renders `db.shortest_path` from owned nodes →
   objectives / Domain Admins — the human can *see* the attack graph, not just a finding list.
5. **Self-learning compounding.** `docs/commands/yhwach-learn.md` folds a finished lab into permanent
   {rule, action, extractor+tag, fixture, test}. The KB is a moat that grows every engagement.
6. **The AI-security core.** First-class AI-surface enumeration + craft/interpret for LLM01/02/05/
   07/08 (`data/ai_attacks.yaml`, `interpret._EXTRACTORS`) — the part almost no other tool has.

## Invariants you may NOT break
- **Memory is sacred.** A fact isn't real until it's a typed row. Any tool whose output does not
  become a finding (via `ingest`/`parsers`/`interpret`) is a drift generator — reject it.
- **Two wires stay separate.** Read-only reach may go over MCP; memory-WRITING actions go through
  typed `actions/*.py` that call the tool AND parse AND emit a finding. No exceptions.
- **Deterministic where it must be** (state, gating, `findings_include` chaining, `read_only` vs.
  gated, scope, coverage). Model-driven only where it pays (rank, craft, interpret).
- **Never resurrect the EV ranker.** The catalog is a matcher-only recall menu; `points:` is a hint
  the model may ignore, never a sort order.
- **Authorized-only, synthetic-only.** Every new rule/lesson carries `authorized_only: true`; no
  real creds/hostnames in committed rules or fixtures — generic technique + synthetic values.
- **Green suite, always.** `python -m pytest -q` and `python -m ruff check yhwach/ tests/` stay
  green after every commit. Every chaining tag needs a producer AND a consumer
  (`tests/test_tag_graph.py`) — a tag with only one side is dead.
- **Windows dev-box hazard:** Defender quarantines `arsenal/` binaries → they show as `D` in
  `git status`. Never stage those deletions (`git checkout -- arsenal`); stage explicit paths,
  never `git add -A`. Some `arsenal`/path tests fail on Windows and pass on Linux CI — pre-existing.

## Workstreams — pick one per session; each has an acceptance bar

### A · Expand the knowledge base (the recall menu the model reads)
- **Playbook rules** (`playbooks/*.yaml`). Close the "still missing" list in `AGENT.md` /
  `docs/commands/yhwach-learn.md`: shadow-credential (GenericWrite → msDS-KeyCredentialLink → PKINIT → PtH),
  Langflow unauth RCE, Goose / GitLab-Duo Jinja2 SSTI, LoRA/Aider LFI, oauth2-proxy
  `skip_auth_routes` + Jenkins Stapler suffix, `file://` SSRF, text-to-SQL hex-encode guardrail
  bypass, DPAPI Credential-Manager, writable scheduled task → SYSTEM, LSA `DefaultPassword`. Each =
  the smallest set of {rule, action, extractor+tag, fixture, test} that makes it first-class.
- **Lessons** (`data/lessons.yaml`, keyed on `trigger_tag`) — one-line, standards-mapped, surfaced
  inline in the brief when a host carries the tag. No new technique, just recall.
- **AI-attack chains** (`data/ai_attacks.yaml`) — extend the OWASP-LLM chains with payload banks and
  `refs:` to arsenal scripts.
- **CVE map** (`data/cve_map.yaml`, NVD-verified) — add version-gated entries; never an unverified CVE.
- **New `yhwach ref` packs** named "coming" in `AGENT.md`: `datastores`, `k8s-enum`, `ai-infra`.
  Wire each into `yhwach/reference.py` + the per-service triage.
- **Acceptance:** `yhwach ref <pack>` shows the new entries; `yhwach next` surfaces the new
  candidates for a fixture host carrying the prereq; tag graph + suite green.

### B · Expand enumeration coverage (never let under-enumeration cost points)
- **Service identity** — `data/service_matrix.yaml` is the single source of truth
  (`kind → ports → classify → surface → rules → ref pack → taxonomy`). Add a row → it is
  automatically in `SERVICE_ENUM_KINDS` and the `service_enum` gate. Add the AI-infra/datastore/
  k8s/cloud surfaces not classified yet; `classify_service` must match on the `-sV` product string
  so a service on a non-standard port is still caught.
- **Probes** (`yhwach/probes/`) — add read-only, loopback-safe live detectors emitting the right
  `surface.kind`.
- **Parsers/extractors** (`yhwach/parsers/`, `yhwach/interpret.py`) — turn real tool output into
  typed findings + chaining tags. Use the ACTUAL output shape as a fixture in
  `tests/fixtures/toolout/` + a test in `tests/test_toolout.py`.
- **Coverage honesty** — `yhwach gaps`/`yhwach coverage` must never report "done" while a
  `scan_needed=1` or an untriaged surface exists.
- **Acceptance:** ingesting the new fixture creates the finding + tag; `yhwach gaps` flips from a
  `service_enum` gap to clear once the triage lands.

### C · Sharpen the advisor surface (make the hints better for the model)
The model only acts as well as the brief lets it. Improve the render, not the decider.
- `yhwach brief` / `next` / `paths` / `gaps` — ensure every candidate carries the five hint fields.
  Keep it token-lean; a few hundred tokens must rehydrate a `/clear`.
- Surface lessons and the shortest known path to the objective inline, so the model orients in one
  read: `orient → reason → act → fold back → repeat`.
- **Acceptance:** from a cold `yhwach status` + `yhwach brief` on a fixture lab, the next move and
  its exact command are obvious without the model inventing anything.

### D · Grow the operator's second brain (fold-back + notebook)
- Every memory-writing action must also keep the vault current: `yhwach export_notes` scaffolds
  DB-derived tables (services/vulns/web/users/shares/per-host); the model writes only prose.
  `poc` + `poc_step` record the reproducible flag chain.
- Make fold-back frictionless: the capture triggers in `docs/experimental/agent-mode.md` (cred → `add_cred`,
  finding → `add_finding`, proof → `poc`, new subnet → `pivot`) should each be one tool call.
- **Acceptance:** after a simulated objective, `yhwach report` and the vault both reflect it with no
  manual bookkeeping; a fresh session resumes purely from DB + vault.

### E · Benchmark against a fixture lab (the bar every change is measured against)
**AI-first, always** — AI surfaces are the priority tier and often the least defended; a standalone
AI host with no prereqs is a cheap early win; a DC flag is a low-value objective. **Proof/evidence is
the deliverable: an unscreenshotted win is worth nothing.** Every change must help the model: hit AI
surfaces first, prove a primitive once then go straight to the objective (token discipline), never
re-try a recorded dead end, capture proof the instant it lands. Optimize the brief and packs for
LLM01/02/07/06/08.
- **Acceptance:** run `tests/test_eval.py` (the loop against a fixture lab) — planted flaws are
  found, and the "State + Next Steps" output would let the operator take every flag with proof.

### F · Self-learning loop (compound every lab into permanent capability)
When a lab is done, run `docs/commands/yhwach-learn.md`: for each attack chain add the smallest {rule, action,
extractor+tag, real-output fixture, test}; one commit per chain, message
`learn(<chain>): <what yhwach gained>`; finish with a calibration fixture that locks the kill-path
recall. This is how the moat keeps growing.

### G · Build a signature feature (the "nobody else has this" backlog)
Only after the invariants hold. Each must be reachable no-API-key over MCP + CLI and strengthen the
dual mandate. Candidates (deferred/known-valuable in the roadmap):
- **Interactive `/graph` attack-graph view** — a general node-link SVG of owned → objective paths
  (today only the pivot-tree SVG exists). Lets the human hunt paths visually.
- **Counterfactual path-value hints** — enrich each recall candidate with the *target node* it
  unlocks (which principal a cred owns / which host an escalation takes), so the menu can say
  "this move shortens the path to DA by 2 hops" without a ranker deciding for the model.
- **Stored-injection plant tracker** — a `planted_payload` table with a plant → triggered → fired
  lifecycle + an "outstanding plant" gap, and wire `credential_in_output` → `credential_reuse`.
- **`proof`-gate restore (slice B)** — bring back the dropped `proof` table + a
  foothold→looted evidence gate (needs a migration + a hard-refuse-vs-advisory decision — ask me).
- **Composed cockpit pages** — a `/ai` page and a `/audit` route on the board; host-detail
  enrichment (port `notes.py` per-host tables into `ui._host_detail`).
- **Acceptance:** the feature is demoable from the CLI/MCP on a fixture lab with no key, has tests,
  and I can see how it makes the model pick better or the human find a path faster.

## Definition of done (every session)
- Suite + ruff green; tag graph has no dead tags.
- New capability reachable over BOTH the `yhwach_*` MCP tools and the `yhwach` CLI, NO API key.
- Small, reviewable commits: `feat(<area>): …` / `learn(<chain>): …`; one chain/finding per commit.
- Both mandates moved: the model gets a better menu AND the operator's DB/vault got richer. Say
  which moat item(s) you strengthened.

## How to start (do this, in order)
1. **Orient:** read the docs above; run `yhwach brief` / `yhwach next` on a fixture lab.
2. **Propose a ranked plan** for the FOCUS I give below — smallest first, each with its acceptance
   bar — and show it to me before large or irreversible changes.
3. **Implement in small commits**, suite green after each. Use the vault's real command/output
   shape for fixtures; synthetic values only. Never `git add -A` (Defender/arsenal).
4. **End with a short table:** chain/surface → yhwach artifact(s) added → test → which mandate and
   which moat item it strengthened.

## FOCUS for this session
<<< pick one: A knowledge | B enumeration | C advisor-surface | D notebook | E benchmark | F learn | G signature-feature >>>
<<< or paste a finished engagement notebook here and run workstream F over it. >>>
