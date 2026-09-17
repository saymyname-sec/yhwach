# Roadmap

## Status

**Done and validated on a live challenge lab — Iron Crown (381 tests):**
- ✅ World model (SQLite, 14 tables) + nmap ingestion + host FSM
- ✅ AI-surface probes (Ollama / OpenAI-compat / chatbot / MCP / Gradio / A2A / vector DB)
- ✅ Traditional-surface detection (Jenkins / GitLab / SMB / LDAP / MSSQL / WinRM / SSH / web /
  message brokers)
- ✅ Deterministic planner: 92 YAML technique rules → EV-ranked tasks, AI-first tiering
      (AI, traditional, cloud/k8s, broker, supply-chain, post-exploit); matches surface / auth /
      product / os / `findings_include` (post-foothold chaining — every rule is matcher-supported)
- ✅ Cross-cutting primitives: technique exhaustion + credential reuse + lore denylist
- ✅ Operator memory: attempt ledger (`yhwach outcome`) → dead ends + EV decay, `yhwach recall`
      catch-up brief, cheap `--no-persona` / `--json` handoffs
- ✅ Enumeration coverage (`scan_coverage`) + `yhwach gaps` — under-enumeration is now queryable
- ✅ Every chaining tag has a producer (0/40 dead) — all 92 rules reachable
- ✅ Actions layer: 107 registered actions (emits → concrete commands); read-only runs
      (untrusted substituted values are shell-guarded), exploitation render-only
- ✅ Deterministic finding extraction from action output (incl. error-based SQLi)
- ✅ Operator handoff: `next --contract` (persona + state + dead ends + enum gaps + candidates)
- ✅ Post-foothold FSM: credential vault, `spray`, linPEAS/winPEAS parsers,
      `foothold → looted → pivoted → done`
- ✅ Proof capture: `yhwach proof` binds a flag + screenshot and gates `foothold → looted` on
      that evidence (the engine refuses `looted` without a proof screenshot)
- ✅ HexStrike as the delegated enumeration backend (`yhwach enum`, loopback-guarded)
- ✅ Engagement notebook: the operator writes detailed notes to an Obsidian vault (single source
      of truth) via the Obsidian MCP at every objective; notes never live in the DB
- ✅ Markdown report generation
- ✅ Calibration harness: fixtures + golden runner + `snapshot`
- ✅ Yhwach-as-MCP server for Claude Code (`yhwach mcp`; Path A in docs/deploy.md)

## Plan — sequenced next tasks

Ordered by leverage and dependency. Each phase has an acceptance bar; check items off as they land.

### Phase 1 — Unlock the chaining engine (`findings_include`) ✅ DONE
All 50 rules are now matcher-supported (was 18 silently dead). The 18 `findings_include` rules fire
once the target host carries the required finding tag.
- [x] Finding-tag convention: `finding.tag` column; `add_finding(..., tag=)`.
- [x] Planner: `findings_include` in SUPPORTED_WHEN_KEYS; surface path gets an EXISTS clause,
      surface-less rules get a host-scoped path (`_matching_hosts`), idempotent host-task upsert.
- [x] First live chain wired: the RAG-upload extractor tags `rag_upload`, unlocking
      `rag_kb_advanced_poisoning` / `embedding_collision_attack`.
- [x] Tests: `findings_include` gates a surface rule; surface-less rule is host-scoped + idempotent.
- **Phase 1b (partial):** ✅ PEAS parser now tags host-side loot — `aws_credentials` (linPEAS),
      `chrome_login_data` + `dpapi_master_key` (winPEAS) — so `aws_iam_role_chain_escalation`,
      `chrome_abe_credential_decrypt`, and `dpapi_credential_chain` light up from a real `ingest`.
      **✅ Closed in Phase 9:** every tag on that remaining list now has a producer —
      `gitlab_token`, `python_requirements`, `ssrf_confirmed`, `mcp_config_writable`,
      `pod_create_permission`, `nvidia_toolkit`, `sagemaker_create_notebook` and `jinja2_template`
      landed with their parsers; `pickle_endpoint`, `code_scanner`, `training_pipeline` and
      `ai_code_review` in Phase 9. **0 of 40 chaining tags are now unreachable.**

### Phase 2 — Installable + CI ✅ DONE
- [x] Packaging: `force-include` bundles `db/schema.sql`, `persona/`, `playbooks/`, `tests/fixtures/`
      into the wheel; `__init__` / `default_playbook_dir` / `default_fixtures_dir` check the packaged
      location first, then fall back to the repo layout. Verified: a wheel installed into a clean
      venv (no repo on path) runs `engage`/`plan`/`persona`/`selftest`.
- [x] GitHub Actions (`.github/workflows/ci.yml`): ruff + pytest + `selftest` on push/PR across
      Linux + Windows × py3.11/3.13, plus an isolated wheel-install smoke job.
- [x] Bonus fix (found via the install test): `yhwach` now forces UTF-8 stdout, so persona/report
      output no longer crashes on a legacy Windows console (cp1252) over `→`/`—`/`·`.
- [x] Lint debt cleared: ruff is green (E501 delegated to the formatter; modernizations applied).

### Phase 3 — Test gap + MCP parity ✅ DONE
- [x] `test_cli.py` (CliRunner): command surface + error/exit paths (~19 tests).
- [x] `test_mcp_server.py`: `_bind_signature`, `_load_fastmcp`, `build_server` (registers all tools).
- [x] MCP tools added: `ingest`, `enum`, `probe`, `run`, `proof`, `consume` — the MCP surface is
      now 15 tools, at parity with the CLI. `run` shares `engine.execute_task` with the CLI (no drift).
- [x] Extracted `engine.py` (shared task-execution core) so CLI `run` and `yhwach_run` are one path.
- **Done:** an MCP-only operator can drive ingest → probe → plan → next → run → proof. 228 tests green.

### Phase 4 — Post-foothold movement + tooling ✅ DONE (in-repo parts)
The buildable-in-repo parts landed. The external MCPs (BloodHound, msfconsole) are driven by the
operator, not by Yhwach (Yhwach is itself an MCP *server*, not a client) — their Yhwach-side work is
ingestion + rules, which moves to **Phase 4a** (AD) and a later msf follow-up.
- [x] **Ligolo tunnel-state → `pivoted` predicate**: `tunnel` table + `add_tunnel`/`list_tunnels`;
      `set_host_stage` gates `looted → pivoted` on a tunnel/reachable-subnet via that host
      (realizes the ARCHITECTURE predicate); a `Reachability / pivots` section in the report.
- [x] **Pre-staged tooling wired into the actions layer**: `deploy_ligolo_agent_win` (svcmon.exe)
      and `drop_amsi_revshell_win` (svc.exe/svc.bin) actions.
- [x] **`yhwach pivot` / `yhwach_pivot`**: records the tunnel, renders the deploy (pre-staged
      obfuscated agent for Windows, stock agent otherwise) + Kali-side route, advances the host to
      `pivoted`. Shares `engine.render_pivot` across CLI + MCP. 234 tests green.
- [ ] Deferred (operator-driven / need external servers): **BloodHound MCP** path reasoning (see
      Phase 4a), **msfconsole MCP** exploit/session hand-off, richer HexStrike tool ingestion
      (see Phase 4a).

### Phase 4a — AD enumeration & chaining ✅ tracks 1–2 DONE
HexStrike *runs* AD tools; Yhwach now *parses* their output and *chains* into AD attacks.
- [x] **AD output parsers** (interpret.py, multi-finding via `interpret_all`): netexec/ldapsearch/
      enum4linux/smbmap → findings with chaining tags `smb_signing_off`, `null_session`,
      `ldap_anon`, `domain_users`, `kerberoastable`, `asreproastable`.
- [x] **AD attack rules** (`playbooks/ad.yaml`) gated via `findings_include`: `kerberos_user_enum`
      (fills the port-88 gap), `ldap_anon_dump`, `asrep_roast`, `smb_ntlm_relay`, `kerberoast`
      (host-scoped) — with impacket/kerbrute/ntlmrelayx actions.
- [x] Tests: extractors (multi-signal SMB, ldap_anon, roast hashes, domain_users) + planner chains
      (ldap_anon → ldap_anon_dump; kerberoastable → kerberoast). 241 green.
### Phase 4b — BloodHound ingestion + deeper AD chains ✅ (core done)
- [x] **BloodHound ingestion** (`yhwach ingest --kind bloodhound`, parsers/bloodhound.py): parses
      the normalized AD-facts JSON a BloodHound MCP/Cypher wrapper emits **and** raw SharpHound
      users/computers collection files → findings + tags (`kerberoastable`, `asreproastable`,
      `dcsync`, `unconstrained_delegation`, `acl_abuse`, …) attached to the DC. Forward-compatible:
      unknown edge kinds still become tagged findings.
- [x] **DCSync + unconstrained-delegation rules** (`playbooks/ad.yaml`): `dcsync` → secretsdump,
      `unconstrained_delegation_abuse` → coerce + TGT capture. BloodHound tags also light up the
      existing kerberoast / AS-REP rules. Tests: parser (facts + SharpHound) + ingest→attack chain.
### Phase 4c — ADCS + creds-aware chaining ✅ DONE
- [x] **ADCS (certipy)**: `yhwach ingest --kind certipy` + parsers/adcs.py reads certipy's
      `-vulnerable -json` report → `adcs_vuln` tag; the `adcs_esc_abuse` rule chains to a certipy
      request. High-impact ESCs (1/3/4/6/8/9/11/15) rank critical.
- [x] **Creds-aware kerberoast**: new planner `vault` when-key (`vault: nonempty` matches once the
      engagement has credentials); `kerberoast_with_creds` (surface: ldap + vault) fires from held
      creds, complementing the tag-gated `kerberoast`.
- [x] **GPP-password tag**: the winPEAS parser now tags `gpp_password` → the `gpp_decrypt` rule.
- [x] Tests: certipy parser + ingest→adcs_esc_abuse chain; vault-gated rule needs creds; gpp chain.

### Phase 4d — HexStrike-delegated execution ✅ DONE
- [x] `run_action` gained a `hexstrike` client path: read-only actions execute through HexStrike
      (delegated) with an identical output/loot path, so the interpret extractors ingest the result
      the same way — AD enum output flows straight into the parsers/tags.
- [x] Threaded through `engine.execute_task(hexstrike_url=...)`, `yhwach run --hexstrike-url`, and
      the `yhwach_run` MCP tool (`hexstrike_url`). HexStrike transport errors are captured, not fatal.
- [x] Tests: run_action via a fake client (+ error path); execute_task through HexStrike extracts
      `smb_signing_off` from delegated netexec output.

### Phase 5 — Judgment layer: align docs to reality ✅ DONE (aligned, not built)
The engine is a read-only context handoff; the operator (Claude Code) does the reasoning. We did
NOT build RANK/CRAFT/INTERPRET calls, contract validation, or persona/rules hashing — the docs now
say so.
- [x] ARCHITECTURE: layers show a **Handoff** + operator-side Judgment (not engine LLM calls);
      FSM section splits enforced predicates (looted/pivoted) from aspirational ones; the loop is
      the real operator cycle; "Judgment shapes" are framed as operator discipline (with the one
      deterministic INTERPRET half that is code); determinism section drops the unbuilt hashing/replay.
- [x] persona/contract.md: reframed as the operator's own format + self-check, not engine-validated.
- [x] docs/deploy.md: "Yhwach never calls a model" is stated up front.
- [x] schema: `event.persona_hash`/`rules_hash` marked **reserved (not populated)**; the event
      comment lists the kinds actually written.

### Phase 6 — Polish ✅ DONE
- [x] **Report v2 — timeline**: the report renders a `## Timeline` table from the append-only
      `event` log (ingest / enum / probe / stage / credential / proof / tunnel), each row summarised.
- [x] **Scope validation**: `yhwach engage` rejects a malformed `--scope`; `yhwach enum` refuses an
      out-of-scope `--target` before any HexStrike traffic (`yhwach/scope.py`). Hostname targets warn.
- [x] **`high_ev_leads` auto-P0**: `primitives.p0_leads` surfaces high-EV findings (dcsync,
      kerberoastable, adcs_vuln, chrome/dpapi/gpp/aws loot, …) as a **P0 LEADS** block at the top of
      the `yhwach next --contract` handoff — attack these before the ranked queue.
- [x] **OPSEC invariants** written into the persona: screenshot the win immediately, never drive
      Metasploit through HexStrike, read the vector-DB detection rules first, keep HexStrike loopback.
- [x] **Configurable timeouts**: `YHWACH_RUN_TIMEOUT` (per-action) and `YHWACH_HEXSTRIKE_TIMEOUT`.
- [x] **Newbie setup guide**: [docs/setup.md](docs/setup.md) — Kali prep, toolchain, HexStrike
      (loopback + firewall), Obsidian + Local REST API, MCP registration, pre-staged tooling, smoke test.

**Deliberately not built (documented decisions, not open TODOs):**
- ~~FSM `scanned→enumerated` predicate~~ — **shipped advisory in Phase 8**: `scan_coverage` now
  records what each run covered, `yhwach gaps` evaluates the predicate, and the handoff/`advance`
  warn. It warns rather than refuses because scans legitimately arrive out of band; the two
  predicates that matter for scoring (`foothold→looted` proof, `looted→pivoted` tunnel) stay hard.
- Structured logging framework: the CLI's `click.echo` output *is* the UX; a logging layer adds
  churn without operator value.
- Inline report screenshots + per-finding verbatim repro: the Obsidian Attack Chain note already
  carries reproduction detail + evidence images; the Markdown report links the proof paths.

### Phase 7 — Hardening pass (A-grade) ✅ DONE
Closes the in-repo weaknesses from the assessment; the only remaining A-blocker is a live-lab run.
- [x] **Engagement-scoped findings**: `finding.engagement_id` (derived from the host) + every
      finding query scoped to it — host-less findings no longer leak across labs.
- [x] **Parser hardening + real-output fixtures** (`tests/fixtures/toolout/`, `tests/test_toolout.py`):
      parsers run against realistic netexec / kerbrute / enum4linux-ng / ldapsearch / certipy /
      SharpHound output. `_ad_users` now handles the real formats (`VALID USERNAME:`, `DOMAIN\user`,
      `username:`); `enum4linux_ng` yields both SMB posture and a user list.
- [x] **`$DOMAIN` auto-fill**: the engagement's AD domain fills AD action commands
      (kerberoast/AS-REP/DCSync/certipy); creds stay operator-supplied so secrets never render.
- [x] Regression caught + fixed by the injection-guard test (the `<DOMAIN>` placeholder must be
      exempt from the shell-metachar taint check — it's engagement config, not target-controlled).

### Phase 8 — Operator memory + enumeration coverage ✅ DONE
The three gaps that hurt an LLM operator most: it could not remember its own failures, could not
re-seed itself after a context reset, and could not see under-enumeration.
- [x] **Attempt ledger** (`attempt` table, `yhwach/memory.py`, `yhwach outcome` / `yhwach_outcome`):
      every resolved move is recorded (`success|fail|blocked|partial` + a one-line reason).
      `success` consumes the technique and closes the task; `fail`/`blocked` retire the task and
      halve that rule's EV on that host at the next `plan` (recomputed, never persisted); `partial`
      leaves it queued. Closes the loop that made the queue grow forever — before this, the engine
      never wrote `task.status` outside the planner.
- [x] **DEAD ENDS block** in `yhwach next --contract`: burned moves, per host, with the reason and
      the try count, so a compacted context cannot re-propose them. Persona hard-rule #2 updated.
- [x] **Recall brief** (`yhwach recall` / `yhwach_recall`, `--json`): elapsed, stages, counts, wins,
      dead ends, P0 leads, enum gaps, blocked hosts, recent timeline, next ranked moves — a few
      hundred tokens, persona-free. The first command of a fresh session or a post-`/compact` turn.
- [x] **Cheap turns**: `next --contract --no-persona` sends the frame's sha256 instead of its ~7 KB
      body (≥50% smaller handoff); `next --json` / `yhwach_next(fmt="json")` emit the same slice as
      data, including per-candidate `task_id` and rendered commands.
- [x] **Scan coverage** (`scan_coverage` table, `parsers/nmap.ScanMeta`): nmap ingest now records
      what a run *covered* — port range per protocol, `-sV`, UDP — from `<scaninfo>` + run args
      (XML) or the command line (`-oN`). Recorded by CLI ingest, MCP ingest and HexStrike `enum`.
- [x] **`yhwach gaps` / `yhwach_gaps`** + an ENUM GAPS block in the handoff and in recall: every
      host missing full-TCP / `-sV` / UDP top-100, each with the exact scan that closes it.
      `advance --to enumerated` warns. This is the `scanned→enumerated` predicate from the FSM
      design, shipped as an advisory (see ARCHITECTURE for why it warns instead of refusing).
- [x] Fixed in passing: the CLI's nmap ingest never wrote an `ingest` event, so it was invisible to
      the report timeline and to recall (the MCP path did).
- [x] 40 new tests (`test_memory.py`, `test_coverage.py`, + CLI/MCP parity); 381 green, ruff clean,
      6/6 golden fixtures unchanged.

### Phase 9 — Close the unreachable rules ✅ DONE
Five rules shipped with a `findings_include` tag that **no parser or extractor ever produced**, so
the planner could never fire them — rule, action and payload all present, chain permanently open.
All five were on the scored AI surface.
- [x] **`_ml_supply_chain` extractor** (interpret.py) over tool lists / OpenAPI specs / model
      listings / Gradio APIs → `pickle_endpoint` (unpickling path: `pickle.loads`, `joblib.load`,
      `dill`, `sympify`, unsafe `yaml.load`, `.pkl` route), `model_checkpoint_load` (`torch.load`,
      `load_state_dict`, `.ckpt`/`.pth`/`pytorch_model.bin`) and `training_pipeline`
      (`fine_tuning`, `adapter_config.json`, `peft`, `trainer_state.json`).
- [x] **`_gitlab_ai_pipeline` extractor** over GitLab recon output → `code_scanner`
      (pre-receive / semgrep / SAST / secret-detection) and `ai_code_review` (GitLab Duo, AI
      reviewer bots). Both guards have documented bypasses; naming the guard unlocks them.
- [x] **`_model_artifacts` in the PEAS parser** — post-foothold file evidence: a `.pt`/`.pth`/
      `.ckpt` checkpoint tags `model_checkpoint_load` (severity **high** when linPEAS marks it
      writable — overwrite + next `torch.load()` is RCE), LoRA/trainer artifacts tag
      `training_pipeline`. `.safetensors` is deliberately never a signal.
- [x] **`_chain()` composer** so an action that already had an extractor (`enumerate_models`,
      `mcp_tools_list`) gains a second one instead of silently replacing it.
- [x] Tests (`test_ml_supply_chain.py`, 14): each of the five chains driven end to end — real tool
      output → extractor → tagged finding → `match_rules` → the rule appears in the queue — plus
      false-positive guards (benign tool lists, `yaml.load(Loader=SafeLoader)`, `.safetensors`).
- [x] Audit: **0 of 40 `findings_include` tags are now without a producer** (was 5); all 92 rules
      are reachable and every `emits` maps to a registered action.

**Still open — needs the live lab (not fixable in-repo):**
- [ ] **Field validation**: run a full engagement end-to-end against real HexStrike + netexec +
      BloodHound + certipy, then capture their *actual* output as `tests/fixtures/toolout/` fixtures
      (the `snapshot` self-learning loop). This is the last step to a clean "A".
- [ ] Native BloodHound **CE graph JSON** ingestion (today: the normalized-facts contract + raw
      SharpHound collection files).

The engine is feature-complete against the plan. The original phased scaffold below predates this
build order and is kept for reference.

---

## Phase 0 — Scaffold

- Repository layout, license, authorization notice
- Architecture doc and persona draft
- SQLite schema v0
- First playbook rules (primitives + AI-surface seeds + lore denylist)
- No runnable code yet

## Phase 1 — First vertical slice: AI surface

The differentiator ships first. End-to-end pipeline for one host class:

- Parser: nmap XML -> SQLite (`host`, `service`, `surface` rows)
- Ingestion: `yhwach ingest <file>` populates the DB
- FSM: `undiscovered -> scanned -> enumerated` predicates for AI hosts
- Playbooks: chatbot + Ollama + Gradio + RAG upload + MCP + A2A + vectordb
- Judgment: RANK call over ranked hypotheses, INTERPRET on HTTP probe output
- CLI: `yhwach engage`, `yhwach ingest`, `yhwach next`, `yhwach status`
- Persona: strict Autonomy Contract enforcement
- Obsidian: best-effort sync via MCP; degrade to disk

**Exit criterion:** Yhwach walks a lab from "nmap output" to "proposed injection to run against found chatbot" with the correct rule cited, deterministically.

## Phase 2 — Traditional hosts

- Linux + Windows FSMs
- HexStrike MCP adapter (delegates enumeration; Yhwach never reimplements linpeas/winpeas)
- winPEAS / linPEAS parsers -> structured `finding` rows
- Playbooks: SUID/sudo/cron/capabilities, service versions, AD indicators
- Autonomy gates for exploitation

## Phase 3 — Post-exploitation and pivot

- Credential vault (`credential` table + validation loop)
- Spray primitive (`credential_reuse` across scope)
- Ligolo tunnel state (subnet reachability graph)
- Screenshot binding to `proof` rows (stage guard: `foothold -> looted` refuses without a screenshot row)

## Phase 4 — Test corpus

- Fixture harness (`tests/fixtures/*.yaml`)
- Deterministic-output tests (temperature = 0)
- Golden-Contract regression tests
- Coverage: every rule >= 1 fixture, every fixture >= 1 rule
- Async lab feedback loop: capture, label, add rule, regression-lock

## Phase 5 — Report

- `yhwach render report` — event log -> Obsidian-friendly Markdown report
- Screenshot inline + reproduction commands verbatim
- ATLAS / OWASP-LLM coverage table

## Phase 6 — MCP server

- Expose Yhwach commands as an MCP for Claude Code on Kali
- Structured tool schemas: `yhwach.next`, `yhwach.ingest`, `yhwach.record_proof`, `yhwach.craft`, `yhwach.interpret`
- Operator persona injected on every judgment call — host CLI personality bypassed

## Non-goals

- **Not a headless attacker.** Yhwach proposes; the operator (human + LLM together) exploits.
- **Not a replacement for HexStrike / msf.** It orchestrates them, it doesn't reimplement them.
- **Not for unauthorized targets.** See AUTHORIZATION.md.
