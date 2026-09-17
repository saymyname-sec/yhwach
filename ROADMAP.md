# Roadmap

## Status

**Done and validated on a live challenge lab — Iron Crown (186 tests):**
- ✅ World model (SQLite, 11 tables) + nmap ingestion + host FSM
- ✅ AI-surface probes (Ollama / OpenAI-compat / chatbot / MCP / Gradio / A2A / vector DB)
- ✅ Traditional-surface detection (Jenkins / GitLab / SMB / LDAP / MSSQL / WinRM / SSH / web /
  message brokers)
- ✅ Deterministic planner: 50 YAML technique rules → EV-ranked tasks, AI-first tiering
      (AI, traditional, cloud/k8s, broker, supply-chain, post-exploit); matches surface / auth /
      product / os / `findings_include` (post-foothold chaining — all 50 rules now supported)
- ✅ Cross-cutting primitives: technique exhaustion + credential reuse + lore denylist
- ✅ Actions layer: 96 registered actions (emits → concrete commands); read-only runs
      (untrusted substituted values are shell-guarded), exploitation render-only
- ✅ Deterministic finding extraction from action output (incl. error-based SQLi)
- ✅ Operator handoff: `next --contract` (persona + state + candidates + commands)
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
      Remaining tags to source from detections: `gitlab_token`, `python_requirements`,
      `pickle_endpoint`, `ssrf_confirmed`, `code_scanner`, `training_pipeline`, `ai_code_review`,
      `mcp_config_writable`, `pod_create_permission`, `nvidia_toolkit`, `sagemaker_create_notebook`,
      `jinja2_template`.

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

### Phase 4 — MCP collaboration (named backlog)
- [ ] BloodHound MCP adapter → AD path reasoning into the planner.
- [ ] msfconsole MCP → exploit/session hand-off from proposal-tier actions.
- [ ] Formalize HexStrike-as-MCP (richer ingestion than raw nmap).
- [ ] Ligolo tunnel-state graph → the `pivoted` predicate.
- [ ] Wire pre-staged `~/osai/current/tools/` binaries (`svcmon.exe` Ligolo agent, `svc.exe`/`svc.bin`
      revshell) into the actions layer so the planner emits them directly.

### Phase 5 — Judgment layer: align docs to reality  ✅ DECIDED (align, don't build)
The engine is a read-only context handoff; the operator (Claude Code) does the reasoning. We are NOT
building RANK/CRAFT/INTERPRET calls, contract validation, or persona/rules hashing.
- [ ] Rewrite ARCHITECTURE / persona/contract / deploy so they describe the handoff that ships.
- [ ] Drop or clearly mark the unused `event.persona_hash` / `rules_hash` columns and the
      RANK/CRAFT/INTERPRET framing as "operator-side, not engine calls".

### Phase 6 — Polish
- [ ] Report v2: event-log timeline + inline screenshots + verbatim repro commands.
- [ ] Enforce FSM entry-predicates (`scanned→enumerated`, …) + `high_ev_leads` auto-P0 + OPSEC invariants.
- [ ] Structured logging / config / configurable timeouts; scope validation on `engage`/`enum`.

The original phased plan below is kept for reference; the numbering predates the
build order above.

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
