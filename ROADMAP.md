# Roadmap

## Status

**Done and validated on a live challenge lab — Iron Crown (186 tests):**
- ✅ World model (SQLite, 11 tables) + nmap ingestion + host FSM
- ✅ AI-surface probes (Ollama / OpenAI-compat / chatbot / MCP / Gradio / A2A / vector DB)
- ✅ Traditional-surface detection (Jenkins / GitLab / SMB / LDAP / MSSQL / WinRM / SSH / web /
  message brokers)
- ✅ Deterministic planner: 50 YAML technique rules → EV-ranked tasks, AI-first tiering
      (AI, traditional, cloud/k8s, broker, supply-chain, post-exploit); 32 fire today, 18 await
      `findings_include` support (see Remaining)
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

**Remaining (bigger lifts / need design input):**
- ⬜ **`findings_include` planner support** — the single highest-leverage gap: 18 of 50 rules
      (all post-foothold chaining: supply-chain, cloud/k8s, RAG-advanced, privesc) gate on a
      `findings_include` `when`-key the matcher does not implement (`planner.py` SUPPORTED_WHEN_KEYS),
      so they never fire and ~30 of their actions are unreachable via `plan`/`next`. Needs a
      finding-tag convention (a `tag` on `finding`, set by the interpret extractors) that the
      matcher can query.
- ⬜ **Packaging for non-editable installs** — `db/schema.sql`, `persona/*.md`, `playbooks/*.yaml`
      live outside the package and aren't bundled; a `pip install` wheel (non-`-e`) ships without
      them and `plan`/`next`/`engage` fail. Add `force-include` + installed-path fallbacks.
- ⬜ **Doc-vs-reality: judgment layer** — ARCHITECTURE/persona/contract describe RANK/CRAFT/INTERPRET
      LLM calls, JSON Autonomy Contract validation, and persona/rules content-hashing into `event`
      (schema has `persona_hash`/`rules_hash` columns, never written). Today it's a read-only text
      handoff. Either implement these or align the docs to what ships.
- ⬜ **Test + CI coverage** — `cli.py` (largest module, entire user surface) and `mcp_server.py`
      have no dedicated tests; no CI runs the suite / `selftest` on push.
- ⬜ **MCP tool parity** — the MCP exposes status/plan/next/findings/report/spray/creds/advance but
      not `ingest`/`enum`/`probe`/`run`/`proof`/`consume`, so an MCP-only operator can't advance the
      world model without dropping to the CLI.
- ⬜ MCP collaboration: drive **HexStrike**, **BloodHound**, and **msfconsole** as MCP servers
      the operator (and Yhwach) coordinate — HexStrike is a REST client today (`yhwach enum`);
      BloodHound feeds AD path reasoning; msfconsole handles exploit/session hand-off
- ⬜ MCP LLM-delegation tools (`craft` / `interpret`): persona-wrapped model calls handed back
      to the host CLI, not just the read-only context tools shipped today
- ⬜ Report v2: full event-log timeline + inline screenshots + verbatim reproduction commands
- ⬜ Ligolo tunnel state: subnet reachability graph feeding the `pivoted` predicate
- ⬜ Pre-staged tooling actions: wire `~/osai/current/tools/` (`svcmon.exe` obfuscated Windows
      Ligolo agent, `svc.exe`/`svc.bin` AMSI-bypass revshell) into the actions layer so the
      planner emits them directly (persona already directs the operator to use them)

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
