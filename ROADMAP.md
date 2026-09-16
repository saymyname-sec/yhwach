# Roadmap

## Status

**Done and validated on a live challenge lab — Iron Crown (170 tests):**
- ✅ World model (SQLite, 11 tables) + nmap ingestion + host FSM
- ✅ AI-surface probes (Ollama / OpenAI-compat / chatbot / MCP / Gradio / A2A / vector DB)
- ✅ Traditional-surface detection (Jenkins / GitLab / SMB / LDAP / MSSQL / WinRM / SSH / web /
  message brokers)
- ✅ Deterministic planner: 58 YAML playbook rules → EV-ranked tasks, AI-first tiering
      (AI, traditional, cloud/k8s, broker, supply-chain, post-exploit)
- ✅ Cross-cutting primitives: technique exhaustion + credential reuse + lore denylist
- ✅ Actions layer: 95 registered actions (emits → concrete commands); read-only runs,
      exploitation render-only
- ✅ Deterministic finding extraction from action output (incl. error-based SQLi)
- ✅ Operator handoff: `next --contract` (persona + state + candidates + commands)
- ✅ Post-foothold FSM: credential vault, `spray`, linPEAS/winPEAS parsers,
      `foothold → looted → pivoted → done`
- ✅ HexStrike as the delegated enumeration backend (`yhwach enum`, loopback-guarded)
- ✅ Engagement notebook: the operator writes detailed notes to an Obsidian vault (single source
      of truth) via the Obsidian MCP at every objective; notes never live in the DB
- ✅ Markdown report generation
- ✅ Calibration harness: fixtures + golden runner + `snapshot`
- ✅ Yhwach-as-MCP server for Claude Code (`yhwach mcp`; Path A in docs/deploy.md)

**Remaining (bigger lifts / need design input):**
- ⬜ MCP LLM-delegation tools (`craft` / `interpret`): persona-wrapped model calls handed back
      to the host CLI, not just the read-only context tools shipped today
- ⬜ Report v2: full event-log timeline + inline screenshots + verbatim reproduction commands
- ⬜ Ligolo tunnel state: subnet reachability graph feeding the `pivoted` predicate
- ⬜ BloodHound MCP adapter for AD reasoning

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
