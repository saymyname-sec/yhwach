# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses a single
pre-release line (`0.1.0`) and groups work under **Unreleased** until a tagged cut.

## [Unreleased]

The real-engagement hardening track — turning yhwach from a CTF tool into an advisor
safe to point at client work. Delivered in phases:

### Added
- **The wire (advisor surface).** `yhwach_interpret` (auto-sniff + ingest any supported
  tool output), `yhwach_attempt` (record a tried move; burned moves retire from recall),
  `yhwach_query` (allowlisted, parameterised views with a JSON/text envelope + paging),
  actionable recall (`data/actions.yaml` — ready commands with `$YH_SECRET` placeholders
  and fold-back hints), a brief governor, and model-legible tool descriptions
  (`yhwach_schema`).
- **Engagement memory ledgers.** notice/comms, activity/traffic, artifact/cleanup, and
  bounty-submission ledgers; a per-instance finding lifecycle with evidence binding and a
  `report --check` QA gate (no report *generation* — the operator writes the report).
- **Ingestion by engagement kind.** Internal AD (secretsdump/potfile, NetExec modules +
  domain facts, Nessus/OpenVAS, masscan/greppable nmap), the credential-reuse attack
  graph (SameHash / LocalAdminReuse / CredValidOn edges), web/bounty (nuclei, httpx /
  subfinder / bbot, Burp/HAR metadata-only capture, web-chaining tags), and cloud
  (kubectl/aws enum, trivy/prowler, Entra/hybrid, CI/CD SARIF/poutine).
- **AI-surface & red-team features.** AI tool/data-source inventory, an indirect-injection
  plant tracker, an MCP tool-list drift probe, a payload ledger with a neutral canary, a
  methodology matrix with host-fact negative evidence, and a role-by-endpoint
  authorization matrix.
- Numbered schema migrations stamped to `PRAGMA user_version` with a schema-parity test.
- `SECURITY.md` and this changelog.

### Changed
- **Advisor-first framing.** The supported runtime is the MCP server (`yhwach mcp`) with
  **no API key**; the MCP client is the brain. `ARCHITECTURE.md` rewritten accordingly;
  `docs/setup.md` no longer installs a global `~/.claude/CLAUDE.md`.
- The CTF/exam methodology router (`agent-mode.md`) moved to `docs/experimental/` as an
  optional lab router — it is no longer part of the supported setup.

### Deprecated
- The self-driving runtime (`yhwach run`, `brain`/`judge`/`orchestrator`/`workers`/
  `providers`, the `[agent]` extra) is experimental and unsupported; see
  `docs/experimental/`.

### Fixed
- A batch of verified safety bugs blocking client use: lockout-threshold misparsing,
  fail-open spray guard, NTLM sprayed with `-p`, API keys sent as Bearer to every web
  root, unscoped scan/enum/probe/spray, a shell-injection f-string, credential re-add
  clobbering the stored secret, and `169.254.169.254` materialised as a target.
- Scan honesty: a `-sn`/`-sL` ping sweep no longer claims top-1000 port coverage; host
  liveness is an `alive`/`unanswered`/`unseen` tri-state.

### Security
- Documentation parity test (`tests/test_docs_commands.py`) asserts every CLI command
  and MCP tool shown in the supported docs actually exists.

## [0.1.0]
- Initial world-model engine, knowledge/recall catalog, MCP server, CLI, and read-only
  board.
