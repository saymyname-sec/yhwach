# Yhwach

**Deterministic red-team engagement engine for the OffSec OSAI exam and authorized AI-security challenge labs.**

Yhwach owns the engagement — the world model, the enumeration state, the ranked next action — as structured data in SQLite. An LLM operator (typically Claude Code on Kali) is called at narrow, typed decision points with fresh minimal context. Long-horizon coherence lives on disk, not in a chat window.

> Named after Yhwach — because he sees the future. This engine tries to.

---

## Why

Prose-driven agents drift. Every operator today re-derives "what stage am I at?" from a 500-line markdown router every turn, forgets to re-recon after a pivot, re-attacks looted hosts, and lets under-enumeration cost points. That is the failure mode Yhwach exists to kill.

Yhwach splits the work:

- **Deterministic engine (Python).** World model, finite-state machine per host, playbook rules as YAML data, EV ranker, autonomy gates. The loop is code, not vibes.
- **LLM operator (any capable model).** Called for three things only — rank hypotheses, craft an injection or payload, interpret a raw tool output. Each call gets *only* the relevant state slice, plus Yhwach's compact operator persona.

The persona travels with the engine. Whatever CLI, host, or client executes the LLM call, Yhwach's frame overrides the host's own personality — the reasoning shape stays the same because Yhwach dictates it.

---

## Status

**Working end-to-end, through post-exploitation.** The deterministic engine runs from an
nmap scan to a persona-framed, doctrine-ranked operator brief with concrete commands, then
carries the engagement through foothold, loot, and pivot — and has been validated against a
live challenge lab (Iron Crown). 274 tests, green on Linux and Windows.

What works today:

- **World model** — SQLite; hosts / services / surfaces / findings / credentials / tasks /
  proofs / tunnels / technique state / event log (12 tables)
- **Ingestion** — nmap XML → hosts + services (monotonic host FSM); linPEAS / winPEAS →
  host-scoped privesc findings; **BloodHound** + **certipy** output → AD / ADCS findings +
  chaining tags on the DC
- **Delegated enumeration** — `yhwach enum` runs nmap through HexStrike (loopback-guarded),
  saves the raw XML to `recon/`, and ingests it; `yhwach run --go --hexstrike-url ...` routes any
  read-only action (netexec / ldapsearch / probes) through HexStrike too, output flowing straight
  into the parsers — Yhwach owns the world model, HexStrike owns tool execution
- **Surface detection** — AI (Ollama, OpenAI-compat, chatbot, MCP, Gradio, A2A, vector DB) **and**
  traditional (Jenkins, GitLab, SMB, LDAP, MSSQL, WinRM, SSH, web portal, message brokers), via
  live probes
- **Planner** — 60 declarative YAML technique rules across AI, traditional, cloud/k8s,
  message-broker, supply-chain, post-exploit, and **Active Directory** (kerberoast / AS-REP /
  NTLM-relay / DCSync / delegation / ADCS) surfaces, matched and EV-ranked with **AI-first
  tiering**; `when` supports surface, auth, product, os, **`findings_include`** chaining, and
  **`vault`** (creds-aware rules)
- **Primitives** — technique exhaustion (no repeats), credential reuse (never exhausted), lore
  denylist (OffSec dev-artifact filtering)
- **Actions layer** — 107 registered actions (`yhwach actions`) turn every playbook step into a
  concrete command; read-only recon runs itself (with untrusted values shell-guarded),
  exploitation is render-only for the operator
- **Findings** — deterministic extraction from action output (unambiguous only; the rest is
  operator judgment via the contract)
- **Post-foothold FSM** — credential vault, `yhwach cred` / `creds` / `spray`, and monotonic
  host stages (`foothold → looted → pivoted → done`) via `yhwach advance`; `yhwach proof` gates
  `foothold → looted` on a flag+screenshot, and `yhwach pivot` records a Ligolo tunnel (deploying
  the pre-staged agent) to gate `looted → pivoted` on real subnet reachability
- **Engagement notebook** — the operator writes detailed notes to an **Obsidian vault** (the
  single source of truth) via the Obsidian MCP at every objective; Yhwach's DB stays the
  queryable world model and never stores notes (see [persona/notebook.md](persona/notebook.md))
- **Operator handoff** — `yhwach next --contract` emits persona + state + ranked candidates + commands
- **Report** — `yhwach report` renders a Markdown engagement report
- **Calibration harness** — YAML fixtures + golden runner + `yhwach snapshot` (a real run becomes a test)
- **MCP server** — `yhwach mcp` exposes the engine to Claude Code on Kali as tools

See [ROADMAP.md](ROADMAP.md) for status and what's next.

---

## Authorization

**Yhwach is released for authorized use only.** See [AUTHORIZATION.md](AUTHORIZATION.md).

Built for:

- The OffSec OSAI certification exam (open-book on tooling per the exam guide).
- Authorized red-team engagements with written scope.
- Personal challenge labs you own or are licensed to test (HackTheBox, TryHackMe, PortSwigger, offsec-hosted challenges).

Not for unauthorized targets. Contributors: submit rules only for authorized-target contexts.

---

## Quick start

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach && cd ~/yhwach
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q            # 274 tests
yhwach selftest      # golden fixtures

# Drive an engagement (authorized targets only):
yhwach engage  --lab lab01 --scope 10.10.10.0/24
yhwach ingest  scan.xml --lab lab01            # nmap -oX output
# or delegate the scan to HexStrike:  yhwach enum --lab lab01 --target 10.10.10.0/24
yhwach probe   --lab lab01                     # AI + traditional surfaces
yhwach plan    --lab lab01                     # match playbooks -> ranked tasks
yhwach next    --lab lab01 --contract          # operator brief for Claude Code
yhwach run     --lab lab01 --task 1 --go       # run read-only recon; render exploits

# Post-foothold:
yhwach advance --lab lab01 --host 10.10.10.15 --to foothold   # auto-notes the milestone
yhwach cred    --lab lab01 --user svc_sql --secret 'S3cr3t!' --kind password
yhwach spray   --lab lab01                     # reuse the vault across sprayable surfaces
yhwach proof   --lab lab01 --host 10.10.10.15 --screenshot flag.png  # -> looted (gated)
yhwach pivot   --lab lab01 --via-host 10.10.10.15 --subnet 10.1.1.0/24  # -> pivoted

yhwach findings --lab lab01
yhwach report  --lab lab01 --out report.md
```

At every objective, the operator writes the detailed write-up into the Obsidian vault via the
Obsidian MCP — the notebook is the vault, not the DB. Run `yhwach mcp` to expose the engine to
Claude Code on Kali as MCP tools (`pip install -e ".[mcp]"`). See [docs/deploy.md](docs/deploy.md).

Yhwach never auto-runs exploitation — it proposes, and the operator (you, or Claude Code
on Kali) executes with judgment.

**New here?** [docs/setup.md](docs/setup.md) is a full, copy-paste, newbie walkthrough — Kali prep,
the offensive toolchain, HexStrike (bound to loopback + firewalled), the Obsidian notebook, and
registering the MCP servers in Claude Code. See also [docs/install.md](docs/install.md) (reference)
and [docs/deploy.md](docs/deploy.md) (MCP details).

---

## License

MIT — see [LICENSE](LICENSE).
