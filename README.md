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

**Working.** The full deterministic engine runs end-to-end — from an nmap scan to a
persona-framed, doctrine-ranked operator brief with concrete commands — and has been
validated against a live challenge lab. 127 tests, green on Linux and Windows.

What works today:

- **World model** — SQLite; hosts / services / surfaces / findings / credentials / tasks / proofs
- **Ingestion** — nmap XML → hosts + services (monotonic host FSM)
- **Surface detection** — AI (Ollama, OpenAI-compat, chatbot, MCP, Gradio, A2A, vector DB) **and**
  traditional (Jenkins, GitLab, SMB, LDAP, MSSQL, WinRM, SSH, web portal), via live probes
- **Planner** — declarative YAML playbooks matched to surfaces, EV-ranked, **AI-first tiering**
- **Primitives** — technique exhaustion (no repeats), lore denylist (OffSec dev-artifact filtering)
- **Actions layer** — every playbook step → concrete command; read-only recon runs itself,
  exploitation is render-only for the operator
- **Findings** — deterministic extraction from action output (unambiguous only; the rest is
  operator judgment via the contract)
- **Operator handoff** — `yhwach next --contract` emits persona + state + ranked candidates + commands
- **Report** — `yhwach report` renders a Markdown engagement report
- **Calibration harness** — YAML fixtures + golden runner + `yhwach snapshot` (a real run becomes a test)

See [ROADMAP.md](ROADMAP.md) for what's next (post-foothold FSM, HexStrike MCP backend).

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
pytest -q            # 127 tests
yhwach selftest      # golden fixtures

# Drive an engagement (authorized targets only):
yhwach engage  --lab lab01 --scope 10.10.10.0/24
yhwach ingest  scan.xml --lab lab01           # nmap -oX output
yhwach probe   --lab lab01                     # AI + traditional surfaces
yhwach plan    --lab lab01                     # match playbooks -> ranked tasks
yhwach next    --lab lab01 --contract          # operator brief for Claude Code
yhwach run     --lab lab01 --task 1 --go       # run read-only recon; render exploits
yhwach findings --lab lab01
yhwach report  --lab lab01 --out report.md
```

Yhwach never auto-runs exploitation — it proposes, and the operator (you, or Claude Code
on Kali) executes with judgment. See [docs/install.md](docs/install.md) and [docs/deploy.md](docs/deploy.md).

---

## License

MIT — see [LICENSE](LICENSE).
