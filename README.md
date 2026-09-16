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

Early scaffold. Design and rules first; Python next; MCP integration after that. See [ROADMAP.md](ROADMAP.md).

Nothing in this repo is runnable yet. What is here:

- Architecture, roadmap, and authorization docs
- Strict operator persona and Autonomy Contract schema
- SQLite world-model schema (`db/schema.sql`)
- Seed playbook rules (primitives, AI-surface, lore denylist)
- CLI / actions / tests scoping docs

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

Not runnable yet. [ROADMAP.md](ROADMAP.md) tracks the milestones; the first runnable slice is the AI-surface pipeline (Ollama + chatbot). See [docs/install.md](docs/install.md) for the intended install shape.

---

## License

MIT — see [LICENSE](LICENSE).
