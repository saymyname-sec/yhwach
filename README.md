# Yhwach

**AI-Driven Memory & Playbook — a persistent world-model, lessons-memory and playbook engine for AI-driven security operators.**

Yhwach owns the engagement as **structured data in SQLite**: every host, service, surface, credential, finding and attempt is a typed row. The operator's model reads that memory each turn, so it never re-derives what it already enumerated, never re-attacks a looted host, and never lets under-enumeration quietly go unnoticed. Long-horizon coherence lives on disk, not in a chat window.

> Named after Yhwach — because he sees the future. This engine tries to.

---

## How it works

Yhwach splits the work into three parts (see [`AGENT.md`](AGENT.md) for the full architecture):

- **Memory** — a SQLite world model (30+ typed tables) plus the ingest → parsers → interpret pipeline that turns raw tool output into typed findings with chaining tags. The one hard rule: *a fact isn't real until it's a row.*
- **Knowledge** — a **matcher-only recall menu**: 181 playbook technique rules (`playbooks/*.yaml`) that surface *every* applicable technique for a host, so the operator picks from a complete menu instead of remembering one. Deterministic chaining (`findings_include`) and safety tags (`read_only` vs. gated) are never left to the model.
- **Brain** — the LLM that reasons over the memory, picks the next move, and rules a phase "done". It can be **Claude Code driving over MCP (no API key)** or **yhwach's own self-driving loop (API key)** — see [Two ways to run it](#two-ways-to-run-it).

Deterministic where it must be (state, gating, chaining, coverage), model-driven where it pays (ranking, crafting a payload, interpreting output).

---

## What's inside

- **World model** — hosts / services / surfaces / findings / credentials / attempts / scan-coverage / AD identity graph / loot / objectives / event log.
- **Ingestion** — nmap XML → hosts + services (monotonic per-host FSM); linPEAS/winPEAS → privesc findings; **BloodHound** + **certipy** → AD/AD-CS findings + chaining tags.
- **Surface detection** (live probes) — **AI**: Ollama, OpenAI-compat, chatbot, MCP, Gradio, A2A, vector DBs, plus versioned probes for MLflow/Langflow/Ray/Triton/ComfyUI. **Traditional**: SMB, LDAP, MSSQL, WinRM, SSH, Jenkins, GitLab, Gitea, n8n. **Data stores & cloud**: redis, mongodb, memcached, elasticsearch, kafka, apiserver, kubelet, etcd, docker-API. **Web apps**: grafana, keycloak, minio, confluence, teamcity, nexus, sonarqube, superset, metabase, jupyterhub, nextcloud, artifactory. A `-sV` product string classifies a service on *any* port.
- **"Check every path" coverage** — `yhwach gaps` names every host that isn't full-ported/`-sV`'d/UDP-swept **and** every discovered service that was never triaged (the `service_enum` gap).
- **Offline knowledge, queryable with `yhwach ref`** — ten packs: `default-creds`, `esc` (AD CS ESC1–16), `gtfobins`, `lolbas`, `wadcoms`, `lessons` (past-lab knowledge), `services` (the service matrix), `tags` (the chaining-tag registry), `arsenal` (the vendored offensive-tooling index), and `ai-attacks` (the RAG/MCP/A2A/vector-db/cloud attack chains, OWASP-LLM/ATLAS-mapped). Plus a **55-entry, NVD-verified CVE map** (`yhwach vulns`, version→CVE).
- **Audit lens** — `yhwach audit` reports coverage by standard (ATT&CK / OWASP-LLM / ATLAS / CWE / CVE) and the paths not yet checked; findings are standards-mapped for the write-up.
- **Autonomous runtime** — brain (SDK caller), per-host workers, policy/budgets, action executor, a separate **judge** that rules phases done, an orchestrator loop, a **State + Next Steps** report, a DB-mediated **kill/approve** control channel, and a live board.
- **Engagement notebook** — the operator writes detailed, reproducible notes to a local Obsidian vault; the DB is the source of truth for atoms, the vault for the narrative (see [persona/notebook.md](persona/notebook.md)).

600+ tests, green on Linux CI. See [ROADMAP.md](ROADMAP.md) for what's next.

---

## Install

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach && cd ~/yhwach
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"      # engine + tests
pytest -q

# optional extras — install what you use:
pip install -e ".[mcp]"          # expose yhwach to Claude Code as MCP tools  (no API key)
pip install -e ".[agent]"        # yhwach's own LLM brain, Anthropic — needs ANTHROPIC_API_KEY
pip install -e ".[agent-openai]" # yhwach's own LLM brain, OpenAI — needs OPENAI_API_KEY
pip install -e ".[ui]"           # the live board (FastAPI + uvicorn)
```

Build the engagement memory (authorized targets only):

```bash
yhwach engage --lab lab01 --scope 10.10.10.0/24
yhwach ingest scan.xml --lab lab01            # nmap -oX output  (or: yhwach enum … via HexStrike)
yhwach probe  --lab lab01                     # detect AI + traditional surfaces
yhwach brief  --lab lab01                     # the AI-legible engagement map
```

---

## Two ways to run it

Yhwach is the same memory + knowledge either way — you only choose **who supplies the intelligence**.

### A · Driven by Claude Code — **no API key**

Claude Code (or any MCP client) is the operator. Register yhwach as an MCP server; Claude reads `yhwach brief` and calls the `yhwach_*` tools to enumerate, record findings, and chain. **Yhwach never calls a model itself, so no `ANTHROPIC_API_KEY` is needed** — the intelligence is your Claude Code session's.

```bash
pip install -e ".[mcp]"
# register once; the lab DB is resolved from $YHWACH_DB
YHWACH_DB=$YHWACH_DATA_DIR/state/yhwach.db  claude mcp add yhwach -- yhwach mcp
```

Then just talk to Claude Code ("engage lab01 on 10.10.10.0/24, scan and triage everything"). This is the simplest path. Pure-terminal variant: `yhwach brief` prints the operator context to stdout and you act on it yourself — no model call at all. See [docs/deploy.md](docs/deploy.md).

### B · Self-driving — **with an API key**

Yhwach's own brain drives the loop: it reasons over each host's memory slice, picks moves, runs read-only recon for real, and a separate judge calls "done". Read-only runs unattended; exploit/destructive moves are **queued for approval**, never auto-run.

```bash
pip install -e ".[agent]"                # Anthropic (default)
export ANTHROPIC_API_KEY=sk-ant-...
yhwach run --lab lab01 --fan-out --hexstrike-url http://127.0.0.1:8888
yhwach ui  --lab lab01            # watch live at http://127.0.0.1:8799 (approve / KILL)
```

**Anthropic or OpenAI — swap without code changes.** The brain calls the model through a provider adapter; the provider is picked at runtime and both keys can coexist in the environment. Precedence: `--provider` → `YHWACH_PROVIDER` → the model id (`claude*` / `gpt*`) → whichever key is set (both set with no other signal is an error, not a guess).

```bash
pip install -e ".[agent-openai]"         # OpenAI
export OPENAI_API_KEY=sk-...
yhwach run --lab lab01 --provider openai            # or just: --model gpt-5
```

Behind a custom or **Azure API Management** gateway (custom base URL, `api-key` header, `api-version`, Responses API — e.g. `gpt-5.6-sol`)? Set the `YHWACH_OPENAI_*` env vars from [docs/openai-azure-responses.md](docs/openai-azure-responses.md); no code change.

Useful flags: `--host IP` (one host) · `--max-actions N` (budget) · `--allow-gated` (run exploit-tier unattended, never destructive) · `--provider {anthropic,openai}` · `--model ID`. Each run ends with a **State + Next Steps** report.

> **No key, no model — just the mechanics?** `yhwach run --lab lab01 --dry-run` walks the whole loop (candidates → execute → judge → report) deterministically, for a demo or a test.

---

## Everyday commands

```bash
yhwach next   --lab lab01                        # the recall menu: what to do next + what you're about to miss
yhwach vulns  --lab lab01                       # version -> CVE (offline, NVD-verified map)
yhwach gaps   --lab lab01                        # what isn't fully enumerated yet
yhwach coverage --lab lab01                      # world-model honesty score + per-host gaps with the exact fix
yhwach paths  --lab lab01                        # shortest owned -> objective / Domain Admins attack paths
yhwach objective --lab lab01                      # engagement scoreboard: record flags/objectives + points, capture, see pace
yhwach audit  --lab lab01                        # coverage by standard + paths not checked
yhwach ref    esc --query esc9                   # query a knowledge pack (esc/lolbas/wadcoms/…)
yhwach cred   --lab lab01 --user svc --secret 'S3cr3t!' --kind password
yhwach recon  --lab lab01 --host 10.10.10.15     # full per-host picture
yhwach report --lab lab01 --out report.md        # Markdown engagement report
yhwach status --lab lab01
```

---

## Authorization

**Yhwach is released for authorized use only** — see [AUTHORIZATION.md](AUTHORIZATION.md). For authorized red-team engagements with written scope, and personal challenge labs you own or are licensed to test (HackTheBox, TryHackMe, PortSwigger). Not for unauthorized targets. Contributors: submit rules and fixtures for authorized-target contexts only, with synthetic/lab data.

**New here?** [docs/setup.md](docs/setup.md) is the full copy-paste walkthrough (Kali prep, the toolchain, HexStrike bound to loopback, the notebook, and registering the MCP server in Claude Code).

---

## License

MIT — see [LICENSE](LICENSE).
