<p align="center">
  <img src="docs/assets/banner.svg" alt="yhwach — AI-Driven Memory & Playbook" width="660">
</p>

**AI-Driven Memory & Playbook — a persistent world-model, lessons-memory and playbook engine for AI-driven security operators.**

Yhwach owns the engagement as **structured data in SQLite**: every host, service, surface, credential, finding and attempt is a typed row. The operator's model reads that memory each turn, so it never re-derives what it already enumerated, never re-attacks a looted host, and never lets under-enumeration quietly go unnoticed. Long-horizon coherence lives on disk, not in a chat window.

> Named after Yhwach — because he sees the future. This engine tries to.

---

## How it works

Yhwach is driven **entirely over MCP** — you register it as an MCP server in your coding-agent CLI (**Claude Code** or **Codex CLI**), and *that* model is the brain. Yhwach never calls a model itself, so **no API key is required**. It splits the work into three parts (see [`AGENT.md`](AGENT.md) for the full architecture):

- **Memory** — a SQLite world model (30+ typed tables) plus the ingest → parsers → interpret pipeline that turns raw tool output into typed findings with chaining tags. The one hard rule: *a fact isn't real until it's a row.*
- **Knowledge** — a **matcher-only recall menu**: 181 playbook technique rules (`playbooks/*.yaml`) that surface *every* applicable technique for a host, so the model picks from a complete menu instead of remembering one. Deterministic chaining (`findings_include`) and safety tags (`read_only` vs. gated) are never left to the model.
- **Brain** — **your MCP client** (Claude Code / Codex CLI). It reads `yhwach brief`, calls the `yhwach_*` tools to enumerate / record / chain, and decides the next move. Yhwach is the memory + the complete recall menu; the model supplies the intelligence.

Deterministic where it must be (state, gating, chaining, coverage), model-driven where it pays (ranking, crafting a payload, interpreting output).

---

## What's inside

- **World model** — hosts / services / surfaces / findings / credentials / attempts / scan-coverage / AD identity graph / loot / objectives / event log.
- **Ingestion** — nmap XML → hosts + services (monotonic per-host FSM); linPEAS/winPEAS → privesc findings; **BloodHound** + **certipy** → AD/AD-CS findings + chaining tags.
- **Surface detection** (live probes) — **AI**: Ollama, OpenAI-compat, chatbot, MCP, Gradio, A2A, vector DBs, plus versioned probes for MLflow/Langflow/Ray/Triton/ComfyUI. **Traditional**: SMB, LDAP, MSSQL, WinRM, SSH, Jenkins, GitLab, Gitea, n8n. **Data stores & cloud**: redis, mongodb, memcached, elasticsearch, kafka, apiserver, kubelet, etcd, docker-API. **Web apps**: grafana, keycloak, minio, confluence, teamcity, nexus, sonarqube, superset, metabase, jupyterhub, nextcloud, artifactory. A `-sV` product string classifies a service on *any* port.
- **"Check every path" coverage** — `yhwach gaps` names every host that isn't full-ported/`-sV`'d/UDP-swept **and** every discovered service that was never triaged (the `service_enum` gap).
- **Offline knowledge, queryable with `yhwach ref`** — packs for `default-creds`, `esc` (AD CS ESC1–16), `gtfobins`, `lolbas`, `wadcoms`, `lessons`, `services` (the service matrix), `tags` (the chaining-tag registry), `arsenal` (a tooling *reference index*; see [`arsenal.manifest.yaml`](arsenal.manifest.yaml)), and `ai-attacks` (the RAG/MCP/A2A/vector-db/cloud attack chains, OWASP-LLM/ATLAS-mapped). Plus an **NVD-verified CVE map** (`yhwach vulns`, version→CVE).
- **Audit lens** — `yhwach audit` reports coverage by standard (ATT&CK / OWASP-LLM / ATLAS / CWE / CVE) and the paths not yet checked; findings are standards-mapped for the write-up.
- **Engagement notebook** — the operator writes detailed, reproducible notes to a local Obsidian vault; the DB is the source of truth for atoms, the vault for the narrative (see [persona/notebook.md](persona/notebook.md)).
- **Live board** *(optional)* — `yhwach ui` renders the world model as a web page (hosts, surfaces, the credential vault, the attack graph).

890+ tests, green on CI. See [ROADMAP.md](ROADMAP.md) for what's next.

> There is also an **experimental self-driving runtime** (yhwach calls a model itself via an API key — brain / judge / orchestrator / workers). It is **not the supported path and needs more work** — see [docs/experimental/](docs/experimental/).

---

## Requirements

- **Python 3.11+** and `git`.
- **SQLite** — bundled with Python (the `sqlite3` stdlib module); nothing to install.
- **An MCP client** — [Claude Code](https://docs.claude.com/en/docs/claude-code) *or* [Codex CLI](https://github.com/openai/codex). This is the "brain"; **no API key is needed for yhwach itself.**
- **A Kali-style offensive toolset on `PATH`** for the commands yhwach records/ingests (nmap, NetExec, impacket, BloodHound, certipy, …). Yhwach *orchestrates and remembers*; it does not reimplement these.
- *Optional:* [HexStrike](https://github.com/0x4m4/hexstrike-ai) as a delegated enumeration backend (loopback-bound).

---

## Install & register as an MCP server

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach && cd ~/yhwach
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[mcp]"      # the engine + the MCP server (no API key)
pytest -q                     # optional: prove the install (pip install -e ".[dev,mcp]")
```

yhwach keeps its state under a workspace dir resolved by `yhwach/config.py`
(`$YHWACH_HOME` → `$XDG_DATA_HOME/yhwach` → `~/.local/share/yhwach`); `$YHWACH_DB`
overrides the DB path directly. Nothing else to configure.

**Claude Code** — register once:

```bash
claude mcp add yhwach -- yhwach mcp
# optional: pin the workspace/DB explicitly
#   claude mcp add yhwach -e YHWACH_HOME=$HOME/.local/share/yhwach -- yhwach mcp
```

**Codex CLI** — add to `~/.codex/config.toml` (see your Codex docs for the exact schema):

```toml
[mcp_servers.yhwach]
command = "yhwach"
args = ["mcp"]
# env = { YHWACH_HOME = "/home/you/.local/share/yhwach" }
```

That exposes the `yhwach_*` tools (`status · brief · next · ingest · enum · probe · gaps · paths · audit · cred · spray · objective · proof · pivot · report · ref · vulns …`) to the model.

---

## Using it

Just talk to your MCP client in plain language — it drives yhwach for you:

> "engage lab01 on 10.10.10.0/24, ingest this nmap XML, probe the surfaces, then brief me and tell me what to do next."

The model reads `yhwach brief` (the AI-legible engagement map), calls `yhwach_*` tools to enumerate, records findings, follows the chaining menu, and keeps the world model honest with `yhwach gaps`. Because the memory lives on disk, the next session (or a context reset) picks up exactly where you left off.

**Human at the terminal?** Every tool is also a plain command — `yhwach brief --lab lab01` prints the same operator context to stdout with no model call at all. The full command reference lives in the docs (below).

*(Optional live view:* `pip install -e ".[ui]"` then `yhwach ui --lab lab01` → `http://127.0.0.1:8799`.*)*

---

## Knowledge references (optional)

yhwach's `ai-attacks` / `ref` packs are self-contained. For deeper "look it up before you attack"
research, it can point you at well-known **public** reference repos you clone yourself — all
optional, none bundled, naming/linking them here is just a reference:

- [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — pentest methodology wiki
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — payloads + bypasses (MIT)
- [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) — AD / internal pentest (MIT)
- [SecLists](https://github.com/danielmiessler/SecLists) — wordlists (MIT)

---

## Development & command reference

The full `yhwach <cmd>` CLI (engage / ingest / probe / next / gaps / paths / audit / report …),
the deployment notes, and the architecture are in the docs:

- [docs/setup.md](docs/setup.md) — full Kali walkthrough (toolchain, MCP wiring, the notebook)
- [docs/install.md](docs/install.md) · [docs/deploy.md](docs/deploy.md) · [docs/agent-mode.md](docs/agent-mode.md)
- [AGENT.md](AGENT.md) — architecture · [docs/prompts/](docs/prompts/) — dev onboarding
- [docs/experimental/](docs/experimental/) — the **experimental** API-key self-driving runtime (WIP)

---

## Authorization

**Yhwach is released for authorized use only** — see [AUTHORIZATION.md](AUTHORIZATION.md). For authorized red-team engagements with written scope, and personal challenge labs you own or are licensed to test (HackTheBox, TryHackMe, PortSwigger). Not for unauthorized targets. Contributors: submit rules and fixtures for authorized-target contexts only, with synthetic/lab data.

---

## License

MIT — see [LICENSE](LICENSE).
