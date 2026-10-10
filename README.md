<p align="center">
  <img src="docs/assets/banner.svg" alt="yhwach — AI pentest knowledge engine" width="660">
</p>

**A memory and playbook for AI-assisted penetration testing: it remembers everything you've found, so you and your agent don't have to.**

A real engagement is long and messy: hundreds of IP addresses, dozens of credentials, several subnets behind pivots, findings that only matter three hosts later. Chat context runs out, notes drift, and the thing that loses you the engagement is rarely a missing exploit — it's forgetting what you already found and what you never checked.

Yhwach is the **memory** for that work. It keeps the whole engagement as **structured data in SQLite** — every host, service, surface, credential, finding, pivot and objective is a typed row — and hands it back to you and your AI agent on demand: what you can reach, what you hold, what is still unexplored, which techniques apply right now, and where the shortest path to your objective runs.

> Named after Yhwach, who sees every possible future. This shows you every option — you pick one.

---

## ⚠️ Read this first — yhwach is not an autonomous pentester

> [!IMPORTANT]
> **Yhwach remembers. It does not plan your attack, and it does not update itself.**
>
> - It **never calls an AI model** and never runs on a schedule. Your MCP client (Claude Code / Codex CLI) is the brain, and **you are in charge of the attack path**.
> - It **knows only what it was told**: tool output you ingested and facts you (or your agent, at your request) recorded. It does not watch your network, your terminal, your files or your notes.
> - **Agent instructions are not enough to keep it current.** Nothing forces an agent to record every new host, credential or finding. If you don't feed yhwach, its picture of the engagement goes stale — and a stale map is worse than none.
> - **Maintaining the memory is part of the job.** You update it regularly, through the whole engagement, the same way you'd keep a lab notebook.
> - **One exception — recording can generate traffic.** Recording a credential (`yhwach_add_cred`) immediately tries it against every matching service already in memory, and an nmap ingest or `yhwach_scan` tries every stored credential against newly found services (via NetExec / curl). Know the lockout policy before you record passwords — see [Before you rely on it](#before-you-rely-on-it).
> - The CLI also contains `yhwach run`, an **experimental, unsupported** loop that calls a model with an API key. It is not part of this workflow — ignore it (details in [docs/experimental/](docs/experimental/)).
>
> This is a different way of working with a pentest tool: **the human drives, the agent executes and records, yhwach remembers.** Used that way, it keeps a long, complicated engagement coherent. Used as a fire-and-forget robot, it won't work.

---

## How it works

| Who | Role |
|---|---|
| **You (human)** | Own the engagement. Choose the attack path, approve every exploit, decide what is worth recording, keep the memory and the notes current. |
| **Your agent** (Claude Code / Codex CLI) | Runs the tools you ask for, reads yhwach's map before suggesting a move, and records results into yhwach when you tell it to. |
| **yhwach** (MCP server) | The memory and the playbook. Stores every fact as a typed row, then answers: *what do we have, what's left, what applies next, how do we get there.* |

Inside yhwach:

- **Memory** — a SQLite database plus parsers that turn saved tool output into typed facts: nmap, linPEAS / winPEAS, NetExec, BloodHound (SharpHound JSON), certipy and web content discovery.
- **Knowledge** — a **recall menu** of ~170 playbook technique rules (`playbooks/*.yaml`) that lists *every* technique matching the current state of a host, so the model picks from a complete menu instead of remembering one. Chaining (a finding unlocking the next technique) and safety tiers (read-only vs. gated) are deterministic, never left to the model.
- **Offline references** — `yhwach_ref` packs: **curated offline subsets** of default creds, AD CS ESC1–16, GTFOBins, LOLBAS and WADComs, plus lessons, the service matrix, the chaining-tag registry, AI-attack chains (OWASP-LLM / ATLAS-mapped) and a tooling index (`yhwach_ref arsenal`). Plus an offline version→CVE map (`yhwach_vulns`). These are subsets — **a miss is not proof that no abuse or CVE exists.**
- **Completeness checks** — `yhwach_gaps` / `yhwach_coverage` name every host that was never fully port-scanned, version-scanned or UDP-swept, and every probed surface of a known service kind that has no finding or attempt yet. Run `yhwach_probe` on a host first so its surfaces are known.

---

## Requirements

- **Python 3.11+** and `git`. **SQLite** comes with Python — nothing to install.
- **An MCP client**: [Claude Code](https://docs.claude.com/en/docs/claude-code) or [Codex CLI](https://github.com/openai/codex). **Yhwach itself needs no API key.**
- **Your usual toolset on `PATH`** (Kali works well): nmap, NetExec, impacket, BloodHound / SharpHound, certipy, … Yhwach records and recalls; it does not replace these tools, and it **ships no offensive binaries** — [`arsenal.manifest.yaml`](arsenal.manifest.yaml) only names and links the tools its playbooks mention, so you can fetch and vet them yourself.
- *Optional:* [HexStrike](https://github.com/0x4m4/hexstrike-ai) bound to loopback, as a delegated enumeration backend.

---

## Install & register as an MCP server

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach && cd ~/yhwach
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[mcp]"                         # add ,ui for the optional live board:  ".[mcp,ui]"
mkdir -p "$HOME/.local/share/yhwach/state"      # the DB directory (your first engage would also create it)
yhwach doctor                                   # preflight check
```

`yhwach doctor` also prints lines about an API key, the `[agent]` extra and HexStrike. Those concern the unsupported self-driving mode or optional backends — ignore them.

Yhwach keeps its database under one workspace: `$YHWACH_HOME`, else `$XDG_DATA_HOME/yhwach`, else `~/.local/share/yhwach` (`$YHWACH_DB` points at a DB file directly). One workspace can hold many engagements — each has its own **lab name**.

**Claude Code** — register once, at **user scope** (so the tools exist in every folder you start Claude Code from, not just this one). Use the absolute path to the venv binary so it works even when the venv isn't activated:

```bash
claude mcp add -s user yhwach -e YHWACH_HOME="$HOME/.local/share/yhwach" -- "$HOME/yhwach/.venv/bin/yhwach" mcp
claude mcp list      # yhwach should show as connected (or run /mcp inside Claude Code)
```

**Codex CLI** — register with the CLI:

```bash
codex mcp add yhwach --env YHWACH_HOME="$HOME/.local/share/yhwach" -- "$HOME/yhwach/.venv/bin/yhwach" mcp
```

…or add it to `~/.codex/config.toml` by hand (TOML does not expand `~` or `$HOME` — **replace `/home/you` with your home directory**):

```toml
[mcp_servers.yhwach]
command = "/home/you/yhwach/.venv/bin/yhwach"
args = ["mcp"]
env = { YHWACH_HOME = "/home/you/.local/share/yhwach" }
```

So that the terminal reads the **same database** as the MCP server, put the same workspace in your shell profile:

```bash
echo 'export YHWACH_HOME="$HOME/.local/share/yhwach"' >> ~/.zshrc     # or ~/.bashrc
```

That exposes 36 `yhwach_*` tools to your agent:

| Purpose | Tools |
|---|---|
| **Feed the memory** | `engage` · `ingest`† · `add_cred`† · `add_finding` · `add_loot` · `set_host` · `add_interface` · `tag` / `untag` · `advance` · `pivot` · `objective` · `poc_step` · `annotate` |
| **Ask the memory** | `status` · `brief` · `next` · `gaps` · `coverage` · `paths` / `path` · `dossier` · `recon` · `findings` · `creds` · `audit` · `ref` · `vulns` · `derive` |
| **Active — sends traffic to targets** | `scan`† · `enum` · `probe` · `spray` |
| **Write-ups** | `poc` · `report` · `export_notes` |

*(each prefixed `yhwach_`, e.g. `yhwach_brief`)*

† **also tries credentials against live services** — `add_cred` sprays the new credential; an nmap `ingest` and `scan` spray stored credentials at newly found services. `vulns` (offline CVE match) and `derive` (candidate passwords) never touch a target.

Most read commands also work in a plain terminal, with no model involved — every one needs `--lab`:

```bash
yhwach status  --lab acme
yhwach brief   --lab acme --section unexplored
yhwach next    --lab acme --host 10.10.10.5
yhwach gaps    --lab acme
yhwach paths   --lab acme
yhwach recon   --lab acme --host 10.10.10.5
yhwach report  --lab acme --out report.md
```

Run `yhwach --help` for the full list (it includes the unsupported `run` — ignore it).

---

## The methodology — working a long engagement with yhwach

This is the core of using yhwach. Think of it as a loop you repeat for the whole engagement — **you** steer it, the agent does the typing, yhwach holds the state.

### 0. Tell your agent the routine

Agent instructions alone won't keep the memory current (see above) — but without them, the agent won't even try. Put something like this in your project's `CLAUDE.md` (Claude Code) or `AGENTS.md` (Codex), and adjust it:

```markdown
## yhwach — engagement memory
- Lab: `acme`. Scope: 10.10.10.0/24. Pass `lab: acme` to every yhwach_* call.
- Start every session with `yhwach_status`, then the `yhwach_brief` sections you need
  and `yhwach_next` for the host you're on. Then read `notes/acme/resume.md`.
- Save every tool's output to a file, then `yhwach_ingest` that file (nmap: `-oX`).
- After any credential, finding, stage change, pivot or flag: record it in yhwach AND
  update the matching note in the same step. Never "later".
- Never re-run an approach listed in `exhausted-approaches.md` without asking me.
- yhwach recalls options; I choose the attack path. Ask before any exploit.
- Before `yhwach_add_cred`, check the lockout policy — recording a credential sprays it.
```

The habit still has to come from you: check that it happened.

### 1. Open the engagement

Give it a lab name and the scope you're authorised for:

> *"Engage lab `acme` on 10.10.10.0/24, domain corp.local, DC 10.10.10.10."*

`yhwach_engage` creates the engagement and adds every in-scope address as an *undiscovered* host, so nothing in scope can be forgotten. Ranges larger than a **/20** are not expanded (engage reports them as skipped) — split them into /20s or smaller, or their hosts only appear once a scan finds them.

### 2. Feed every result — the same moment you get it

After **every** scan or tool run, have the agent ingest the output. What isn't ingested doesn't exist for yhwach.

> *"Ingest that nmap XML into yhwach and tell me what changed."*
>
> *"Ingest the linPEAS output for 10.10.10.5."*

`yhwach_ingest` reads a **saved file**, not pasted text. It creates hosts and services, records how thoroughly each host was scanned, and tags findings so the recall menu can chain them. Every kind except nmap needs the host already in memory (scan it first) and a `host`:

| Tool | What to save and feed |
|---|---|
| **nmap** | `-oX` (best) or `-oN` output file — no host needed, it creates hosts |
| **linPEAS / winPEAS** | the saved stdout + the host it ran on |
| **NetExec** | the saved stdout + the target host |
| **BloodHound** | **unzip** the SharpHound zip and ingest `users_*.json` and `computers_*.json` one at a time, host = the DC |
| **certipy** | output of `certipy find -vulnerable -json`, host = the CA or DC |
| **Web discovery** | gobuster / ffuf / feroxbuster / dirb output, host + the base URL it ran against |
| **Anything else** | no parser over MCP — record it with `yhwach_add_finding` / `yhwach_add_loot`. In a terminal, `yhwach ingest --lab acme --kind raw --title "<title>" --host <ip> <file>` stores it as a finding and keeps the full output as loot |

### 3. Record what no parser can see

Parsers don't read your mind. These you (or the agent, on your word) record explicitly:

| What happened | Record it with |
|---|---|
| Found / cracked a credential | `yhwach_add_cred` — include **where it was found** and **where it works** (`validated_on`). ⚠️ This immediately tries it against matching services. |
| Confirmed a vulnerability or lead | `yhwach_add_finding` — give it a **chaining tag** (see `yhwach_ref tags`) so it shows in the brief and unlocks follow-on techniques |
| Grabbed a file, key or dump | `yhwach_add_loot` (a secret inside it still needs `add_cred`) |
| Learned a hostname / OS / role, or a second NIC | `yhwach_set_host` · `yhwach_add_interface` |
| Got a foothold, looted, finished a host | `yhwach_advance` with a one-line *why* |
| Pivoted into a new subnet | `yhwach_pivot`, **then re-run `yhwach_engage` with the FULL scope** — every earlier range plus the new one, e.g. *"Re-engage lab acme with scope 10.10.10.0/24,172.16.5.0/24"*. Engage **replaces** the scope: anything you leave out is treated as out of scope from then on. |
| Captured a flag / objective | `yhwach_objective` (the proof itself lives in your notes and PoC chain) |
| Did something reproducible | `yhwach_poc_step` — the exact command, its output, any script used |
| Tried something that **didn't** work | `yhwach_annotate` on the host, **one section per approach** (re-annotating a section replaces it) + your *exhausted approaches* note — the note is the durable record |

### 4. Ask before you decide

Before picking the next move, ask yhwach — then **you** choose:

> *"Brief me. What's still unexplored, and what does `next` suggest for 10.10.10.5?"*

| Ask | You get |
|---|---|
| `yhwach_status` | Compact counts — the cheap way to re-orient |
| `yhwach_brief` | The engagement map: what you can **reach**, what you **hold**, live **surfaces**, what's **gated** behind a credential, the **unexplored** frontier, **objectives** — whole, or one section at a time |
| `yhwach_next` | The recall menu: every technique that applies right now, per host, split read-only vs. gated, plus enumeration gaps and untried credentials |
| `yhwach_gaps` / `yhwach_coverage` | Hosts and probed services that were never fully enumerated — and the exact scan that closes each gap |
| `yhwach_paths` | Shortest path from everything you own to each objective and to Domain Admins |
| `yhwach_dossier` / `yhwach_recon` | Everything known about one host |

Yhwach recalls and ranks options; it never decides. The attack path is yours.

### 5. Resume after a break or a context reset

Your chat context will be reset or compacted many times. The memory isn't:

> *"Check yhwach status for lab `acme`, show me the unexplored and objectives sections of the brief, then read my resume note and tell me where we are."*

Start every session with `yhwach_status`, then the `brief` sections you need (`objectives`, `unexplored`, `hold`) and `yhwach_next` for the host you're working, plus `resume.md` in your Obsidian vault (below). A full `brief` or a host-less `next` on a big scope is long — ask for slices.

### Working at scale — many hosts, credentials and subnets

- **Let yhwach hold the lists.** Don't paste hundreds of IPs into chat — ask for slices: one host's `next` / `dossier` / `gaps`, or one `brief` section (`reach`, `hold`, `surfaces`, `unlocks`, `unexplored`, `objectives`).
- **Every new subnet is a new scope.** Record the pivot, re-engage with the **full** scope (old ranges + the new one), then scan and ingest the new segment like a fresh engagement.
- **Credentials are never "used up."** Each one stays in yhwach's credential store and stays relevant for every new host. Record where it works (`validated_on`); failed attempts are logged by the sprays (`yhwach_spray` and the automatic ones).
- **Keep names stable.** One lab name per engagement; set hostnames and roles once so maps and briefs stay readable.

### Keeping the memory honest

At the end of each working session, run through this checklist with your agent:

- [ ] Every scan and tool output from this session is ingested.
- [ ] Every new credential is recorded, with where it works.
- [ ] Every confirmed finding is recorded with a chaining tag.
- [ ] Host stages are advanced (foothold / looted / pivoted / done).
- [ ] Pivots are recorded and the scope re-engaged in full.
- [ ] Failed approaches are noted, so they aren't retried blindly.
- [ ] `yhwach_brief` matches what you believe is true — if it doesn't, fix the memory now (below).
- [ ] Your Obsidian notes are updated (next section).

**Correcting the memory.** Wrong facts will happen in a long engagement. Re-recording the same credential (same identifier and kind) or the same finding (same host, class and title) **updates** it rather than duplicating it. A wrong stage: `yhwach advance --lab acme --host 10.10.10.5 --to <stage> --force --why "<reason>"` in a terminal (the MCP tool won't move a stage backwards). A wrong tag: `yhwach_untag`. Credentials and findings can't be deleted, so for anything else that's wrong or stale, record the correction with `yhwach_annotate` on the host — and fix the note.

*Optional helper:* [`docs/hooks/yhwach-sync-reminder.sh`](docs/hooks/yhwach-sync-reminder.sh) is a Claude Code `PostToolUse` hook that interrupts your agent after offensive commands (NetExec, impacket, certipy, evil-winrm, `ssh user@…`, …) to remind it to record the result. It needs `jq`, the install steps are in the script header, and it's Claude Code only. It's a nudge — it records nothing, and it does not fire after plain nmap or web scans.

### Before you rely on it

> [!WARNING]
> - **Recording can send traffic.** `yhwach_add_cred` immediately tries the new credential against every matching service already in the memory, and an nmap ingest or `yhwach_scan` re-tests stored credentials against new services — real authentication attempts. Know the lockout policy before recording passwords, and stay within your authorised scope.
> - **You enforce the scope.** The active tools (`scan`, `enum`, `probe`, `spray`) act on whatever you point them at.
> - **Secrets are stored and shown in clear** — to the model (`yhwach_creds`) and on the live board. The board's `--redact` masks only part of it (see [Live board](#live-board-optional)).

---

## Notes with Obsidian

Yhwach and your notes have **separate jobs**, and keeping both current is on you:

- **Yhwach DB = the facts** — hosts, services, credentials, findings, stages, pivots. Queryable, structured, the source of truth for *what*.
- **Obsidian vault = the story** — how you got in, why a path worked, the reproducible chain behind every flag. The source of truth for *how* and *why*.

> [!NOTE]
> **Yhwach never reads your Obsidian vault, and nothing syncs the two automatically.** Your agent writes notes with its normal file tools — when you ask it to. Record the fact in yhwach and write the note in the same step, every time.

### What yhwach generates for you

| Command | Produces |
|---|---|
| `yhwach export-notes --lab acme --out <obsidian-vault>/acme/_yhwach` | Inventory notes built from the DB — *Services & Software*, *Vulnerabilities*, *Web*, *Users & Groups*, *Shares* — and one `hosts/<host>.md` per host, **including every in-scope address not yet scanned** (a /24 means ~254 files; keep the folder collapsed or excluded from graph view). **Each run overwrites these files**, so export them into their own subfolder and never type your own prose into them. Re-export after big ingests. |
| `yhwach_poc_step` → `yhwach poc --lab acme --objective <name> --out <obsidian-vault>/acme/chains/<name>.md` | A reproducible chain: every step's command, output, script and source, in order — the backbone of your write-up. Without `--out` it is written to `~/.local/share/yhwach/chains/`, **outside your vault and shared by every lab** — so use objective names that are unique across engagements. |
| `yhwach report --lab acme --out report.md` | A full Markdown engagement report: findings, hosts, pivots and the timeline. |
| `yhwach recon --lab acme --host 10.10.10.5` | Everything known about one host — paste it into a note. |

### What you write (or ask your agent to write)

A note set that works well, one folder per engagement:

| Note | Holds |
|---|---|
| `index.md` | Status board — links to every note, hosts / findings / credentials at a glance |
| `overview.md` | The 30-second summary and one line per objective |
| `attack-chain.md` | The end-to-end kill path, newest phase last |
| `credentials.md` | Every credential: value, where it's valid, how it was obtained |
| `network-map.md` | Subnets, routes, pivots, tunnels — who reaches what |
| `next-steps.md` | Open leads, in order |
| `exhausted-approaches.md` | Dead ends and decoys, **with why** they failed — never re-try blindly |
| `resume.md` | Where you stopped and the very next move — read it first after any break |
| `hosts/`, `findings/`, `chains/` | Your own per-host narrative, one note per finding, and the per-flag reproducible chains |

The rule that makes it work: **every time something lands in yhwach, the matching note gets updated in the same step** — and before you end a session, `resume.md` is current.

---

## Live board (optional)

```bash
pip install -e ".[ui]"
yhwach ui --lab acme --redact      # http://127.0.0.1:8799 — read-only view of the memory
```

A read-only web view of hosts, surfaces, the credential vault, the network / pivot map, PoC chains and the report. It binds to localhost by default.

`--redact` masks secrets in the credential vault and withholds finding evidence, host dossiers and notes on the board. It does **not** redact the **PoC chains** page or the **full-report download** — those still show stored secrets. Don't screen-share or expose those pages.

---

## Knowledge references (optional)

The `yhwach_ref` packs are self-contained. For deeper "look it up before you attack" research, these well-known **public** references are worth keeping locally — optional, none of them bundled:

- [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — pentest methodology wiki
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — payloads and bypasses (MIT)
- [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) — Active Directory and internal pentest (MIT)
- [SecLists](https://github.com/danielmiessler/SecLists) — wordlists (MIT)

The tooling index (`yhwach_ref arsenal`) and the deploy commands `yhwach_pivot` suggests (ligolo-ng, chisel, …) refer to tools yhwach does **not** ship — fetch the ones you want from the links in [`arsenal.manifest.yaml`](arsenal.manifest.yaml).

---

## Authorization

**Yhwach is released for authorized use only** — see [AUTHORIZATION.md](AUTHORIZATION.md). Use it on engagements with written scope, and on challenge labs you own or are licensed to test (HackTheBox, TryHackMe, PortSwigger). Never on targets you aren't authorised to test.

---

## License

MIT — see [LICENSE](LICENSE).
