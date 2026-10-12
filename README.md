<p align="center">
  <img src="docs/assets/banner.svg" alt="yhwach — AI pentest knowledge engine" width="660">
</p>

**A memory and playbook for AI-assisted penetration testing: it remembers everything you've found, so you and your agent don't have to.**

Yhwach is the **memory** for that work. It keeps the whole engagement as **structured data in SQLite** — every host, service, surface, credential, finding, pivot and objective is a typed row — and hands it back to you and your AI agent on demand: what you can reach, what you hold, what is still unexplored, which techniques apply right now, and where the shortest path to your objective runs.

> Named after Yhwach, who sees every possible future. This shows you every option — you pick one.



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
pip install -e ".[mcp,ui]"                      # mcp = the server; ui = the board (recommended — see below)
mkdir -p "$HOME/.local/share/yhwach/state"      # the DB directory (your first engage would also create it)
yhwach doctor                                   # preflight check
```

`yhwach doctor` also prints lines about the optional `[mcp]`/`[ui]` extras and HexStrike reachability — install what you need and ignore the rest. It needs no API key.

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

That exposes the full `yhwach_*` toolset to your agent (run `yhwach schema` to list every one):

| Purpose | Tools |
|---|---|
| **Feed the memory** | `engage` · `ingest`† · `add_cred`† · `add_finding` · `add_loot` · `set_host` · `add_interface` · `tag` / `untag` · `advance` · `pivot` · `objective` · `poc_step` · `annotate` |
| **Ask the memory** | `status` · `brief` · `next` · `gaps` · `coverage` · `paths` / `path` · `dossier` · `recon` · `findings` · `creds` · `audit` · `ref` · `vulns` · `derive` |
| **Active — sends traffic to targets** | `scan`† · `enum` · `probe` · `spray` |
| **Write-ups** | `poc` · `report` · `export_notes` |

*(each prefixed `yhwach_`, e.g. `yhwach_brief`)*

† **also tries credentials against live services** — `add_cred` sprays the new credential; an nmap `ingest` and `scan` spray stored credentials at newly found services. `vulns` (offline CVE match) and `derive` (candidate passwords) never touch a target.

### What sends traffic, and when

Most of yhwach is a local memory you read and write — it sends nothing. Only a few actions reach a target, and even those are gated:

| Action | Traffic to a target? | When |
|---|---|---|
| `status` · `brief` · `next` · `gaps` · `paths` · `dossier` · `recon` · `findings` · `creds` · `audit` · `ref` · `vulns` · `query` | **No** | pure reads over the local DB |
| `ingest` / `interpret` (paste tool output), `add_finding`, `tag`, notes | **No** | parse/record text you already have |
| `enum` · `probe` · `spray` · `scan` | **Yes** | active scanning and real authentication attempts |
| `add_cred` | **Yes** | immediately sprays the new credential at every matching service already in memory |
| nmap `ingest` / `scan` | **Yes** | re-tests stored credentials against newly discovered services |

And the gates that sit in front of every traffic-sending action:

- **Record-only by default.** Outside `lab`/`ctf` engagements, scan/enum/probe/spray are refused until a human runs **`yhwach arm`** in a terminal — arming is never an MCP argument, so the model can ask for it but cannot do it.
- **Dumped hashes and cracked passwords never auto-spray.** They are `manual`; only a credential you name explicitly is ever sprayed.
- **Scope is a chokepoint.** An empty scope refuses everything; exclusions win over inclusions.
- **`YHWACH_AUTOSPRAY=0`** is a hard kill switch that disables every active path.

`yhwach doctor --lab <name>` prints the current traffic state (armed? in scope?) in one line.

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

Run `yhwach --help` for the full list.

---

## The methodology — how to prompt your agent

yhwach is just memory; the discipline is the agent's. The one rule that makes it work: **the agent must fold every result into yhwach the moment it gets it** — hosts, creds, findings as they appear — because a stale memory is worse than none. The loop:

- **Open** — `yhwach_engage` with the lab name and authorised scope; every in-scope address becomes an undiscovered host.
- **Ingest** — after every scan/tool run, save the output to a file and `yhwach_ingest` it (nmap: `-oX`).
- **Record** — `yhwach_add_cred` and `yhwach_add_finding` for what no parser sees — with where a credential was found and where it works.
- **Ask** — `yhwach_status`, then `yhwach_brief` / `yhwach_next` / `yhwach_gaps` for what applies now; yhwach recalls the options, you pick the path.
- **Resume** — after any context reset, `yhwach_status` plus the `brief` sections you need; the chat forgets, the memory doesn't.

Put the routine where the agent will read it — `CLAUDE.md` (Claude Code) or `AGENTS.md` (Codex):

```markdown
## yhwach — engagement memory
- Lab: `acme`. Pass `lab: acme` to every yhwach_* call.
- Start each session with `yhwach_status`, then the `yhwach_brief`/`yhwach_next` slice you need.
- Save every tool's output to a file, then `yhwach_ingest` it (nmap: `-oX`).
- Record every credential/finding the moment it appears (`yhwach_add_cred`, `yhwach_add_finding`),
  with where it was found and where it works. Never "later".
- `yhwach_add_cred` sprays the credential — check the lockout policy first.
- yhwach recalls options; I choose the path. Ask before any exploit.
```

Every tool has a terminal mirror (`yhwach status`, `yhwach ingest …`) for driving without an agent.

### Before you rely on it

> [!WARNING]
> **Recording can send traffic.** `yhwach_add_cred` immediately tries the new credential against every matching service already in memory, and an nmap ingest or `yhwach_scan` re-tests stored credentials against newly found services — real authentication attempts. Know the lockout policy before you record passwords, and stay within your authorised scope.

---

## The board — how you drive

**Run the board. It's not a dashboard you glance at — it's how you steer the engagement.** Your agent works one host at a time through a narrow window; the board is where *you* see the whole estate at once and spot what it skipped. Keep it open the whole time.

```bash
yhwach ui --lab acme --redact      # http://127.0.0.1:8799 — read-only, binds to localhost
```

Eight pages, each answering one question. The screenshots below are a small fictional engagement (`acme`).

### Board — *where do I stand, and what's possible right now?*

The landing page. Scored tiles at the top (points, hosts owned, pending scans, enum honesty, findings), then the **applicability inventory**: every technique that applies to the current state, split read-only vs. gated — the same recall menu as `yhwach_next`, across the whole estate. Below it, the coverage panel (*what you still owe*, with the exact scan to close each gap) and the hosts-by-stage columns.

![The board page](docs/assets/board-overview.png)

### Recon — *what has actually been looked at, per host?*

The completeness check. One row per host; columns for full-port, version scan, UDP, services, surfaces, web paths, shares, principals, credential tries. A ✓ is a checked box, an ✗ is an open door. Thinnest hosts sort to the top. The scan ledger below shows the exact `nmap` argv behind every row. **This is the page you read before calling a host done** — and the one that shows you the port nobody enumerated.

![The recon / enumeration-coverage page](docs/assets/board-recon.png)

### Surfaces — *what's listening, and how much do we know about it?*

Every service, version and web path in one inventory, plus a decoded view of AI surfaces (models, tools, endpoints a probe found) and a payloads-sent/answered log. This is where you browse ports and protocols looking for the next lead to hand the agent.

### Identity — *what do we know about the AD, and what haven't we collected?*

Password policy (and a loud warning when the lockout policy is unknown — spraying blind can lock out the estate), the principal roster, rights per principal, shares, and an "AD world model" panel that names what has **not** been collected yet, so an empty Groups panel never reads as "the domain is flat".

### Map — *what can I reach, and what's still dark?*

The pivot tree: every host as a node coloured by stage, tunnels drawn as edges, and per-subnet rollups (discovered / owned / open ports / pending / undiscovered). A subnet behind a tunnel with nothing discovered inside shows as reachable-but-empty — a whole segment waiting to be scanned. Click any node for its host page.

![The network map / pivot tree](docs/assets/board-map.png)

### Vault — *which credentials open what, and where haven't they been tried?*

The credential vault (secret, what it opens, where it's validated, provenance), then the **credential × service matrix**: every credential is a row, every reachable service a column, each cell green (works / admin), red (failed) or grey (never tried). The grey cells are the question *"have my creds been tried everywhere they could be?"* — answered at a glance.

![The credential vault and credential × service matrix](docs/assets/board-vault.png)

### PoC — *can I prove what I captured?*

Every objective and whether it has a reproducible chain behind it — including captured flags with **zero** recorded steps, the case that quietly loses points. Expand one to see its steps.

### Report — *what can the write-up not yet support?*

An evidence gap list (findings with no evidence line, captures with no chain, loot recorded but not saved locally), then the engagement-state summary and the full Markdown report, with both report files as downloads.

### The host page

Click a node on the map for one host's full picture: a dossier (*what this box is · what we hold here · open leads · what's still dark*), stage history, open ports, findings and every attempt run against it.

![A single host's focus page](docs/assets/board-host.png)

> [!WARNING]
> `--redact` masks secrets in the credential vault and withholds finding evidence, host dossiers and notes. It does **not** redact the **PoC** page or the **full-report download** — those still show stored secrets. The board binds to localhost; don't expose it or screen-share those two pages.

---

## Notes with Obsidian

Yhwach holds the **facts**. Your Obsidian vault holds the **story and the evidence**: how you got in, why it worked, and the proof. **The report is written from the vault, not from yhwach.**

> [!NOTE]
> **Yhwach never reads your Obsidian vault, and nothing syncs the two automatically.** Your agent writes notes with its normal file tools — when you ask it to. Record the fact in yhwach and write the note in the same step, every time.

The advice below comes from reviewing the vaults of real, finished engagements: a handful of notes carried the entire report, while others were created at kickoff and never filled. Put your effort where it pays. One folder per engagement, e.g. `~/notes/acme/`.

### Report notes — these become the report

| Note | Holds |
|---|---|
| `chains/<ID>-<host>-<technique>.md` | **One per flag / objective — the deliverable.** Seven fixed sections ([below](#the-chain-note)): every command, its output and a screenshot, start to flag. |
| `screenshots/` | Proof images, each paired with a `.txt` of the same command's output — made by [`docs/hooks/yhwach-shot.sh`](docs/hooks/yhwach-shot.sh) and embedded in the chain notes. |
| `credentials.md` | A **master table at the top**: principal · secret · where it works · how it was obtained (link the chain) · last verified · durable or ephemeral. Move superseded values to a section at the bottom instead of correcting them in prose further down. |
| `attack-chain.md` | The narrative: one dated phase per step forward, each linking its chain note. It becomes the report's summary. |
| `scripts/` | Every exploit or helper you ran, with a header: what it does, where it came from, what you changed, how you ran it. Feeds *Source & modifications*. |
| `loot/` | Small text loot (keys, configs) and an `.ORIGINAL` copy of every file you overwrite on a target, for cleanup. Large dumps stay outside the vault, referenced by path and hash. |
| `index.md` | The status board while you work. At the end, the **submission summary**: one row per flag with its chain link and its proof **embedded** (a plain filename renders nothing). |

### Working notes — keep you oriented, stay out of the report

| Note | Holds |
|---|---|
| `resume.md` | **One** rolling note, **overwritten** each session: where you are, how to reconnect, which access is durable (credentials, keys) and which is ephemeral (shells, tunnels, sessions), the next three moves, cleanup owed. Read it first after any break. |
| `next-steps.md` | Open leads, ranked. What's left at the end becomes the report's *not captured* section. |
| `exhausted-approaches.md` | Each dead end: what you tried, the result, **how confident** you are and **what you assumed** (tunnel up, fresh token, right credentials) — so it gets re-tested when that changes. Move an entry out when it turns out to work. |
| `hosts/<host>.md` | One per host you touch, under **one** canonical name. Keep its status lines (access, privesc, loot, link to its chain) **updated in place**, not as appended session logs, and update it after exploitation, not only at recon. |
| `network-map.md` | Subnets, routes, pivots and tunnels — and which of them die on a revert. |

### Skip these — they ended up empty

- **A new resume note every session.** They pile up and contradict each other. Keep one `resume.md`; archive old versions to `sessions/<date>.md`.
- **An `overview.md` written at kickoff.** Nobody updates it. Keep the summary in `index.md`, or write the overview at the end.
- **A half-used `findings/` folder.** Either one note per vulnerability (severity, evidence embed, link to its chain), or let section 2 of each chain note be the finding. Half-done leaves orphans.
- **`yhwach export-notes` inventory notes** (*Services & Software*, *Shares*, *Users & Groups*, *Vulnerabilities*, *Web*). They are built only from structured records yhwach holds, and in practice they stayed empty. Export them (into their own `_yhwach/` folder — each run overwrites it) only if you feed those records, and re-export after each ingest.
- **Non-chain notes in `chains/`** — resume points, deferred plans, idea lists. `chains/` holds exactly the deliverable.
- **Tool artifacts** — C2 session stubs, cracking session files, temporary run scripts. Keep them out of the vault.

### The chain note

Start every chain from [`docs/templates/chain-note.md`](docs/templates/chain-note.md) (it works with Obsidian's *Templates* plugin). Seven sections, in this order:

1. **Target + objective** — host, service, the proof file, points.
2. **Vulnerability** — class / CVE / misconfiguration in a sentence or two. This *is* the finding.
3. **Prerequisites** — exactly what a reader needs to start: tunnel, credentials (each linked to the chain that produced it), tools. Nothing else assumed.
4. **Steps** — numbered. Each one: the exact command, the verbatim output from its `.txt`, one line on what it proves, the screenshot.
5. **Proof** — one command run on the target as the compromised user, showing identity + hostname + flag together.
6. **Source & modifications** — the full source of every script used, where it came from, and what you changed.
7. **Cleanup / notes** — persistence installed, what's left on the target, what's durable and what's ephemeral.

What separated report-ready chains from the rest:

- **Each step written right after it ran.** Notes reconstructed at the end of a session — or screenshots retaken afterwards — miss state that's already gone.
- **Commands that run as pasted:** real IPs, users and paths inline; no `$VARS`, `~/` or temp paths; no placeholders; no "same as step 2 of the other note" (make that note a prerequisite instead).
- **Output pasted, not paraphrased** — copied from the `.txt`.
- **A control step** where it helps: the blocked request before the bypass.
- **A final re-run from zero:** revert, follow each chain note literally, re-capture, stamp *re-verified &lt;date&gt;*, and delete the superseded first-pass screenshots.

`yhwach poc` gives section 4 a head start: `yhwach poc --lab acme --objective <name>` prints the steps you recorded with `yhwach_poc_step`. Paste them into the chain note and write the other six sections yourself. Don't point its `--out` at a note you edit by hand — it overwrites the file.

### Proof screenshots — `docs/hooks/yhwach-shot.sh`

```bash
export YHWACH_VAULT="$HOME/notes"          # vault root; each lab is a folder in it
~/yhwach/docs/hooks/yhwach-shot.sh -l acme -n c1-web01-proof --cmd -- <the command that prints the proof>
#   SAVED:  /home/you/notes/acme/screenshots/20261010-174506_c1-web01-proof.png
#   OUTPUT: /home/you/notes/acme/screenshots/20261010-174506_c1-web01-proof.txt   (exit 0)
#   EMBED:  ![[20261010-174506_c1-web01-proof.png]]
```

`--cmd` opens a terminal, runs the command in it, saves the output to the `.txt` (headed by the UTC time, `user@host` and the exact command line) and captures the whole screen. For a shell that's already open — a reverse shell, a C2 session — bring it to the front and use `--region --delay 3` to frame it yourself. The script prints an embed only for a file that really exists; otherwise it prints `⚠️ SCREENSHOT-MISSING` and exits 1. It needs a desktop session: ImageMagick `import` on X11, or `grim` + `slurp` on Wayland. Make it executable once (`chmod +x`) and, if you like, symlink it onto your `PATH`; configuration and the optional Claude Code hooks live in [docs/hooks/](docs/hooks/).

What makes a screenshot count:

- **Capture points:** the first shell, every privilege boundary, every web or AI request that lands, and the proof.
- **The proof is the output of a command you ran on the target as the compromised user:** `whoami` / `id`, `hostname`, the IP and the flag, in one frame. A flag you downloaded and read on your own machine, or a value the target merely echoes back, isn't proof.
- **AI targets:** the exact request **and** the real effect — the tool result, job trace or listener hit — not the model repeating your input.
- **A clean frame:** an opaque terminal, no other chats or sessions visible (the whole screen is captured), no resizing during the capture, command lines short enough not to wrap.
- **Label with the chain ID** (`-n c1-web01-proof`) so each image belongs to one note, and paste the embed on its **own line** — never in backticks or a code block, never split across lines.
- **A capture point you missed gets the literal token `⚠️ SCREENSHOT-MISSING`** at that step — not a sentence about it — so the check below finds it.

### Before you call it done — `scripts/yhwach-vault-check.py`

```bash
~/yhwach/scripts/yhwach-vault-check.py ~/notes/acme
```

A mechanical done-gate for one lab folder. It lists embeds that point at missing files or won't render, leftover `SCREENSHOT-MISSING` / `TODO` / `UNVERIFIED` markers, chain notes missing one of the seven sections, screenshots no note embeds, captures that saved output but no image, and links to notes that don't exist. It exits 1 while any chain note isn't done.

> [!WARNING]
> Your vault holds live secrets — credentials, keys, flags. Never sync it to a public location.

### Also from yhwach

| Command | Produces |
|---|---|
| `yhwach report --lab acme --out report.md` | A Markdown engagement report from the database — findings, hosts, pivots, timeline. Cross-check it against your chain notes. |
| `yhwach recon --lab acme --host 10.10.10.5` | Everything yhwach knows about one host — paste what's useful into its host note. |

---

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
