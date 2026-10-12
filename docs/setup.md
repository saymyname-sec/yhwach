# Setup — prepare a machine for Yhwach (step by step)

A complete, copy-paste walkthrough for someone starting from a fresh **Kali** box. By the end you'll
have: Yhwach installed, the offensive toolchain in place, HexStrike bound to loopback, the Obsidian
notebook wired, Claude Code (the operator) configured with the right instruction files and MCP
servers, and a green smoke test of the whole loop.

> **Authorized use only** — see [../AUTHORIZATION.md](../AUTHORIZATION.md). Everything below assumes
> lab targets you own or are licensed to test.

## Where things run

| Where | Runs | Role |
|---|---|---|
| Kali (VM) | Yhwach + HexStrike + the offensive toolchain | the engine + tool execution |
| Kali | Claude Code | the **operator** — reasons over Yhwach's handoff, drives the MCPs |
| Kali | Obsidian (opens the local vault) | the engagement **notebook** — narrative prose + generated `_RESUME.md` |

**Operator box is Kali.** Everything in this doc runs on **Kali**. Clone the repo to `~/yhwach` on Kali.

## Conventions used in this doc

- **User is `kali`.** All paths below are under the `kali` home.
- **Canonical vault root: `$YHWACH_VAULT_DIR/<lab>/`.**
- **Obsidian notebook = local files, optionally surfaced through the Obsidian Local REST API MCP.**
  The MCP reads/writes the same local vault files; "plain files" and "via MCP" are the same vault.
  Wire the MCP (step 9) only if you want the operator to write notes through it.
- **Engagement root is `$YHWACH_DATA_DIR/`, the per-engagement workspace.** Fix a dead symlink
  before writing anything.

---

## 1. Prerequisites

- Kali Linux 2024+ (or any Debian-based distro), Python **3.11+**, `git`, `pipx`.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip pipx git jq sqlite3
pipx ensurepath
python3 --version    # must be >= 3.11
```

## 2. Install Yhwach

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach
cd ~/yhwach
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"        # dev = tests/lint; mcp = the MCP server extra

# verify
yhwach --version
pytest -q                          # should be all green
yhwach persona | tail -1           # prints the operator persona hash
```

Tip: add `source ~/yhwach/.venv/bin/activate` to your `~/.zshrc` so `yhwach` is always on PATH.

> The operator **persona** (`persona/operator.md`, `notebook.md`, `contract.md`) is bundled into the
> package and travels with the engine — `yhwach persona` prints the exact frame in effect. You do
> **not** copy it into `~/.claude/`.

## 3. Install the offensive toolchain

Yhwach *renders and runs* these tools; install the ones you'll use. Most ship with Kali already —
the command below installs/updates the common set:

```bash
# Kali metapackages / apt (many are preinstalled)
sudo apt install -y nmap netexec smbmap enum4linux-ng ldap-utils \
                    impacket-scripts evil-winrm nuclei ffuf sqlmap \
                    freerdp2-x11 seclists gpp-decrypt

# Not always packaged — install via pipx / download:
pipx install certipy-ad                      # ADCS (certipy find/req/auth)
# kerbrute (static binary):
sudo curl -sL -o /usr/local/bin/kerbrute \
  https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
sudo chmod +x /usr/local/bin/kerbrute
```

**Ligolo-ng** (pivoting proxy on Kali + agents you deploy on targets):

```bash
mkdir -p ~/tools/ligolo && cd ~/tools/ligolo
# download the proxy (Kali) + agent binaries from:
#   https://github.com/nicocha30/ligolo-ng/releases
# proxy runs on Kali; agents run on compromised hosts (see $YHWACH_DATA_DIR/tools/ for the
# pre-staged obfuscated Windows agent — step 6).
```

What maps to what (so you know why each is here):

| Tool | Used by |
|---|---|
| `nmap` | `yhwach enum` (via HexStrike), ingestion |
| `netexec` (`nxc`) / `smbmap` / `enum4linux-ng` / `ldapsearch` | SMB/LDAP enum -> AD tags |
| `impacket-*` (GetUserSPNs, GetNPUsers, secretsdump, ntlmrelayx) | kerberoast / AS-REP / DCSync / relay |
| `certipy` | ADCS (ESC) — `yhwach ingest --kind certipy` |
| `kerbrute` | kerberos user enum |
| `nuclei` / `ffuf` / `sqlmap` | web recon/exploitation |
| `evil-winrm` | WinRM shells |
| ligolo-ng / chisel | pivoting (`yhwach pivot`) |

## 4. Install HexStrike (and lock it down)

HexStrike executes tools for Yhwach. Its `/api/command` is **unauthenticated RCE** — treat it like
a loaded gun: bind it to loopback and firewall the port.

```bash
git clone https://github.com/hexstrike-ai/hexstrike-ai ~/tools/hexstrike-ai
cd ~/tools/hexstrike-ai
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# START IT BOUND TO LOOPBACK ONLY (check the project's README for the exact flag/port; 8888 default)
python3 hexstrike_server.py --bind 127.0.0.1 --port 8888     # keep it on 127.0.0.1
```

Firewall the port so a pivoted target can never reach it:

```bash
sudo iptables -A INPUT -p tcp --dport 8888 ! -i lo -j DROP    # re-check after every pivot
```

Verify Yhwach can reach it (from the Yhwach venv):

```bash
yhwach engage --lab test --scope 127.0.0.0/8
yhwach enum   --lab test --target 127.0.0.1        # runs nmap via HexStrike, ingests it
```

If `enum` says "HexStrike not reachable", HexStrike isn't running on `127.0.0.1:8888`.

## 5. Engagement directory layout

```bash
mkdir -p ~/engagements $YHWACH_VAULT_DIR ~/tools ~/engagements/notekit ~/repos
# per-lab: point current -> the active lab (redo this on every new lab)
mkdir -p ~/engagements/lab01/{state,recon,loot,screenshots,scripts,tools}
ln -sfn ~/engagements/lab01 $YHWACH_DATA_DIR
readlink $YHWACH_DATA_DIR      # must resolve; fix a dead symlink before writing evidence
```

Layout Yhwach reads/writes:

```
$YHWACH_DATA_DIR/            # symlink -> ~/engagements/<lab>/
  state/  yhwach.db  scope.txt  hosts_inventory.txt  network_map.md
  recon/  loot/  screenshots/  scripts/  tools/
$YHWACH_VAULT_DIR/<lab>/        # the Obsidian vault (narrative + _RESUME.md)
~/yhwach/                  # this repo
```

## 6. Pre-staged operator tooling

Before each challenge, drop your custom binaries in `$YHWACH_DATA_DIR/tools/` with an instructions
file that states the listener **port**. Yhwach hardcodes their canonical paths in
`yhwach/arsenal.py` (run `yhwach ref arsenal` to print them — don't hand-maintain a copy):

```
$YHWACH_DATA_DIR/tools/
  svcmon.exe        # obfuscated Windows Ligolo agent (AV/EDR-evasive) — THE Windows drop-in
  svc.exe / svc.bin # custom AMSI-bypass reverse shell
  instructions.txt  # the callback/listener PORT + usage notes (operator reads this, never guesses)
```

Chisel (Linux fast-path pivot) belongs on PATH:

```bash
sudo cp ~/tools/chisel /usr/local/bin/chisel && sudo chmod +x /usr/local/bin/chisel
```

## 7. Local knowledge base (offline answer key)

```bash
mkdir -p ~/repos && cd ~/repos
git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks.git
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone --depth 1 https://github.com/swisskyrepo/InternalAllTheThings.git
# SecLists is already at /usr/share/seclists on Kali (from step 3)
```

## 8. Claude Code CLI — the files to copy

Claude Code is the operator. The one thing that matters is **registering the MCP
server** (next sub-section) — that is what makes the `yhwach_*` tools appear. Any
per-engagement instruction fragment should be **kind-appropriate** and live next to
that engagement (a bounty run is not a CTF; stealth and scope differ per kind), not a
one-size global router. (The persona is NOT copied — it ships with the engine; see
step 2.)

> **Do not install a one-size global `~/.claude/CLAUDE.md`.** Earlier versions told you
> to copy the CTF methodology router over your global Claude config. That file is **CTF/exam
> doctrine** ("15 free points", "proof = points", "speed beats stealth", "if refused,
> re-frame") — wrong for real client work, and it would override your own global config
> for *every* project. It now lives in [`docs/experimental/agent-mode.md`](experimental/agent-mode.md)
> as an **optional** router you may load yourself for a lab/CTF, never a mandated install.

Optionally, the `/lab` and `/yhwach-learn` slash commands and the capture hook are
convenience glue for lab/CTF work (they are not required for real engagements):

| Source (in `~/yhwach`) | Copy to | What it is |
|---|---|---|
| `docs/commands/lab.md` | `~/.claude/commands/lab.md` | `/lab` — start/resume a lab and drive the loop |
| `docs/commands/yhwach-learn.md` | `~/.claude/commands/yhwach-learn.md` | `/yhwach-learn` — mine a finished vault into yhwach improvements |
| `docs/hooks/yhwach-sync-reminder.sh` | `~/.claude/hooks/yhwach-sync-reminder.sh` | PostToolUse hook: forces state+note capture after every offensive command |

```bash
mkdir -p ~/.claude/commands ~/.claude/hooks
cp ~/yhwach/docs/commands/lab.md      ~/.claude/commands/lab.md
cp ~/yhwach/docs/commands/yhwach-learn.md  ~/.claude/commands/yhwach-learn.md
cp ~/yhwach/docs/hooks/yhwach-sync-reminder.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/yhwach-sync-reminder.sh
```

Register the hook in `~/.claude/settings.json` (merge into any existing config):

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "~/.claude/hooks/yhwach-sync-reminder.sh" } ] }
    ]
  }
}
```

### MCP servers

Register every server the persona calls, not just yhwach. Confirm the `yhwach_*` tools appear inside
Claude Code afterward (full tool list + rationale: [deploy.md](deploy.md)).

```bash
# Yhwach — the memory/engine (required). Sets the lab DB once via the env.
YHWACH_DB=$YHWACH_DATA_DIR/state/yhwach.db claude mcp add yhwach -- yhwach mcp

# Hashcat — async cracker (CPU box)
claude mcp add hashcat -- python3.13 ~/tools/claude/hashcat_mcp.py

# BloodHound — AD attack-graph reasoning (needs neo4j UP at bolt://localhost:7687)
claude mcp add bloodhound -- python3.13 ~/repos/BloodHound-MCP-AI/BloodHound-MCP.py

# Metasploit — shell handler + durable sessions (needs msfrpcd on 127.0.0.1:55553 + PostgreSQL)
claude mcp add metasploit -- /opt/MetasploitMCP/.venv/bin/python /opt/MetasploitMCP/MetasploitMCP.py --transport stdio

# Adaptix — OPTIONAL C2 fallback (needs its teamserver on https://localhost:4321)
claude mcp add adaptix -- python3.13 ~/tools/claude/adaptix_mcp.py
```

Or edit the config file directly:

```json
{
  "mcpServers": {
    "yhwach": { "command": "yhwach", "args": ["mcp"],
                "env": { "YHWACH_DB": "$YHWACH_DATA_DIR/state/yhwach.db" } }
  }
}
```

- **filesystem** — Claude Code already has scoped file tools for `/home/kali`; add a filesystem MCP
  only if you want a second, explicitly-scoped path. Confirm the exact server package before adding.
- **hexstrike** — Yhwach calls HexStrike over its loopback HTTP API (step 4); it does not need a
  `claude mcp add` entry for the yhwach loop. Register HexStrike's own MCP only if you want Claude to
  drive it directly (see its README for the command).

Then start a lab from Claude Code with `/lab --lab <name> --scope <cidr> --domain <d> --dc <ip>`
(omit args to resume). The PostToolUse hook interrupts after any offensive/loot command with a "fold
state into Yhwach + write the note" checklist — the enforcement that keeps the loop and notebook from
lapsing mid-engagement (survives context compaction).

## 9. Obsidian notebook

The vault is local files under `$YHWACH_VAULT_DIR/<lab>/`. Two ways to write it — pick one and keep the
persona (step 2) consistent with your choice:

- **Plain files (no MCP):** install Obsidian, open the folder, let the operator write with the file
  tools. `~/engagements/notekit/` scaffolds and reconciles: `scaffold_vault.sh <lab>` creates the note-set,
  `heartbeat.py` keeps `_RESUME.md` + rollups synced with yhwach, `shot.sh <host>_<slug> <host>`
  captures a proof screenshot (UTC+local time burned in).
- **Via Obsidian MCP:** install the **Local REST API** community plugin in Obsidian, copy its API
  key, then register the Obsidian MCP so the operator reads/writes the same vault over the API.
  Confirm the exact MCP package/command and pass the key via its env. The vault files on disk are
  identical either way.

```bash
sudo apt install -y obsidian    # or the AppImage
# open $YHWACH_VAULT_DIR/<lab>/ as a vault
```

## 10. First real run (smoke test the whole loop)

```bash
yhwach engage  --lab lab01 --scope 10.10.10.0/24
yhwach enum    --lab lab01 --target 10.10.10.0/24     # nmap via HexStrike -> ingested
yhwach probe   --lab lab01                            # AI + traditional surfaces
yhwach brief   --lab lab01                            # the operator brief (the client reasons over this)
yhwach next    --lab lab01                            # the recall menu for the next move
yhwach status  --lab lab01                            # resume-safe engagement state
yhwach report  --lab lab01 --check                    # QA gate: evidence/PoC/secret-leak checks
```

From your MCP client the same loop runs via the `yhwach_*` tools — the client reasons over
`yhwach_brief`, acts, and folds results back with `yhwach_interpret` / `yhwach_attempt`. (The
deterministic `yhwach run --dry-run` harness still exists for the experimental self-driving path —
see [docs/experimental/](experimental/).)

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `yhwach: command not found` | Activate the venv: `source ~/yhwach/.venv/bin/activate` |
| `HexStrike not reachable` | Start it on `127.0.0.1:8888` (step 4); check `curl -s 127.0.0.1:8888/health` |
| `enum … not in scope` | The `--target` is outside `--scope`; fix the scope on `engage` or the target |
| `Target … is not an IP/CIDR` warning | Scope can't be verified for hostnames — use IPs/CIDRs |
| `readlink $YHWACH_DATA_DIR` is empty/dead | `ln -sfn ~/engagements/<lab> $YHWACH_DATA_DIR` before writing evidence |
| `yhwach_*` tools missing in Claude | Re-run `claude mcp add`; check `pip install -e ".[mcp]"` |
| BloodHound MCP errors | neo4j not up (`bolt://localhost:7687`) |
| Metasploit MCP won't connect | `msfrpcd` not on `127.0.0.1:55553`, or PostgreSQL down |
| Persona/report prints mojibake on Windows | Already handled — Yhwach forces UTF-8 output |
| `pip install` wheel missing schema/playbooks | Use `pip install -e .` from the repo, or a wheel built from it (data is bundled) |

See also: [install.md](install.md) (requirements reference) and [deploy.md](deploy.md) (MCP details).
