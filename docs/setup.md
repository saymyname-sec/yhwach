# Setup — prepare a machine for Yhwach (step by step)

A complete, copy-paste walkthrough for someone starting from a fresh Kali box. By the end you'll
have: Yhwach installed, the tool it drives installed and safe, HexStrike bound to loopback, the
Obsidian notebook wired through an MCP, and Claude Code able to call Yhwach as MCP tools.

**The moving parts**

| Where | Runs | Role |
|---|---|---|
| Kali (VM) | Yhwach, HexStrike, the offensive toolchain | the engine + tool execution |
| Kali | Claude Code | the **operator** (reasons over Yhwach's handoff, drives the MCPs) |
| Your host / another VM | Obsidian + Local REST API plugin | the engagement **notebook** (single source of truth) |

> Authorized use only — see [../AUTHORIZATION.md](../AUTHORIZATION.md). Everything below assumes lab
> targets you own or are licensed to test.

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
yhwach selftest                    # golden fixtures
yhwach persona | tail -1           # prints the operator persona hash
```

Tip: add `source ~/yhwach/.venv/bin/activate` to your `~/.zshrc` so `yhwach` is always on PATH.

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
# proxy runs on Kali; agents run on compromised hosts (see your ~/osai/current/tools/ for the
# pre-staged obfuscated Windows agent — step 7).
```

What maps to what (so you know why each is here):

| Tool | Used by |
|---|---|
| `nmap` | `yhwach enum` (via HexStrike), ingestion |
| `netexec` (`nxc`) / `smbmap` / `enum4linux-ng` / `ldapsearch` | SMB/LDAP enum → AD tags |
| `impacket-*` (GetUserSPNs, GetNPUsers, secretsdump, ntlmrelayx) | kerberoast / AS-REP / DCSync / relay |
| `certipy` | ADCS (ESC) — `yhwach ingest --kind certipy` |
| `kerbrute` | kerberos user enum |
| `nuclei` / `ffuf` / `sqlmap` | web recon/exploitation |
| `evil-winrm` | WinRM shells |
| ligolo-ng | pivoting (`yhwach pivot`) |

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

Firewall the port so a pivoted target can never reach it (matches the OSAI rule):

```bash
sudo iptables -A INPUT -p tcp --dport 8888 ! -i lo -j DROP    # re-check after every pivot
```

Verify Yhwach can reach it (from the Yhwach venv):

```bash
yhwach engage --lab test --scope 127.0.0.0/8
yhwach enum   --lab test --target 127.0.0.1        # runs nmap via HexStrike, ingests it
```

If `enum` says "HexStrike not reachable", HexStrike isn't running on `127.0.0.1:8888`.

## 5. Obsidian notebook (Local REST API)

The engagement notebook is an Obsidian vault the operator writes via an MCP. On the machine running
Obsidian:

1. Install Obsidian, open (or create) your engagements vault.
2. Settings → Community plugins → browse → install **Local REST API** → enable it.
3. In the plugin settings, **copy the API key** and note the host/port (default `https://127.0.0.1:27124`,
   HTTP `27123`). On a VM setup, bind it to the host-only adapter so Kali can reach it, and note
   that address.

Keep the API key secret — you'll pass it to the MCP via an env var (step 6), never in a file you commit.

## 6. Register the MCP servers in Claude Code (on Kali)

Claude Code is the operator. Give it three MCPs: **Yhwach** (the engine), **Obsidian** (the
notebook), and optionally **BloodHound** (AD path reasoning).

```bash
# Yhwach — set the lab DB once via the env; then all yhwach_* tools use it
YHWACH_DB=~/osai/current/state/yhwach.db claude mcp add yhwach -- yhwach mcp

# Obsidian — use any MCP that wraps the Local REST API; pass the key + base URL via env.
# (example shape — check your chosen server's README for exact args)
claude mcp add obsidian \
  -e OBSIDIAN_API_KEY=<paste-your-key> \
  -e OBSIDIAN_BASE_URL=https://127.0.0.1:27124 \
  -- <obsidian-mcp-command>

# BloodHound (optional) — an MCP that runs your BloodHound/Cypher queries.
# Yhwach ingests its output: yhwach ingest --kind bloodhound --host <DC> <facts.json>
```

Or edit the config file directly:

```json
{
  "mcpServers": {
    "yhwach":   { "command": "yhwach", "args": ["mcp"],
                  "env": { "YHWACH_DB": "~/osai/current/state/yhwach.db" } }
  }
}
```

Confirm inside Claude Code that the `yhwach_*` tools are listed (status/plan/next/run/ingest/…).
Full tool list + rationale: [deploy.md](deploy.md).

## 7. Pre-staged operator tooling

Before each challenge, drop your custom binaries in `~/osai/current/tools/` with an instructions
file that states the listener **port**. Yhwach's persona is built to use these instead of
rolling its own:

```
~/osai/current/tools/
  svcmon.exe        # your obfuscated Windows Ligolo agent (AV/EDR-evasive)
  svc.exe / svc.bin # your custom AMSI-bypass reverse shell
  instructions.txt  # the callback/listener PORT + any usage notes
```

The operator reads `instructions.txt` for the port and never guesses it (see
[../persona/operator.md](../persona/operator.md), "Pre-staged tooling").

## 8. Local knowledge base (offline answer key)

```bash
mkdir -p ~/repos && cd ~/repos
git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks.git
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone --depth 1 https://github.com/swisskyrepo/InternalAllTheThings.git
# SecLists is already at /usr/share/seclists on Kali (from step 3)
```

## 9. First real run (smoke test the whole loop)

```bash
yhwach engage  --lab lab01 --scope 10.10.10.0/24
yhwach enum    --lab lab01 --target 10.10.10.0/24     # nmap via HexStrike -> ingested
yhwach probe   --lab lab01                            # AI + traditional surfaces
yhwach plan    --lab lab01                            # rank tasks
yhwach next    --lab lab01 --contract                 # the operator brief (Claude reasons over this)
yhwach run     --lab lab01 --task 1 --go              # run read-only recon; findings + tags extracted
yhwach report  --lab lab01 --out report.md
```

From Claude Code, the same loop runs via the `yhwach_*` MCP tools, and Claude writes the write-up
to Obsidian via the Obsidian MCP at every objective.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `yhwach: command not found` | Activate the venv: `source ~/yhwach/.venv/bin/activate` |
| `HexStrike not reachable` | Start it on `127.0.0.1:8888` (step 4); check `curl -s 127.0.0.1:8888/health` |
| `enum … not in scope` | The `--target` is outside `--scope`; fix the scope on `engage` or the target |
| `Target … is not an IP/CIDR` warning | Scope can't be verified for hostnames — use IPs/CIDRs |
| Persona/report prints mojibake on Windows | Already handled — Yhwach forces UTF-8 output |
| `pip install` wheel missing schema/playbooks | Use `pip install -e .` from the repo, or a wheel built from it (data is bundled) |

See also: [install.md](install.md) (requirements reference) and [deploy.md](deploy.md) (MCP details).
