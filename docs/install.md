# Install (Kali)

Yhwach targets Kali Linux with the standard OSAI-exam tooling stack.

## Requirements

- Kali Linux 2025+ (or any Debian-derived distro with the tools below)
- Python 3.11+
- `sqlite3` on PATH
- `jq`
- **HexStrike** MCP server: [hexstrike-ai/hexstrike-ai](https://github.com/hexstrike-ai/hexstrike-ai) — bound to `127.0.0.1:8888`
- **Metasploit** + `msfmcpd` MCP server
- **Obsidian Local REST API** plugin reachable from Kali (VMware host or LAN)
- **Local knowledge base** (see below)
- Optional: **BloodHound MCP** for AD reasoning

No API key required. Yhwach's operator persona ships with the engine; the host CLI or MCP client executes the judgment call.

## Install

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach
cd ~/yhwach
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Verify:

```bash
yhwach --version
yhwach --check-env       # prints tool discovery report + persona hash
```

## Local knowledge base

Yhwach's RESEARCH step reads from local repos already used by OSAI operators:

```bash
mkdir -p ~/repos && cd ~/repos
git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks.git
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone --depth 1 https://github.com/swisskyrepo/InternalAllTheThings.git
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
# OSAI notes: your private repo, checked out separately.
```

## Firewall — matches OSAI CLAUDE.md rule

HexStrike exposes `execute_command` unauthenticated on `0.0.0.0:8888`. Ligolo tunnels expose it to the target subnet. Yhwach expects HexStrike bound to loopback only:

```bash
sudo iptables -A INPUT -p tcp --dport 8888 ! -i lo -j DROP
```

Re-check after every pivot.

## Layout on disk

Yhwach reads and writes here:

```
~/osai/current/                       # engagement root (managed by /osai-engage)
  state/
    yhwach.db                         # the world model — SQLite; one per lab
    scope.txt                         # source of truth for scope
  loot/                               # ingested tool output
  screenshots/                        # bound to `proof` rows
~/yhwach/                             # this repo, checked out
```

State survives `/clear`; context does not.
