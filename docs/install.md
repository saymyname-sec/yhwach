# Install (Kali)

Yhwach targets Kali Linux with the standard OSAI-exam tooling stack.

## Requirements

- Kali Linux 2025+ (or any Debian-derived distro with the tools below)
- Python 3.11+
- `sqlite3` on PATH
- `jq`
- **HexStrike** MCP server: [hexstrike-ai/hexstrike-ai](https://github.com/hexstrike-ai/hexstrike-ai) — bound to `127.0.0.1:8888`
- **Metasploit** + `msfmcpd` MCP server
- **Obsidian** + the **Local REST API** plugin, reachable from Kali (VMware host or LAN), plus an
  **Obsidian MCP** registered in your host CLI — the engagement notebook is the vault, written by
  the operator via that MCP (see [../persona/notebook.md](../persona/notebook.md))
- **Local knowledge base** (see below)
- Optional: **BloodHound MCP** for AD reasoning

No API key required. Yhwach's operator persona ships with the engine; the host CLI or MCP client executes the judgment call.

## Install

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach
cd ~/yhwach
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # add ,mcp -> ".[dev,mcp]" to run `yhwach mcp`
```

Optional extras: `dev` (pytest / ruff / black), `mcp` (the `mcp` SDK for `yhwach mcp`).

A non-editable install works too — the wheel bundles the schema, persona, playbooks, and fixtures,
so `pip install .` (or a built wheel) ships everything `engage`/`plan`/`selftest` need. CI
(`.github/workflows/ci.yml`) runs the suite + a clean-venv wheel-install smoke on Linux and Windows.

Verify:

```bash
yhwach --version
yhwach persona           # prints the operator persona in effect + its hash
pytest -q                # 241 tests
yhwach selftest          # golden fixtures
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
  recon/                              # raw scan output (e.g. HexStrike nmap XML)
  loot/                               # captured action output (yhwach run --go)
  screenshots/                        # bound to `proof` rows (yhwach proof)
  tools/                              # pre-staged custom tooling (provided per challenge):
                                      #   svcmon.exe  — obfuscated Windows Ligolo agent
                                      #   svc.exe / svc.bin — custom AMSI-bypass reverse shell
                                      #   + an instructions file with the listener port
~/yhwach/                             # this repo, checked out
```

The `recon/` and `loot/` directories are derived relative to the DB path, so a non-canonical
`--db` location still keeps its artifacts beside it. The engagement notebook is **not** on Kali
disk — it lives in the Obsidian vault, written via the Obsidian MCP.

State survives `/clear`; context does not.
