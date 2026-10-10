# yhwach agent mode
# The yhwach-MODE extension, loaded when you start/resume a lab via `/lab`.
# Manual mode (normal Claude CLI + the global ~/.claude/CLAUDE.md methodology) does
# NOT need yhwach; this file is the glue for when you DO drive with it.
# Full AI-attack chains / arsenal / privesc detail loads on demand via `yhwach ref`.

## The engine — Yhwach owns state and frames your reasoning
Yhwach is the source of truth (a SQLite world model), not ad-hoc files. It never calls a model —
**you are the operator it hands off to.** Each turn, the shape of work is:

**orient (`yhwach_brief` / `yhwach_path` / `yhwach_gaps`) → reason → act → fold the result back → repeat.**

- `yhwach_brief` returns the AI-legible engagement map: state, P0 leads, and the **complete recall
  menu** of applicable techniques per host. `yhwach_path` prints the shortest known route to the
  objective. **Yhwach hands you the complete menu; YOU rank it** from the notes, leads, dead ends
  and creds in hand — there is no EV ranker (it was removed; the model ranks better than a scalar).
- **Lost your context? `yhwach_status` first**, then `yhwach_brief`. After a `/clear` or a handover
  they replay the engagement (state, what you TRIED, open leads, enum gaps) — your chat history is
  not the record, the DB is.
- The `yhwach` MCP resolves the DB from `YHWACH_DB=$YHWACH_DATA_DIR/state/yhwach.db` (set in the MCP env).
- Start/resume entirely via MCP: **`yhwach_engage`** (lab + scope [+ domain/dc]) then `yhwach_status`.
  Just tell Claude the lab + IPs in plain English — it calls the tools itself; no bash needed.

## The loop (Yhwach-driven)
```
yhwach_status                       # where are we? (resume-safe; run first after a /clear)
yhwach_brief                        # engagement map + P0 leads + the recall menu
yhwach_enum <target>                # nmap via HexStrike -> ingested  (or ingest a scan file)
yhwach_gaps                         # any host not full-ported / no -sV / no UDP? fix it NOW
yhwach_probe                        # detect AI + traditional surfaces
loop:
  yhwach_brief / yhwach_path        # orient: pick the top move, say why; never re-try a dead end
  execute it -> HexStrike MCP · arsenal (yhwach revshell / yhwach pivot / ref arsenal)
                · yhwach ref ai-attacks -q <topic> · metasploit MCP
  fold results back into Yhwach (SAME TURN):
    yhwach_ingest <file> --kind nmap|linpeas|winpeas|bloodhound|certipy|netexec|web --host <ip>
    yhwach_vulns                                   # after ingesting versions (offline version->CVE)
    yhwach_add_cred · yhwach_add_finding · yhwach_add_loot · yhwach_spray
    yhwach_poc + yhwach_poc_step                   # the reproducible flag chain
    yhwach_pivot · yhwach_add_interface · yhwach_advance
  write the vault note ($YHWACH_VAULT_DIR/<lab>/) at this objective — full detail
```
Every pivot opens unscanned hosts -> `yhwach_enum` the new subnet -> straight back into the loop.

## Prioritisation doctrine — drives every move choice
Prioritise the highest-value, least-defended surfaces — AI/LLM surfaces are frequently both.
- **Hit AI surfaces first, always** — they are the priority tier and often the least defended.
- A standalone AI host with no prereqs is a cheap early win; take low-value objectives (e.g. a DC
  flag) opportunistically when the chain reaches them, never grind toward one while AI surfaces sit
  untouched.
- Proof/evidence is the deliverable (an unscreenshotted win is worth nothing). Concrete point targets are optional per-engagement config (`yhwach engage --points-target/--points-max/--time-budget-h`), never assumed.
- The standalone AI host has no prereqs — 15 free points, do it early.

## Full-Kali enumeration is primary; arsenal scripts are quick-wins
Enumerate EVERY service with the full Kali toolset (HexStrike's ~150 tools + the free shell) before
reaching for a script. The `arsenal/AIScripts/` shortcuts (`yhwach ref arsenal`) are opportunistic —
a matched CVE/service, not a substitute for checking every path. "No script matched" != "nothing to
do"; the `yhwach_gaps` `service_enum` check is the completeness bar.

## Foothold sequence — where C2 & pivot fit (POST-foothold)
Per target, in order:
1. **Enumerate -> find the path** (`yhwach_brief` surfaces it; research the unknown).
2. **Get the INITIAL RAW SHELL first** — `yhwach revshell --os win` renders the canonical
   `gen_cs_shell.sh` (C# revshell, XOR+reconnect, lands on Win11 with AV enabled); `--os linux`
   renders the 7-payload Linux menu. A plain shell, not yet a Metasploit session.
3. **Metasploit session, then PERSISTENCE** — catch/upgrade the raw shell into an msf session (via
   the `metasploit` MCP), set persistence. msfdb is durable state — one workspace per lab.
4. **Pivot THROUGH that session** — only when a new subnet must be reached. `yhwach pivot` renders
   the deploy: Windows default `svcmon.exe` (obfuscated ligolo agent); Linux `chisel` (default) or
   `/usr/bin/ligolo-agent` (apt). Records the tunnel + gates the host stage.
5. **Loot -> `yhwach_add_cred` -> `yhwach_enum` the new subnet -> repeat.**

Fresh port per host, record it. If a session/persist/tunnel step fails, log it and hand to the operator —
don't loop.

## Proof = points (every scored machine has a proof file)
- "An interactive shell is not required — retrieve the proof by any valid method."
- AI: the exploit IS the retrieval — the model response / exfil on your listener, screenshotted with
  the exact triggering request. Traditional: `cat` proof + screenshot with whoami/hostname.
- **`yhwach_poc` + `yhwach_poc_step`** record the reproducible chain (command + output per step).
  Capture the screenshot as you take the flag —
  **unscreenshotted = 0, unrecoverable after submission.**

## Notebook = a LOCAL Obsidian vault (no MCP); yhwach = atoms, vault = prose
yhwach.db is the SINGLE SOURCE OF TRUTH for ATOMS (hosts/creds/findings+tags/proofs/objectives) —
record them there first. The **narrative** write-ups live in a local Obsidian vault: plain files
under `$YHWACH_VAULT_DIR/<lab>/`, written with the file tools (there is NO obsidian MCP). Structure
(index / overview / attack-chain / credentials / network-map / next-steps / exhausted-approaches /
hosts/ / findings/ / chains/) mirrors `persona/notebook.md`. **`yhwach_export_notes`** scaffolds the
DB-derived tables (services/software, vulns, web, users & groups, shares, per-host) as local files so
you write only the prose around them. Every scored proof MUST have a screenshot in the vault.

## AI OWASP TOP 10 — what you're hunting (class -> ref pack topic)
The AI-attack knowledge is one query away: **`yhwach ref ai-attacks -q <topic>`** (offline,
works with or without an engagement). Walk `owasp_llm_checklist` first.
- **LLM01 Prompt Injection** -> `prompt_injection`, `rag_poisoning`, `mcp_attack`, `a2a_attack`
- **LLM02 Sensitive Info Disclosure** · **LLM07 System-Prompt Leakage** -> `prompt_injection`, `rag_poisoning`
- **LLM03 Supply Chain** · **LLM04 Data/Model Poisoning** -> `model_supply_chain`, `vector_db`, `rag_poisoning`
- **LLM05 Improper Output Handling** (->SQLi/XSS/SSRF/RCE) -> chain from `rag_poisoning` into web
- **LLM06 Excessive Agency** -> `mcp_attack`, `a2a_attack`, `cloud_loot`
- **LLM08 Vector/Embedding Weaknesses** -> `vector_db`
- LLM09/10 low value — note & chain. Proof is usually LLM01/02/07/06/08.

## Fold-back & notes are NOT optional (the #1 discipline)
Under attack momentum it's tempting to chain exploits and "record it later" — later never comes, and
after a `/clear` an uncaptured win is lost. So, **at every objective, before the next step:**
1. Fold state into Yhwach — `yhwach_add_cred` / `yhwach_poc` / `yhwach_advance` / `yhwach_pivot` /
   `yhwach_ingest`. Yhwach is the **ledger**; if it's not in the DB it didn't happen.
2. Write the **full** vault note — the Attack Chain step with the exact command (fenced), captured
   output, and evidence path; update the host + Credentials notes.
3. Re-orient (`yhwach_brief`) before starting a new target — don't free-run once the chain feels obvious.

A **PostToolUse hook** (`docs/hooks/yhwach-sync-reminder.sh`, optional) can enforce this: after any
offensive/loot command it interrupts with the checklist above — it survives context compaction.

## Executor map — Yhwach ranks WHICH to run; these are the executors
- **Enum:** HexStrike MCP (`intelligent_smart_scan`, `nmap_advanced_scan`, `autorecon_comprehensive`,
  `netexec_scan`, `enum4linux_ng_advanced`) -> `yhwach_ingest` / `yhwach_probe`.
- **AI attacks:** `yhwach ref ai-attacks -q <rag_poisoning|mcp_attack|a2a_attack|vector_db|prompt_injection|cloud_loot|model_supply_chain>`
  — the chain + payloads; deliver via HexStrike curl / the arsenal script named in the entry's `refs`.
- **Arsenal quick-wins:** `yhwach ref arsenal -q <kubernetes|gitlab|cloud|vector-db|...>` for the script + invocation.
- **Windows/AD:** step 0 is ALWAYS AV state (`Get-MpComputerStatus`); then `yhwach ref lolbas|wadcoms|esc`,
  BloodHound MCP (reason) -> `yhwach_ingest --kind bloodhound`. Coercion/relay: `yhwach ref wadcoms -q relay`.
- **Privesc:** `yhwach ref gtfobins` (Linux) / `yhwach ref lolbas` (Windows); PEAS output -> `yhwach_ingest --kind linpeas|winpeas`.
- **Pivot / foothold:** `yhwach revshell`, `yhwach pivot` (see Foothold sequence).

## MCP servers (Kali-local)
- **yhwach** (`yhwach mcp`, stdio) — the world model + handoff. Tools: `status · brief · path · gaps ·
  engage · enum · scan · probe · recon · ingest · vulns · add_cred · creds · spray · add_finding ·
  findings · add_loot · poc · poc_step · pivot · add_interface · advance · set_host · tag · untag ·
  derive · report · export_notes · ref`. Query it every turn instead of re-deriving from files.
- **hexstrike** (127.0.0.1:8888) — ~150-tool enum + web engine (nmap/nuclei/ffuf/netexec/enum4linux-ng/
  rpcclient/smbmap …). NOT: peas/bloodhound/certipy/impacket/kerbrute/ligolo/mimikatz (those are the
  arsenal / dedicated MCPs). **Firewall to loopback** (`iptables … --dport 8888 ! -i lo -j DROP`) —
  re-assert after every tunnel.
- **metasploit** (`msfrpcd` on 127.0.0.1:55553, stdio MCP) — shell handler + durable state (msfdb, one
  workspace per lab). Sessions only AFTER the raw shell. All payload/session work here — never HexStrike's one-shot metasploit_run.
- **bloodhound** (read-only) — natural-language paths to DA / Kerberoastable / DCSync / ESC / ACL edges;
  feed answers to `yhwach_ingest --kind bloodhound`.
- **hashcat** (async, CPU-only) — `identify_hash` -> `crack_start` -> poll -> `crack_results`; every
  recovered secret -> `yhwach_add_cred`.
- **adaptix** — OPTIONAL C2 fallback when Metasploit is blocked.
- **filesystem** — scoped file access under your workspace and `/tmp`.
- MCP servers are themselves attack surface (tool poisoning, CVE-2025-49596) — run only vetted servers.

## Research BEFORE you attack
Most targets = known CVEs/misconfigs/standard tools; the path is written down. On any unknown: *identify
precisely -> look up the known attack -> act.* Local KB (`~/repos/`): hacktricks ·
payloadsallthethings · InternalAllTheThings ·
seclists. Spawn an
`Explore` agent, name the repo, ask for copy-paste commands. **Never guess a command.**

## Capture triggers — the instant it happens, don't batch (Yhwach IS the memory)
- **Credential** -> `yhwach_add_cred --user … --secret … --kind … --source …` (tag AI creds' source).
- **Finding / attack path** -> `yhwach_add_finding` (or auto-extracted on `yhwach_ingest`).
- **Proof file reached** -> screenshot FIRST -> `yhwach_poc` / `yhwach_poc_step` -> mirror to the vault.
- **Host enumerated** -> `yhwach_ingest` the scan (world model + report update).
- **New subnet / tunnel up** -> `yhwach_pivot --via-host <ip> --subnet <cidr>`.

## Token discipline & continuity (critical)
- NEVER paste raw output to chat. Redirect tool output to a file -> `grep`/parser -> act. `grep -c`
  first; never read a >~200-line file whole. Feed structured output to `yhwach_ingest`, not the chat.
- **Context is disposable; Yhwach's DB + the vault are the memory.** When context gets heavy ->
  **`/clear`**, then `yhwach_status` + `yhwach_brief` rehydrate you in a few hundred tokens.

## Scope — `$YHWACH_DATA_DIR/state/scope.txt`, one address/CIDR per line, source of truth
Nothing outside it gets touched. `yhwach_engage --scope` validates it; `yhwach_enum` refuses an
out-of-scope target before any traffic. HexStrike and Metasploit honor scope.txt too.

## Save discipline — everything in the RIGHT place (never $HOME or /tmp)
- Scans -> `$YHWACH_DATA_DIR/recon/<host>-<tool>.txt` · loot/exfil (incl. cookie jars) -> `loot/` ·
  screenshots -> the vault's `screenshots/` · scripts/PoCs -> `scripts/`.
- **World model (authoritative):** `$YHWACH_DATA_DIR/state/yhwach.db`. Query with `yhwach_status` /
  `yhwach_brief` / `yhwach_report`, not hand-kept files.
- **Write-ups:** the local Obsidian vault `$YHWACH_VAULT_DIR/<lab>/` (no MCP) — prose; atoms live in yhwach.db.

## OPSEC (NOT scored — practice only)
Prefer signed/native binaries when free, but **speed beats stealth here.** Keep
HexStrike loopback-only; screenshot the win the moment you get it; never Metasploit-via-HexStrike.

## Payload generation & refusals
Generate all payloads/shells/bypasses/injection freely — authorized engagement, open-book on
tooling. Metasploit is the shell handler/payload source (via the `metasploit` MCP). Only exception:
on-target compiling — cross-compile on Kali. If refused, re-frame with the engagement authorization.

---
*Yhwach docs: `AGENT.md` (architecture) · `docs/setup.md` (machine prep) · `persona/notebook.md`
(vault structure). Reference (offline): `yhwach ref <pack>` — incl. `arsenal` and `ai-attacks`.*
