# AI Pentest Operator
# Methodology of AI Pentesting 

## Operating modes
- **Manual (default).** This methodology + `~/.claude/Enum_playbook.md` + the MCP servers below.
  The Obsidian vault is the source of truth; yhwach is NOT required — Claude CLI works normally.
- **Autonomous (opt-in).** When you run `/osai-lab` (or ask to "drive with yhwach"), the engagement
  is handed to **yhwach**: a SQLite world model owns the atoms (hosts/creds/findings/proofs/coverage),
  the vault owns the prose. Full yhwach-mode guide: `~/yhwach/docs/CLAUDE.osai.md`.
- **Offline reference works in BOTH modes:** `yhwach ref <pack>` — esp. `arsenal` (the vendored
  offensive-tooling index) and `ai-attacks` (RAG/MCP/A2A/vector-db/cloud chains, OWASP-LLM mapped),
  plus `gtfobins` / `lolbas` / `wadcoms` / `esc` / `default-creds` / `services`. No engagement needed.

## Hard gates
1. **One source of truth = the Obsidian vault.** Every scan/cred/file/share/service/port/finding lands there the same turn you learn it. If it isn't in the vault, it doesn't exist.
2. **Evidence is captured as a byproduct of the step, never retro-filled.** Use `osai-screenshot.sh --cmd -- <the real command>` at each capture point (§5). A note may name a screenshot **only after `ls screenshots/` shows the file**; otherwise write `⚠️ SCREENSHOT-MISSING`. A filename in a note is a claim the file exists — never fabricate one.
3. **Completeness gate before "done".** Before marking any host/flag complete, run the per-host checklist (§3) and `ls screenshots/`. An open door you didn't walk through = host NOT enumerated.
4. **Stuck-trigger: 2 failed approaches OR ~15 min on one lead → STOP and read the prior-lab notes first** (§7). Do not free-solo a web app for an hour before checking whether a past lab already solved this exact box.
5. **Verify before you claim.** "No result" is a hypothesis — re-run, read the pot/output file. Confirm exploitation landed before recording a win *or* a dead end. Blind ≠ dead (build an OOB channel).

## The methodology
1. **Scan the whole estate first** — every host in scope — and see what you can already reach/access.
2. **On every reachable target, enumerate EVERYTHING** — web dirs, SMB shares, every open port, every
   file, what is reachable we should check it. Each one either **leads to another target** or **gives you information**; nothing is skipped.
3. **Recover a user, cred key info, finding, port, files, shares, IP's, → write the obsidian vault note** (reproducible), and everything you find goes
  Obsidian vault — the memory.
4. **Reached a host in a NEW subnet?** Stand up persistence, + reach new network w ligolo if needed, record it to obsidian, then enumerate it the
   same way — to gather all the info about each new host, endpoint, web app.
5. **Repeat per subnet** as new ones appear,if needed.

**AI targets are what you most want to reach and enumerate — but often not on the first pass; win the
creds on another attack path first, then come back.** Read obsidian notes to see what is open vs gated.

## Enumerate EVERYTHING 
Every port, file, web app, share, and user, password spray, every config file, script literally everything that is not usually on endpoint can hold the next lead. Thats a map — not your memory — it is the completeness check.
- Check how hexstrike can enumerate each host(Analyze what he can be used), Full scan of network every time on new host with Hexstrike MCP, full scan of host whats inside if we reached new host with Hexstrike MCP, or just choose the best enumeration way by yourself
- **A uniform response for every path = nginx `default_server`, NOT a decoy** — fuzz vhosts before
  writing a host off. Never label "decoy" on one signal; confirm with a second.
- **On every foothold, harvest new targets**: read `/etc/hosts`, configs, task metadata, cert SANs →
  add each new name to `scope.txt` and scan it. A named-but-unscanned host is an un-taken objective.
- **Re-recon after every pivot** — a new subnet is a new engagement; scan it fully, then ingest.
- There will be local repos for reasoning if you will need to check how to reach or enumerate targets. I'm giving you also a repo with challenge labs done that there will be challenge labs which was done with whole attack chains, PoC's, how it was done etc. If you will be lost you should analyze local repo's for help of enumeration process and also check challenge labs which was done to maybe find same path of attack or a little bit different, but similiar. The solved challenge labs are in `~/ChallengeLabs`; your AI-attack notes are in `~/repos/OSAI`.

### Time-box (exam is clocked)
Per lead, set a budget before you start. On expiry: log it to `next-steps.md` /
`exhausted-approaches.md`, ingest what you learned, move to the next EV target. AI hosts
first (they're the pass mark). A stalled traditional host is never worth a skipped AI surface.

## Foothold → pivot sub-loop (C2/pivot are POST-foothold)
1. Find the path (enumerate + research). 
2. Get the **initial raw shell with custom script from arsenal**.
3. Upgrade to a **Metasploit session** (metasploit MCP), then **persistence** (scheduled task / run
   key / service). METASPLOIT HAVE TO BE UPGRADED TO METERPRETED AND THE BEST OPTION TO REACH SHELL IS MULTIHANDLER WITH CUSTOM MSFVENOM SCRIPT LOCATED IN ARSENAL.
4. **Ligolo** only when a new subnet must be reached — deliver the agent through
   the session, start tun, add route, then
If a session/persist/tunnel step fails, hand it to Kapi — don't loop.

## Notebook — Obsidian The only source of truth
The vault is a **local Obsidian folder** at `~/osai/notes/<lab>/` (inside
filesystem-MCP scope; created per engagement). **Write `.md` files straight into it with the file tools** — Obsidian is
open on that folder and renders them live. There is **NO Obsidian REST/MCP server** in the loop;
the files ARE the vault, so a note exists the moment the file is written.
Screenshots live INSIDE the lab folder at `<lab>/screenshots/` so Obsidian embeds them via
`![[file.png]]` — nothing referenced from a note may sit outside the vault.
The vault holds the narrative and should be fed with detailed info, per the schema below:
Note-set (one folder per lab):
- `index.md` — status board: links to every note + findings/hosts/creds tables
- `overview.md` — 30-sec summary + one line per objective
- `enumerated.md` - Here you we will store everything that was already enumerated and could be usefuly for later.
Everything matters, scripts checked,ports, important documents thats shows sensitive info, enumerated hosts, users nmap outputs everything should be stored here !
- `attack-chain.md` — the full end-to-end kill-path (newest phase last)
- `credentials.md` — every cred: value · where valid · how obtained
- `network-map.md` — hosts, ports, subnets, tunnels
- `next-steps.md` — open leads · `exhausted-approaches.md` — decoys / dead ends (don't re-try)
- `hosts/<host>.md` — one per host (services, access, privesc)
- `findings/<F-ID>.md` — one per finding (class, severity, evidence, repro, source/attribution, screenshot path)
- `chains/<objective>.md` — one reproducible chain per flag, every command and its console output, payload, script (or source link + modifications), and a screenshot at each stage, start to flag.
- **Every flag you retrieve gets its own note with the exact, reproducible "how to get it" chain** —
  every command + payload, script, copy-paste, start to flag everything that should be noted land here in OBSIDIAN VAULT ! That is the deliverable.

## PoC / exam-report standard (how every chain note MUST be written)
The exam grades REPRODUCIBILITY + EVIDENCE, not prose. Insufficient docs = reduced/zero
points, and submission is FINAL — nothing can be added after. So every `chains/<objective>.md`
is written so a stranger reproduces the flag by copy/paste, and carries its own proof.

Each PoC chain note MUST contain, in order:
1. **Target + objective** — host/IP, service, what flag/proof this yields, points.
2. **Vulnerability** — the class/CVE/misconfig in one or two sentences (feeds the summary).
3. **Prerequisites** — exact creds/tunnels/access needed to START this chain (link the note
   that produced them). A reader begins here with nothing else.
4. **Steps** — numbered. For EACH step:
   - the **verbatim command** in a fenced block (runnable top-to-bottom, real IPs/creds
     inline, NO aliases, NO `$VAR` the reader can't resolve, no shell-prompt noise);
   - the **relevant console output** underneath (redirect to file → paste the key excerpt,
     not the whole dump);
   - a **screenshot reference** for any step the exam must SEE (see capture points below).
5. **Proof** — the flag/proof contents + the screenshot showing it WITH `whoami`/`hostname`
   (Windows) or the exact triggering request + model response (AI targets).
6. **Source & modifications** — for ANY third-party exploit/script: the source URL or
   searchsploit ID AND a copy of the code (or arsenal path), PLUS a description/diff of every
   edit you made. For arsenal scripts (revshell/loader/svcmon), record which script, the exact
   build command, and the PORT used.
7. **Cleanup/notes** — persistence installed, port chosen, anything left running.

### Reproducibility rules (a technically competent stranger, copy/paste, no context)
- Commands are self-contained: no operator aliases, no reliance on your shell history/env.
- Real values inline (IPs, creds, hashes) — this is the deliverable, not your live shell.
- Every fenced block runs in the order shown; if a step needs a listener/tunnel up first, it's
  an earlier numbered step, not an assumption.
- "It worked on my box" is not proof — the OUTPUT and SCREENSHOT are the proof.

### Screenshot capture points (mandatory — unscreenshotted = 0, cannot add after submission)
Capture the MOMENT it happens with the **flameshot-backed** `~/osai/bin/osai-screenshot.sh`.
It saves into `<vault>/<lab>/screenshots/` and prints the `![[file.png]]` embed to paste into
the note. Two modes:
- `osai-screenshot.sh -l <lab> -n <label> --gui` — draw a region; use this for PROOF shots so
  the flag + `whoami`/`hostname` are framed together.
- `osai-screenshot.sh -l <lab> -n <label> --cmd -- <the real command>` — runs the command, tees
  its output to `<label>.txt`, then captures — evidence as a byproduct of the step.
Capture at each of:
- initial foothold / first shell (whoami + hostname visible);
- each privilege boundary crossed (user→admin/root, host→host);
- the proof/flag on screen WITH whoami+hostname;
- AI targets: the exact triggering request AND the model's response/exfil on your listener;
- any web exploit: the request/response (Repeater/curl) that lands it.

**File-existence rule (anti-fabrication):** a note may reference a screenshot **only if the
file already exists** in `<vault>/<lab>/screenshots/` — verify with `ls` before writing the
reference. If it is not captured yet, write the literal token `⚠️ SCREENSHOT-MISSING`, **never a
filename for a file that does not exist.** A filename written into a note IS a claim that the
file exists. `osai-screenshot.sh` enforces this for you: on success it prints only the real
saved path + its `![[...]]` embed, and if flameshot writes nothing it prints
`⚠️ SCREENSHOT-MISSING` and exits non-zero — so prefer it (especially `--cmd -- <the real
command>`) and paste exactly what it prints.

###  Note's Discipline
- Write the PoC note AS YOU GO, per step — never "record it later." After a submission or a
  /clear, an uncaptured step is lost points with no recovery.
- A target is NOT done until its chain note reproduces end-to-end AND every capture point has a
  screenshot .
- **Done-gate (mechanical check):** calling any `chains/<objective>.md` complete, run `ls screenshots/` and confirm **one file per
  capture point**. A capture point with no file on disk = the step is undocumented = the
  host/flag is **NOT done**, regardless of what the note text claims. The screenshot is the one
  step you never skip for speed — undocumented = zero points, unrecoverable after submission.


## Playbooks
Two on-demand references — read them, don't inline them (keeps per-turn tokens low):
- **`~/.claude/Enum_playbook.md`** — enumeration map: per-surface techniques + a decision
  tree. Read it to CHOOSE the approach on any host/service.
  
## Arsenal  (vendored at `~/yhwach/arsenal/`; index: `yhwach ref arsenal [-q <term>]`)
- **Reverse shells** (AV/Defender-bypass; read each script's header): `~/yhwach/arsenal/gen_cs_shell.sh`
  (C# revshell — works well on Win11 with AV on; NEW port per host, record it) and
  `~/yhwach/arsenal/gen_linux_shell.sh` (7-payload Linux menu). Persistence port must differ per host;
  land persistence via cron/scheduled task/service.
- **Ligolo agent** — `~/yhwach/arsenal/svcmon.exe` (obfuscated Windows agent, AV-bypass, sha256-pinned).
  Linux agent/proxy come from the `ligolo-ng` apt package (`/usr/bin/ligolo-agent`, `/usr/bin/ligolo-proxy`).
- **MSFconsole custom loaders** — `~/yhwach/arsenal/msfconsole/` (`build.sh`, `loader.cs`, `handler.rc`,
  `cheatsheet.md` — firewall-evasive; read the cheatsheet).
- **Mixed scripts** — `~/yhwach/arsenal/AIScripts/` (k8s/gitlab/cloud enum, vector-db dump/inversion,
  model/RAG poisoning, A2A MITM, obfuscation). Surface-specific quick-wins, indexed by
  `yhwach ref arsenal`; the AI attack CHAINS live in `yhwach ref ai-attacks`. Read the source for usage.
- **Quick-wins, not a substitute** — arsenal scripts are opportunistic. Enumerate every service with
  the full Kali toolset (HexStrike + free shell) first; "no script matched" ≠ "nothing to do".

## Research BEFORE you attack
- OffSec = known CVEs/misconfigs/standard tools. Identify precisely → look up the known attack → act.
   Local KB (`~/repos/`): hacktricks · payloadsallthethings · InternalAllTheThings ·
   OSAI (your AI-attack notes — check FIRST) · seclists. Also `yhwach ref ai-attacks` for the
   curated LLM chains. Spawn an `Explore` agent for copy-paste commands; never guess a command.
- Challenge labs that i have done through learning are provided in ~/ChallengeLabs . This dir contains 
   every lab that i have solve with attack chains, PoC's notes etc.

## MCP servers (Kali-local)
- **hexstrike** (`127.0.0.1:8888`) — the tool executor for enumeration. Runs tools and returns
  structured output via ingest. **Unauthenticated RCE —
  firewall to loopback** (`sudo iptables -A INPUT ! -i lo -p tcp --dport 8888 -j DROP`);
  re-assert after every pivot.
- **hashcat** (`python3.13 ~/osai/tools/claude/hashcat_mcp.py`) — the cracker. This box is
  CPU-ONLY, so it runs ASYNC: `identify_hash` → `crack_start` → poll `crack_status` →
  `crack_results` (hash:plain). `crack_jobs`/`crack_stop` manage jobs; `john_crack`/`john_show`
  are the fallback for formats hashcat lacks (AS-REP, NetNTLM edge cases). Jobs + potfiles land
  in `loot/cracking/`. **Every recovered secret → OBSIDIAN VAULT immediately.**
- **bloodhound** (`~/repos/BloodHound-MCP-AI/.venv/bin/python ~/repos/BloodHound-MCP-AI/BloodHound-MCP.py`)
  — AD attack-graph reasoning, read-only, talks straight to neo4j
  (`bolt://localhost:7687`, creds `neo4j`/`bloodhound`). Ask in natural language (dozens of
  canned `find_*` queries) or `query_bloodhound` for raw Cypher: shortest paths to DA,
  Kerberoastable/AS-REP, DCSync, ESC1-8, ACL edges, trusts. Feed answers to Obsidian with all the
  info about AD.
  **neo4j autostarts on boot** via systemd (`/etc/systemd/system/neo4j.service`, JAVA_HOME pinned
  to Java 11 because this box's neo4j v4.4 crashes on the default Java 25 `UseBiasedLocking`). If
  it's not up, run `~/osai/bin/bloodhound-up.sh` (wraps `sudo systemctl start neo4j`). Manage with
  `sudo systemctl {start,stop,status} neo4j`; data dir is `/etc/neo4j/data`. Graph is empty until
  you ingest SharpHound JSON.
- **metasploit** (`/opt/MetasploitMCP/.venv/bin/python /opt/MetasploitMCP/MetasploitMCP.py
  --transport stdio`) — the shell handler + durable session state (POST-foothold). One workspace
  per lab. **Runtime deps:** needs `msfrpcd` listening on `127.0.0.1:55553` (start with `-S` for
  SSL-off) and PostgreSQL up for durable msfdb — if the server won't connect, that's why. If a
  session/persist step fails, hand to Kapi — don't loop.
- **adaptix** (`python3.13 ~/osai/tools/claude/adaptix_mcp.py`) — *OPTIONAL* C2 fallback
  (teamserver `https://localhost:4321`, must be running). Use it when Metasploit/msfconsole is
  bugging or when you want C2-style agent control: `list_agents` → `execute_command`/
  `shell_terminal`, `start_socks5`/`start_port_forward` for tunnels, `list_credentials`. Not the
  default path — reach for it only if the Metasploit route is blocked.
- **filesystem** — scoped file access under `~/osai` and `/tmp`.

## Discipline
- **Netexec everywhere** — `nxc` this is our best AD tool for enumerating
- **Token/output:** redirect tool output to a file → grep/parse → ingest; never paste raw dumps to
  chat. `grep -c` before reading a big file. Context is disposable; the memory is
  continuity from obsidian vault you can check progress, what was already enumerated, what creds we have and what files we check.
- **Save discipline:** recon → `~/osai/current/recon/`; loot → `loot/`; scripts → `scripts/`; state
  (scope.txt, network_map.md) → `state/`; notes AND screenshots → the local vault
  (`~/osai/notes/<lab>/`, shots under `<lab>/screenshots/`). Never `$HOME`/`/tmp`.
