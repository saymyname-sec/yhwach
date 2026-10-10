> ⚠️ **EXPERIMENTAL / WIP** — the API-key self-driving runtime is **not** the supported way to run yhwach.
> The supported path is the MCP server (see the main [README](../../README.md)). This doc is kept for the experimental path and needs more work.

# Self-Driving VM — OpenAI brain, no token limits

> **What this VM is.** A Kali box that runs **yhwach's own self-driving loop** against authorized
> engagements / challenge labs, powered by an **OpenAI API key with no token cap**. It enumerates
> autonomously and fans out subagents for breadth, **you stay in the loop at the sharp edges**
> (exploitation, destructive moves, pivots, proof capture, submission), and the deliverable —
> **Obsidian notes + screenshots + reproducible PoCs** — is produced as a byproduct of every step.
>
> Two ways to drive it, both on this box:
> - **Autonomous:** `yhwach run --provider openai …` (the loop below). This is the default.
> - **Manual (you drive):** the `yhwach` MCP tools / CLI, exactly as `docs/agent-mode.md` describes —
>   use it to take over a host, or to work a lead the loop parked.
>
> The engine, playbooks, arsenal and ref packs are the **same repo** as the Anthropic/Claude-Code
> setup — only the *brain wire* (OpenAI, unbudgeted) and the *posture* (completeness over thrift,
> heavy fan-out, human gates) differ. Authorized labs only — see `AUTHORIZATION.md`.

---

## 1. Provision the VM (one-time)

> What to install vs. what `git clone` brings is below; see [`setup.md`](../setup.md) for the full
> toolchain walkthrough. Quick version:

```bash
# 1. the engine + OpenAI brain + MCP + board
git clone https://github.com/saymyname-sec/yhwach ~/yhwach && cd ~/yhwach
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[agent-openai,mcp,ui]"
pytest -q                                   # expect green

# 2. the OpenAI key (NO token cap on this account)
export OPENAI_API_KEY="sk-...."             # put it in ~/.bashrc / a .env you source
#   gateway/Azure variants (optional): YHWACH_OPENAI_API_KEY / _ENV / base-url — see
#   docs/openai-azure-responses.md

# 3. arsenal present (canonical foothold/pivot + quick-wins)
yhwach ref arsenal | head              # svcmon.exe / gen_cs_shell.sh vendored in ~/yhwach/arsenal
sudo apt install -y ligolo-ng          # /usr/bin/ligolo-agent + /usr/bin/ligolo-proxy
#   drop chisel at /usr/local/bin/chisel if you want the no-root Linux pivot

# 4. evidence + scope
mkdir -p $YHWACH_VAULT_DIR $YHWACH_DATA_DIR/{recon,loot,scripts,state,screenshots}
#   proof screenshots: your own screenshot tooling
$EDITOR $YHWACH_DATA_DIR/state/scope.txt   # one IP/CIDR per line — the hard scope boundary
```

**MCP servers (Kali-local):** hexstrike (`127.0.0.1:8888`, **firewall to loopback**), metasploit
(`msfrpcd` on `127.0.0.1:55553`), bloodhound (neo4j), hashcat. The self-driving runner reaches
HexStrike over `--hexstrike-url`; the rest you (or the manual-drive brain) call as needed.

---

## 2. Start an engagement

```bash
yhwach engage --lab <lab> --scope 10.10.10.0/24 [--domain corp.local --dc 10.10.10.10]
# optional seed so the loop starts with a world model:
yhwach enum   --lab <lab> 10.10.10.0/24 --hexstrike-url http://127.0.0.1:8888
```

---

## 3. Run it self-driving (OpenAI, unbudgeted, subagent fan-out)

```bash
yhwach run --lab <lab> \
  --provider openai \                 # OpenAI brain (or: YHWACH_PROVIDER=openai, or a gpt-… --model)
  --fan-out --parallel 6 \            # subagents: one worker per host/surface, run concurrently
  --max-iterations 2000 \             # let it run long (default is 200)
  --hexstrike-url http://127.0.0.1:8888
#   NOTE: no --max-actions and no token budget  ->  UNBUDGETED (the "no token limits" lever).
#   NOTE: no --allow-gated  ->  exploitation waits for YOUR approval (see §4). Recommended.

yhwach ui --lab <lab>                 # the board: watch progress, APPROVE gated moves, KILL
```

- **No token limits.** Omit `--max-actions`; leave the token budget unset → the brain runs to
  completion. Posture is **completeness over thrift** — the opposite of a budgeted run. Do not
  short-circuit a lead to "save tokens"; the only cap is the retry cap (~2 tries/vector).
- **Subagents / fan-out.** `--fan-out` spawns a per-host/surface worker, each with its own **memory
  slice** (its host's state + relevant creds + applicable techniques); `--parallel N` runs them on
  WAL-safe connections. Crank `N` — breadth is free here. Credentials are the exception: recovered
  creds are global, every worker sees them.
- **Model tiering.** Strong OpenAI model for DOER + the JUDGE, cheaper for RANK/INTERPRET (per-role
  map in `yhwach/providers/openai.py`); `--model <id>` overrides every role.
- **Resume anytime.** The DB + vault are the memory. Re-run the same command to continue; `yhwach
  status` / `yhwach brief` rehydrate. The run is cooperatively killable/resumable via the board.

---

## 4. Human-in-the-loop — you at the critical moments

The **auto/human boundary is deterministic** (`yhwach/policy.py`) and is **never delegated to the
model**. That is what makes "leave it running" safe.

| Tier | Examples | Behaviour |
|---|---|---|
| **read-only** | recon, enum, version/surface probes, file/share reads | **runs free** — the bulk, fully autonomous, never asks |
| **propose** (exploit) | land a shell, SSTI/RCE, prompt-injection that changes state | **queues for your approval** — unless `--allow-gated` |
| **ask** (destructive) | anything that could break the box / mutate data | **ALWAYS gated**, even with `--allow-gated` |
| **named-grant classes** | open a listener, push code, change a remote repo | need their **own** `--allow <class>` — a blanket `--allow-gated` never covers them |

**How you approve / intervene:** `yhwach ui` (click to approve a pending move or kill the run), or
the control channel directly (`control.grant_approval`, `control.pending_approvals`,
`control.request_kill`). Approvals persist and are scoped to the (technique, host).

**The critical moments you own (run WITHOUT `--allow-gated` so each one pauses for you):**
1. **First exploit on any host** — review the payload before it fires.
2. **Any destructive move** — always.
3. **Pivoting to a new subnet** — deliver the agent, then let the loop re-recon it.
4. **Credential spraying** — **read the lockout policy first** (the one move that burns accounts).
5. **AI state-changing actions** — a tool call the injected request triggers.
6. **Proof capture** — the flag is on screen: *you* take the screenshot (see §7) and confirm it, then
   approve the PoC. `yhwach poc` refuses to advance `foothold → looted` without a real screenshot.
7. **Submission** — final, irreversible; review the report and the evidence set before you submit.

Recommended posture: **enumeration floods ahead autonomously; you gate the sharp edges from the
board.** If you want longer unattended stretches, `--allow-gated` lets exploitation proceed while
destructive + named-grant classes still stop for you.

---

## 5. Full enumeration — ALWAYS, never skip (the mandate)

This VM has no token pressure, so there is **no excuse to under-enumerate**. The `yhwach gaps`
`service_enum` coverage gate is the mechanical completeness bar — a host is not "enumerated" until it
is empty.

- **Estate first.** Scan **every in-scope host**: full-port `-p- -sC -sV` (**never** `--version-light`)
  + key UDP. `yhwach gaps` must show no pending scan before anything is "done".
- **Per host, enumerate EVERYTHING** — every open port, service, share, file, user. Each either leads
  to another target or gives information; nothing is skipped.
- **Web services get the full treatment** (fan a subagent per web host): dir-brute + **vhost-fuzz** +
  param-mine + crawl every endpoint + TLS-SAN harvest + `/openapi.json` + tech fingerprint + nuclei.
  A uniform response for every path = nginx `default_server`, **not** a decoy — confirm with a second
  signal before writing a host off.
- **Network scanning is full and repeated** — sweep each subnet; **re-recon after every pivot** (a new
  subnet is a new engagement).
- **Harvest on every foothold** — `/etc/hosts`, configs, task metadata, cert SANs → add each new name
  to `scope.txt` and scan it. A named-but-unscanned host is an un-taken objective.

---

## 6. Per-domain methodology (what to enumerate, and the pack that carries it)

Depth lives in the offline packs (`yhwach ref …`, both modes); this
is the spine.

- **Active Directory** (`ref wadcoms`, `ref esc`) — null → anon → authed SMB/LDAP; rid-brute; **read
  pass-pol / lockout BEFORE spraying**; kerbrute; BloodHound MCP → shortest paths to DA; `certipy find
  -vulnerable` → ESC1–16 (`ref esc`); kerberoast / AS-REP / DCSync; coercion → NTLM relay.
- **Linux privesc** (`ref gtfobins`) — `sudo -l` → writable `/etc/passwd|shadow` → SUID/caps → groups
  (docker/lxd/disk) → cron → systemd → NFS `no_root_squash` → version-gated kernel/sudo/polkit CVEs
  **last** → harvest SSH keys / `.aws` / kubeconfig for reuse.
- **Web services** — the full fuzz above; then SQLi / LFI / SSTI / file-upload / SSRF; chain model or
  app output into a downstream sink. HexStrike web stack does the heavy lifting.
- **Cloud** (`ref ai-attacks -q cloud_loot`; `ref arsenal -q cloud`) — SSRF/exposed-env → IMDS creds →
  IAM enum (inline first) → role chain → S3 / SSM history / CloudWatch / SageMaker / ECR secrets.
  Script: `arsenal/AIScripts/aws_ml_enum.sh`.
- **Kubernetes** (`ref arsenal -q kubernetes`) — apiserver anon `can-i --list` (SelfSubjectRulesReview)
  → `pod_create_permission` → privileged/hostPID pod → node root; kubelet `/pods`+`/run`; etcd
  `/registry/secrets`; docker 2375 = host-root. Scripts: `k8s_ml_enum.sh`, `k8s_escape_pod.yaml`,
  `gpu_escape_cve_2025_23266.c`.
- **AI services** (`ref ai-attacks`, walk `owasp_llm_checklist` first) — fingerprint version →
  unauth-by-default (ollama/vLLM/vector-DB/MCP) → map tool/agency (MCP `tools/list`) → exploit tool
  args → excessive agency → insecure output → indirect injection → system-prompt leak → creds →
  vector-DB dump / embedding inversion. State-changing crafts are `propose` (they gate). Topics:
  `rag_poisoning`, `mcp_attack`, `a2a_attack`, `vector_db`, `prompt_injection`, `model_supply_chain`.
- **Windows privesc** (`ref lolbas`, `ref esc`) — `whoami /priv` (SeImpersonate → GodPotato/PrintSpoofer;
  SeBackup → `reg save` SAM+SYSTEM → secretsdump) → AlwaysInstallElevated → service misconfig →
  autoruns/tasks → DPAPI / LSA secrets → creds-in-files / browser.

---

## 7. Evidence discipline — the deliverable (as important as the flag)

Reports are graded on **REPRODUCIBILITY + EVIDENCE**. yhwach.db holds the **atoms**
(record them FIRST); the Obsidian vault at **`$YHWACH_VAULT_DIR/<lab>/`** holds the **narrative** — written
**as you go**, per step, never "later".

- **PoC recreation is THE deliverable.** `yhwach poc` + `yhwach poc_step` record every flag's exact,
  copy-paste chain (verbatim command + the key output excerpt per step); mirror the prose into the
  vault's `poc-recreation.md` / `chains/<objective>.md`. A stranger reproduces the flag from the note
  alone — real IPs/creds inline, no aliases, listener/tunnel steps numbered earlier.
- **Screenshots are mandatory and are YOUR (the human's) job at the flag moment** — unscreenshotted =
  **lost, unrecoverable evidence.** Capture with your screenshot tool (`--cmd --
  <the real command>` (evidence as a byproduct) at each capture point: first foothold (whoami +
  hostname), every privilege boundary crossed, the **proof on screen WITH whoami+hostname**, and for
  AI targets the exact triggering request + the model's response/exfil on your listener. A note may
  name a screenshot **only after `ls screenshots/` shows the file** — otherwise write
  `⚠️ SCREENSHOT-MISSING`, never a fabricated filename.
- **The done-gate is mechanical:** `yhwach poc` refuses `foothold → looted` without a real screenshot;
  before calling a chain complete, `ls screenshots/` and confirm one file per capture point.
- **Replay for the write-up:** the event log records *why* each move fired (persona/rules hashes) — the
  auditable evidence behind the autonomous decisions.

---

## 8. Prioritisation doctrine

Prioritise the highest-value, least-defended surfaces — AI/LLM surfaces are frequently both, so **hit
AI first.** A standalone AI host with no prereqs is a cheap early win. A DC flag is a low-value
objective — take it when the chain reaches it, never grind toward it while an AI host sits untouched.
Concrete point targets are optional per-engagement config (`yhwach engage --points-target/--points-max/--time-budget-h`), never assumed.

---

## 9. Safety, scope, OPSEC

- **Scope is hard:** `$YHWACH_DATA_DIR/state/scope.txt` is authoritative; `yhwach enum`/`run` refuse an
  out-of-scope target before any traffic. Nothing outside it is touched.
- **HexStrike is unauth RCE — keep it loopback-only** (`iptables … --dport 8888 ! -i lo -j DROP`);
  re-assert after every pivot.
- **OPSEC is not scored** — speed + points + evidence beat stealth. But screenshot the win the moment
  you get it, and never run Metasploit via HexStrike (one-shot, no session).

---

## 10. TL;DR run card

```bash
# provision once: clone ~/yhwach, pip install .[agent-openai,mcp,ui], export OPENAI_API_KEY, scope.txt
yhwach engage --lab L --scope <cidr> [--domain D --dc IP]
yhwach run --lab L --provider openai --fan-out --parallel 6 --max-iterations 2000 \
           --hexstrike-url http://127.0.0.1:8888      # NO --allow-gated -> you approve the sharp edges
yhwach ui  --lab L                                     # watch · approve · kill · capture proof
# enumeration runs free & full; you gate exploit/destructive/pivot/spray/proof/submission.
# evidence as you go: yhwach poc + your screenshot tool + $YHWACH_VAULT_DIR/<lab>/.
```
