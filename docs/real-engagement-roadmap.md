# yhwach beyond CTFs: analysis and roadmap for real engagements and bug bounties

*Analysis date: 2026-10-12. Base: `main` at 50657e7.*

## How this was produced

| Step | What ran | Output |
|---|---|---|
| Understand | 8 code readers, one per subsystem (memory core, knowledge/recall, read views, active/safety, MCP+CLI wire, board, reporting/evidence, tests/docs/legacy) | Subsystem maps with `path:line` evidence, CTF assumptions, weaknesses, extension points |
| Ideate | 8 practitioner lenses: AD/network consultant, bug-bounty/web hunter, cloud assessor, red-team lead, delivery/QA lead, AI-security assessor, MCP-ergonomics engineer, product strategist | 106 raw ideas |
| Merge | Clustering, then deterministic merge in code | 67 distinct ideas |
| Verify | Two adversarial reviewers per idea: a senior engineer checking the tree, and a 10-year pentester/hunter trying to refute practical value | 66 survived, 1 dropped, 64 reshaped |
| Critique | Completeness critic over all survivors | 6 missing areas |
| Gap round | Ideation on the 6 missing areas, then the same two-reviewer check | 34 more ideas |

**Verification coverage is uneven in the gap round.** Usage limits cut the last verification batch short. Of the 34 gap ideas, 6 were checked by both reviewers, 13 by the practitioner only, and 15 by neither. The unverified ones are marked **(unverified)** below; treat their effort estimates as rough.

The headline safety findings in section 2 were re-checked by hand against the code before writing this.

---

## 1. Bottom line

yhwach already owns something nobody else has: a typed, honest engagement memory with a deterministic, chaining-aware recall menu that the operator's own model reads over MCP, with no API key. BloodHound has the graph but no memory of what you tried. Ghostwriter, Dradis and PlexTrac have the register but no recall. HexStrike and the nmap/Metasploit MCPs execute but remember nothing. The key-bound autonomous agents (PentestGPT, CAI, PentAGI, XBOW, Strix) decide for you. yhwach is the only one that sits in between.

Three things stand between that and real work, in this order:

1. **It is not safe on a client network.** Writing a credential or an nmap file to memory sends authentication traffic, behind a lockout guard that is broken for the most common thresholds, with no scope check on any traffic path. No consultancy review or bounty program would allow this. Fixing it is mostly bug fixing plus one engagement-level switch.
2. **It can only describe a lab.** Scope is IPv4 CIDRs, the only asset is an IPv4 host, the engagement is a scored lab with flags and points, and a finding cannot carry CVSS, remediation, affected instances or a status change. Bounty, web, external and cloud engagements cannot even be opened.
3. **The tools people actually run have no landing path.** Six parsers cover the OSAI toolchain. Nessus, testssl, secretsdump and potfiles, httpx/nuclei/subfinder, Burp/HAR and kubectl output all degrade to hand-typed findings, which by yhwach's own invariant makes them drift generators.

The recommended order is: make it safe, then make it able to hold a real engagement, then make the wire actionable, then widen ingestion one engagement kind at a time.

---

## 2. Verified safety bugs to fix before anything else

These are defects, not features. Each was confirmed in the tree.

| # | Bug | Evidence | Consequence on a client network |
|---|---|---|---|
| S1 | The lockout-threshold parser matches the digit `0` anywhere, so 10, 20, 30 and 100 are stored as "no lockout" | `yhwach/parsers/netexec.py:207-211`; guard filters `threshold > 0` at `sprayer.py:258-262` | The sprayer's only safety guard is off on the most common hardened-AD settings |
| S2 | The lockout guard is fail-open when no policy row exists, which is the normal state on day one | `sprayer.py:251-266, 523`; pinned by `tests/test_sprayer.py:414` | Unlimited spraying until someone happens to ingest `--pass-pol` |
| S3 | NTLM hashes are sprayed as passwords; there is no `-H` branch | `sprayer.py:325` builds `-u user -p secret` for every kind | Pass-the-hash never succeeds, every hash burns lockout budget, and a false `fail` is cached |
| S4 | `api_key` and `token` creds are sent as `Authorization: Bearer` to the root of every web-ish service in memory, and any 200 counts as a valid login | `sprayer.py:96-97, 417-431` | Client secrets are transmitted to arbitrary hosts, and public homepages "validate" every token |
| S5 | Any product string containing `http` on a non-listed port is sprayed as WinRM | `sprayer.py:79, 166-171` | Wrong-protocol auth attempts against production web servers, counted against domain lockout |
| S6 | Recording a credential sprays it, and an nmap ingest sprays the whole vault, with no off switch | `mcp_tools.py:331, 451` | Taking a note generates an auth burst, outside any testing window |
| S7 | No traffic path checks scope. `tool_scan` scans after `observe_ip` silently refuses, MCP `tool_enum` has no check, nmap ingest inserts every host in the file, and the sprayer selects every service | `mcp_tools.py:1130-1131, 517-549`; `parsers/nmap.py:349-373`; `sprayer.py:175-205`; the only scope call in `mcp_tools.py` is in `engage` | A typo or a pasted neighbour's scan leads to nmap, nxc and HTTP probes against an unauthorised target, with no record |
| S8 | `yhwach_enum` interpolates `target` unquoted into a shell command on the operator's box, and the loopback check is a substring test | `hexstrike.py:69, 77-78` | A prompt-injected agent can run arbitrary commands on Kali |
| S9 | Re-adding a credential with a new password overwrites the secret in place, and the cached `fail` row blocks the new secret from ever being tried | `db.py:810-848`; `sprayer.py:234-251` | Password-spray workflows silently do nothing after the first miss |
| S10 | `169.254.169.254` in finding evidence becomes a host row queued for a full-port scan | `discovery.py:50-58` does not reject link-local | A link-local address gets `-p-` scanned and pollutes the estate |

Fix S1 to S5 and S8 to S10 as one small PR, with fixtures for thresholds 10 and None. S6 and S7 need the engagement switch and the scope chokepoint described in theme A.

---

## 3. Where yhwach stands today

### What is genuinely strong

- **Honesty ledgers.** `scan_coverage` records what was scanned, not just what was found. `probe_run` separates "never probed" from "probed, nothing matched". The `service_enum` gap names every discovered service nobody triaged. `CoverageScore` returns "n/a" instead of 100% on an empty engagement. No competing tool models under-enumeration as visible debt.
- **Deterministic chaining recall.** 173 technique rules, a matcher that emits every applicable technique, and `findings_include` chaining guarded by the tag-graph test. AD depth is production-grade (ESC1-16, BadSuccessor, shadow credentials, timeroast, MAQ to RBCD, coercion to ESC8).
- **The AI-security core.** 33 AI-surface rules, 11 cookbooks mapped to OWASP-LLM and ATLAS, probes that keep an MCP server's tool list with descriptions and parameters, and an OWASP-LLM PRESENT/ABSENT/UNKNOWN matrix. No open tool has this.
- **Disciplined read views.** Every view is pure SELECTs, shared by CLI, MCP and board. The dossier escapes hostile banners, and model annotations go stale honestly through a state fingerprint.
- **A good board.** The Recon matrix, the credential-by-service matrix, the NOT COLLECTED versus ABSENT encoding and the "UNKNOWN lockout is never safe" badge transfer directly to client work.

### What is lab-shaped

Every layer encodes the OSAI challenge-lab shape: one operator, one CIDR, flags with points, a time budget, proof screenshots.

- **Scope and identity.** `scope.py` accepts only IPs and CIDRs, and `in_scope('dc01.corp.local')` is false by contract (`tests/test_scope.py:28-29`). `host.ip` is NOT NULL and every other entity hangs off it.
- **The engagement.** `engagement` has `points_target`, `points_max` and `time_budget_h`, but no client, kind, rules of engagement, status or end date. `objective.kind` defaults to `flag`.
- **The finding.** It is class, title, severity, one evidence line, tag and status. Nothing writes the status. Re-ingest overwrites curated evidence and never changes severity. Twelve XSS endpoints collapse into one row.
- **Coverage.** "Complete" means `-p-`, `-sV` and UDP top-100 per host, with hard-coded `-T4` fix commands. There is no per-web-app, per-domain, per-account or per-test-case axis. On a /22 every placeholder owes a full scan for the whole engagement.
- **Vocabulary.** "You may be about to miss points", "Engagement scoreboard", 👑 objectives and `PROOF the flag path` reach the model and would reach a client.

### Structural root causes

1. **The engagement and asset model is the blocker for everything else.** Until a domain, URL, wildcard or cloud account is a first-class in-scope target, web, bounty and cloud features have nowhere to land.
2. **The MCP wire is one-way prose.** This was diagnosed earlier and is still open. Results are `str()`-coerced, recall candidates lack the command, and nothing records what the model tried. Nothing wrong can be corrected: the only DELETE in the package removes a host tag.
3. **Memory writes have side effects.** Spraying and scan queueing are bolted onto record verbs, so "record-only" mode does not exist.
4. **The legacy runtime is still load-bearing.** About 2,900 lines and 169 tests serve the unsupported autonomous loop. `knowledge.py` imports `policy.ActionClass`, the board's `/report` goes through `synthesis` and `judge`, and the ~70 `interpret` extractors are reachable only from `runners.py`.
5. **Docs contradict the product.** `AGENT.md` claims precedence for an API-key agent. `cli/README.md` documents 11 commands that do not exist. `docs/setup.md` installs `agent-mode.md`, with "15 free points" and "if refused, re-frame", as the user's global CLAUDE.md. CI skips the 110 board tests because the `ui` extra is not installed.

---

## 4. CTF assumptions to unwind

| Assumption | Evidence | Why it hurts in real work | Replace with |
|---|---|---|---|
| Recording a fact is permission to send traffic | `mcp_tools.py:331, 451` | Lockouts, out-of-window traffic, credential testing that bounty programs forbid | Record-only by default outside labs; arming is a human CLI act |
| Scope is a comma-separated CIDR list with no exclusions | `scope.py:20-27`; re-engage overwrites at `db.py:490-498` | Bounty, external and cloud scopes cannot be entered; exclusions live in the tester's head | A typed `scope_entry` table with kinds, include/exclude, and one `assert_target` chokepoint |
| The only asset is an IPv4 host | `schema.sql:34,47`; `discovery.py:111-113` | Subdomains, CDN-fronted apps, buckets, roles, repos and IPv6 have no row | Domain- and URL-keyed web assets plus a generic `asset` table with nullable `host_id` |
| An engagement is a scored, time-boxed lab | `engagement` columns; `objective.kind` default `flag` | No client, kind, ROE, status or retest; points and flags leak into every output | One engagement-profile spec: uid, kind, client/program, status FSM, ROE |
| One operator, no attribution | `event` has no actor; annotation author hard-coded to `claude-code` | No testing log for the SOC, no multi-tester attribution | An actor on every write, plus an activity ledger |
| Facts are never wrong | Only DELETE is `remove_host_tag`; `finding.status` has no writer | False positives, duplicates and fixed findings live forever and keep feeding recall | Status verbs with tombstones and events, never deletes |
| Every host follows own-the-box: scanned, foothold, looted, pivoted | `db.py:575`; UDP floor at `coverage.py:26-27` | Web, cloud and bounty work has no foothold FSM, and ROEs forbid UDP or full-port sweeps | Per-asset coverage and test cases, with ROE waivers rendered as waived |
| Every address in scope owes a `-Pn -p-` scan | `discovery.py:127-133`; `scanner.py:75-93` | 820 dead addresses on a /22 scanned for hours, "1000 pending" forever | Discovery-first: alive state, masscan and `-sn` ingest, out-of-band scans clear the flag |
| Secrets can be printed in full to the model and the report | `mcp_tools.py:351-378`; `report.py:113-114` | Every transcript and report becomes a credential store | Masked by default in read views, a vault-derived masker on exports, 0600 files |
| Ownership is any credential whose name matches a principal | `pathfind.py:53-58` | A guessed or uncracked credential reports a one-hop path to DA | Ownership only from validated access or an explicit "owned" mark |
| The crown is Domain Admins or a host-bound flag | `pathfind.py:30, 69-86` | No path to "HR SQL server", "CDE segment", Tier-0 groups or cloud admin roles | Tier-0 pack plus objective kinds `crown_jewel`, `segment` and `principal` |
| Version match equals a confirmed vulnerability | `vulns.py:126-136` (state confirmed, CVSS 5.4 rendered as high) | Inflated severities in a client report | `state='potential'` and severity from the real CVSS band |
| Content-discovery keywords are findings | `ingest.py:75-83`; `parsers/web.py:16-24` | "CWE-200 Web api surface (medium)" for `/static/v2/x.json` | Info-severity LEAD rows with chaining tags, kept out of the findings register |
| The self-learning loop copies exact tool output into the repo | `docs/commands/yhwach-learn.md:44-46` | A client data leak into a public MIT repo and the wheel | Lessons over the wire, gap reports, and fixture capture only on synthetic engagements |
| The persona is one lab file | `persona/operator.md`; `docs/agent-mode.md:177-184` | "Speed beats stealth" is wrong for red teams and bounties | A per-kind instruction fragment written by `yhwach init`, plus deterministic gates |

---

## 5. The ideas, by theme

Each table lists the idea id, what to build in the reviewers' corrected shape, effort (S, M, L or XL), and real-world value from 1 to 5, averaged across both reviewers. "Ops" notes are corrections from the practitioner reviewer that change the design.

### Theme A. Safe on a client network

Nothing else matters until these land. All are deterministic gating on typed rows, so they fit the north star exactly.

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I01 | Sprayer fixes: anchored lockout parser with fixtures for 10/20/None; unknown policy blocks domain auth with a clear message; `-H` for NTLM; drop `http` from WinRM products; an unauthenticated baseline before http-basic counts a 200; domain-matched policy selection; a `yhwach spray --dry-run` CLI twin | M | 5 | The claimed "2x under-count" is wrong, because `--local-auth` does not hit the domain counter. Key the cache on a secret fingerprint so a second password gets tried (S9) |
| I02 | Engagement `active_mode` (record_only or armed, record_only by default for every kind except lab), `status` (active, paused, closed), and a small ROE record (`no_spray_accounts`, max attempts per account per window, exclusions). One `roe.gate()` in front of both autospray hooks and scan/probe/enum/spray | L, M core | 5 | **Arming is a human CLI act** (`yhwach arm --until`), never an MCP argument. Do not reuse `force=True`, which already means "re-spray cached pairs". Drop the 15-key ROE JSON |
| I03 | `scope_entry` table (cidr, ip, hostname, domain, wildcard, url_prefix; include or exclude; removed_at) and `scope.assert_target()` called by scan, enum, probe, the sprayer's candidate query, scanner queue and nmap ingest. Out-of-scope hosts are kept as `blocked` rows so the report can list "observed, not tested". An empty table means memory writes allowed, traffic refused | L | 5 | Add `yhwach scope check <target>`. Resolve hostname exclusions to IPs at add time or warn. `next`, `gaps` and `paths` must hide excluded hosts |
| I04 | Protected host tags (do-not-touch, honeypot, fragile, blue-team) honoured inside `_run_matrix`, `scan_host`, probe and enum, and by recall | M | 5 | Tags only exist after discovery, so the primary exclusion source is the ROE list from I02/I03. Validate tag names at write time |
| I21 | HTTP profile honoured by probes and the http-basic adapter: user agent, required headers (`X-Bug-Bounty`), Burp proxy, TLS verify, delay and jitter, `write_probes: false` default outside labs, and one `nmap_extra_args` passthrough | M | 5 | Fold this into the I02 ROE record, not a separate `opsec_json`. Write-shaped probes (chat POSTs, MCP `initialize`) get `WRITES=True` and record `skipped_policy` as a coverage gap |
| I26 | `api_key`, `token` and explicit cloud kinds get no spray adapter; validate `kind` on add; `credential.realm` and `expires_at`; expired and cloud creds listed as "held identities", not "spray these" | L, S slice 1 | 4 | Do not invent canonical ID formats; keep whatever the cloud CLI printed |
| G3b | Credential provenance: provided, discovered, derived or guess. Provided accounts skip autospray, are excluded from "compromised" counts, and appear as assumed-breach start nodes in pathfind **(unverified)** | M | 5 | The critic called this "the reporting error that gets consultants fired". `tool_derive` writes `derived` |
| G4d | Required rule field `impact: read, write, modify or destructive`, replacing the dead `likelihood`/`time_cost`. Recall annotates it, the ROE gate consumes it, and the report methodology lists modifying actions | L | 5 | ROEs are written in exactly this vocabulary: no lockouts, no password changes, no new accounts |
| G4e | Expiring `approval` rows naming rule, host, impact and approver, recorded by `yhwach approve` (human) or `yhwach_approve` with the human's verbatim words. Write, modify and destructive moves need one **(unverified)** | L | 5 | Replaces the README's unbacked promise that the human approves every exploit |
| G4c | Stop and pause: a `stop_request` or `pause` notice flips `paused_at` atomically, every traffic path refuses with code `paused`, and a red banner shows until resume **(unverified)** | M | 5 | Resume never re-arms; pause and arming are separate axes |
| I60 | One `ToolError(code, hint)` contract: `out_of_scope`, `paused`, `unknown_lab`, `bad_arg`, `refused`. Re-raise as an MCP error so the SDK sets `isError` | S | 3 | A typed `out_of_scope` refusal is a safety control: the model stops routing around it |

### Theme B. Engagement and asset model

The critic's strongest structural note: I02, I16, I18, I20, I42 and I67 each define `engagement.kind` with a different enum. **Write one engagement-profile spec first**: a stable engagement uid, `kind` (lab, internal, external, web, cloud, redteam, bounty, retest), client or program, a status FSM (kickoff, active, paused, reporting, retest, closed), ROE, and data policy.

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I29 | One generic non-IP target: `asset(kind, identifier, name, parent, host_id NULL, first_seen, last_seen)` with `asset_id` on finding, credential and loot. Cloud scope kinds go into `scope_entry` | L | 4 | Not an 8-provider, 20-kind hierarchy. Land it ingest-first, never through 400 manual `add_asset` calls |
| G3c | Scope importers into `scope_entry`: TXT/CSV, HackerOne, Bugcrowd and Intigriti policy JSON, AWS/Azure account lists, each with source, severity caps and a diff on re-import | M | 4 | Half the platform schemas were guessed. Start with TXT/CSV and bbscope output |
| G3a | Authorization record: window, declared source IPs, authorizing and emergency contacts, shown on the report cover and checked by the arm gate | M | 4 | Ops: the window and source IPs in the model's context are the useful part. The document hash is ceremony |
| G3e / G3f | A kickoff checklist when `status='kickoff'`, each item carrying the exact call that closes it, and a one-file `kickoff.yaml` import | M / S | 4 | Keep it short with few hard gates. Secrets never go in the YAML |
| I48 | Continuous recon: `last_seen`, latest-wins for status/title/tech, one `ingest_diff` event per run, a `changes` brief section and `yhwach_changes --since` | M | 4 | Tie staleness to an ingest run, not wall-clock days. Raw diffs are what `anew` already does; the value is typed flips correlated with recall |
| G3d | Vantage points on the coverage, probe, access and attempt ledgers, filtered and down observations kept as rows, and a `yhwach segmentation` matrix as positive evidence of isolation for PCI-style segmentation tests **(unverified)** | L | 5 | Internal pentests are defined by where you tested from |

### Theme C. Ingestion: meet the tools people actually run

Principle from the strategist lens: **integrate, do not reimplement.** Parse the normalised formats (ProjectDiscovery JSONL, bbot NDJSON, BloodHound CE exports, zizmor/poutine SARIF) and own the "what next" knowledge, not the scanner.

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I64 | `yhwach_interpret(text, kind='auto', host, url, dry_run)` as the single text entry point: sniff, parse, write typed rows, and return the `unlocked` rule diff. Unparsed text goes to loot and an event | L | 5 | Ambiguous shapes require a `kind=` hint rather than a guess. Strip ANSI and tmux wraps. An unparsed paste does not create a finding unless `title=` is given |
| G2a | `.nessus` v2 and OpenVAS XML into keyed `vulnerability` rows (plugin id, port, CVSS, solution, plugin output excerpt), plus a small promote pack (plugin 57608 to `smb_signing_off`, MS17-010 to `exploitable_cve`) | L | 5 | The network consultant's daily baseline. Qualys/Nexpose CSV are client VM-team artefacts; skip them |
| G2c | secretsdump NTDS/SAM/LSA/cached output into `credential` rows (ntlm, source dump, linked to principals), plus hashcat/john potfile ingest that promotes to plaintext and never sprays | M | 5 | A row-level `spray_policy='manual'` is mandatory |
| G2d | `yhwach password-audit`: total and unique hashes, percent cracked, reuse clusters, privileged accounts cracked, LM and empty hashes, observed policy versus reality | M | 5 | DPAT does most of this; the value is the joins with BloodHound membership and pathfind |
| G2b | testssl/sslscan into per-service TLS findings | M | 4 | Mostly bulk low-severity copy. Keep the self-signed/untrusted cert on LDAPS/RDP/WinRM as the one chaining tag |
| I44 | Discovery-first: `host.alive` tri-state, `-sn`, masscan and `-oG` ingest, out-of-band `-p- -sV` ingests clear `scan_needed`, split "alive / unanswered / unseen" counts | M | 5 | Today a `-sn` XML falsely records top-1000 coverage (`nmap.py:117`). A single ping miss is not "dead" on Windows networks |
| I45 | `domain_fact` table plus module-aware NetExec parsing (MAQ, LAPS, ldap-checker, trusts, rid-brute, kerberoasting/asreproast) and a kerberos parser. Hash kinds (krb5tgs, krb5asrep, ntp_hash) are never sprayed | L | 5 | The pass-pol row is what makes the sprayer guard engage. Extend the typed NetExec parser instead of sinking `ExtractedFinding`s |
| I47 | ProjectDiscovery JSONL and bbot NDJSON into domain and web_app rows | L | 4 | Needs typed scope first. Do not create host rows for CDN IPs, and never trigger spray hooks from domain-keyed ingests |
| I50 | nuclei JSONL as `vulnerability(state='potential')`, with promote-on-confirm mapping templates to existing consumer tags | M | 4 | Fix the dedupe key, which today collapses every non-CVE template on a host into one row. Credential templates' extracted results go to loot |
| I49 | Burp "Save items" XML, HAR and ZAP JSON for **metadata only**: methods, body parameter names, auth requirement, status. Bodies are stored only when bound to a finding | L | 4 | PortSwigger ships an official Burp MCP; yhwach must not become a second plaintext token store |
| I51 | BloodHound CE export (saved query or attack path) as typed edges, plus an owned-principal sync both ways. From SharpHound read only a bounded subset | L | 4 | Full ACE re-ingest duplicates BloodHound and gets SIDs wrong: today `bloodhound.py:226` writes SID-named principals |
| I31 | kubectl `auth can-i --list`, `get pods -A` (privileged, hostPID, hostPath) and `get secrets -A` counted only, plus `aws sts get-caller-identity` | M | 4 | Drop the IAM/role-binding sniffers; those names are not permissions |
| I32 | trivy into software and vulnerability rows, plus Prowler, ScoutSuite and kube-bench FAILs filtered through an allowlist of attack-relevant checks mapped to chaining tags | L | 3 | Drop the CIS/PCI/NIST matrices. Prowler already ships the compliance deliverable |
| I59 | mcp-scan output with consumer rules; garak and promptfoo results as coverage rows using the tools' own taxonomy tags | M | 3 | Never compute severity from fail rate. Drop PyRIT, which has no stable export |
| I34 | CI/CD: ingest zizmor, poutine and gato-x output into `gha_*` tags, plus a `cicd` ref pack and rules | L | 4 | Do not hand-roll a GitHub Actions analyzer |
| I66 | Bulk `add_findings`/`add_creds`, and conn-level helpers shared by CLI and MCP so the two stop disagreeing | M | 4 | The spray default comes from the engagement mode, never "True to preserve behaviour" |

### Theme D. The advisor wire and recall

This is the moat delivered at the wire: the model gets something runnable, records what it tried, and can ask questions instead of re-reading a brief.

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I65 | `data/actions.yaml` for the 249 emitted action ids: command template, needs, risk, `parses_as`, ref, with `manual: true` for the rest. Candidates gain actions, ref, why-now, unlocks, lessons and tried. Adds `yhwach_action(id, host)` | L | 5 | Render secrets as `$YH_SECRET_<id>` env references, never values. A `then:` hint may only point at read or record verbs, never scan or spray |
| I19 | `yhwach_attempt(rule or free-text technique, host, result, reason, detected?)`. `next` hides burned pairs, and the report's dead-ends section fills in advisor mode | M | 4 | Fail and blocked results are sticky; no 24-hour resurrection. Accept off-catalog techniques |
| I63 | `yhwach_query(view, where, q, fields, order)` over code-defined views with allowlisted operators and parameterised SQL. Every row carries an id | M | 5 | Scope service, surface and web_path through a host join. Mask evidence like creds. Add canned anti-join views ("445 open, no share listing") |
| I62 | JSON envelope plus `fmt`, `limit`, `offset`, `max_chars` on list tools; ids on every row; a truncation footer that prints the exact follow-up call | L | 4 | Drop opaque cursors. Paging must be a real tool parameter, not signature injection |
| I06 | Brief governor (per-section caps, placeholders hidden behind a "+N not shown" line, a size test on a synthetic /22), `yhwach_engagements`, optional `lab` with an echoed resolution order, and `yhwach_resume` | L | 4 | The brief governor is a bug fix; ship it first. "Since" must read row timestamps because spray, scan and probe write no events |
| I61 | Generated `args:` and `example:` lines on every tool description from one vocabulary table. Warn that `yhwach_tag` does not unlock rules. Add `yhwach_schema` | S | 3 | Today FastMCP only receives the short spec string, so the rich docstrings never reach the model |
| I23 | Web chaining tags from content discovery (`idor_candidate`, `graphql`, `api_spec`, `debug_page`, `redirect_param`) with consumer rules; keyword "findings" demoted to info LEADs | M | 4 | Kept as proposed by both reviewers |
| I43 | Missing network service kinds: SNMP, NFS/rpcbind, SMTP/IMAP/POP3, DNS, IPMI, VNC, telnet, MSRPC, printers, ESXi. UDP-aware classification and read-only triage rules with extractors and fixtures | M | 5 | Open-relay tests, printer default logins and NFS mounts are gated, not read-only. Fix the protocol-blind classifier and the `probe_run` key first |
| I33 | Entra/hybrid producers: MSOL_/Sync_ accounts, the ADSync service, ADFS SPNs, AZUREADSSOACC$. Report-class rules plus exploit-class rules gated behind `cloud_tenant_in_scope` | M | 5 | Device-code and consent phishing are red-team social engineering; keep them out of pentest recall |
| I46 | Path honesty: ownership only from validated access, `credential.kind='guess'`, `yhwach_own`, a Tier-0 pack, objective kinds `crown_jewel`/`segment`/`principal`, and edges yhwach uniquely knows (validated access, credential reuse, dual-homing) | L | 5 | Do not re-derive BloodHound ACL edges. Needs a migration note for existing lab DBs |
| G2e | `SameHash`, `LocalAdminReuse` and `CredValidOn` edges from dump rows and validated access, so pathfind sees the most common real lateral path | S | 4 | Write a star rather than a clique for large clusters |
| I40 | Slice 1 only: derived edges from validated access and tunnels so pathfind starts from real footholds. Slice 2 is a minimal operator-asserted session row | L | 4 | A hand-maintained copy of C2 session state goes stale within the hour |
| I38 | Sensor inventory (EDR, AV, Sysmon, forwarders) from `tasklist /svc`, `Get-MpComputerStatus`, Seatbelt and nxc `enum_av`, with tri-state per host and `sensor_present`/`sensor_absent` when-keys. Pivot render refuses on EDR or unknown hosts | L | 5 | Red teamers do not run winPEAS on suspected EDR hosts. `sensor_absent` matches only "collected: none" |
| I37 | Required `noise: quiet, moderate or loud` on every rule; optional telemetry and artifacts; a `max_noise` filter that never sorts | M | 4 | A wrong "quiet" label is worse than none. Artifacts flow into the cleanup ledger (I39) |
| I57 / I58 / I25 / I27 | AI_KINDS from the service matrix with `openai_compat` included; the openapi surface wired to a web rule and an AI rule; cookbook topics joined to dossiers by surface kind; the `k8s-enum` ref pack plus a test that every matrix `ref_pack` exists; cloud rules retagged off LLM06 onto ATT&CK Cloud and Containers | S each | 3-4 | The OpenAPI row carries no LLM id, or every REST API becomes an "AI surface" |

### Theme E. Coverage and methodology beyond port scans

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I35 | Methodology checklists as per-asset coverage gaps: AD first, then WSTG and cloud. PRESENT, CHECKED or UNKNOWN, never operator-typed | L | 4 | First add a negative-evidence primitive: a `host_fact` row written by NetExec banners and `ldap-checker`, spooler, MAQ and LAPS modules. Otherwise every item sits at UNKNOWN forever |
| I52 | `ai_tool` and `ai_data_source` rows keyed on the existing surface: sink from a lexicon that the operator can override, `desc_sha` with first/last seen for rug-pull detection, and `tool_sink`/`source_writable` when-keys | XL, M slice 1 | 5 | Hostname-only apps wait for the asset model. No `allowed_hosts` stopgap |
| I54 | Indirect-injection plant tracker: plants, sightings and a cleanup checklist in the report | L | 4 | Canary format must be neutral and configurable, with no `YHW-` prefix fingerprinting the tool in client data |
| I53 | `yhwach_payload`: a payload, response and verdict ledger running the existing injection extractors, with an operator verdict override, per-engagement canaries and a batch path | M | 4 | A regex refusal heuristic must never become the fact of record |
| I55 | MCP probe v2: https and http, `/sse`, initialize then tools, resources and prompts, transport/auth/Origin meta, and an `mcp` checklist pack | M | 4 | Store the previous tool list and emit drift as an event with a diff; promote to a finding only after review |
| I24 | Role-by-endpoint authorization matrix from captured traffic: fingerprinted sessions, `{id}` templating, unobserved cells marked distinctly from denied | L | 4 | Identify sessions by cookie/header name plus value hash or a JWT `sub`, never a hash of the whole header. Keep an explicit "unassigned" bucket |

### Theme F. Findings, evidence and the deliverable

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I07 | Report-grade finding: CVSS vector and score, CWE, description, impact, remediation, references, retest status, `curated` flag, author, and a `yhwach_finding_set` lifecycle verb. One `LIVE_FINDING_STATUSES` constant used everywhere | L | 5 | **Keep per-instance rows** because recall chains per host. Add a `group_key` and roll up "12 hosts, 1 finding" only in report and export |
| I08 | Offline CVSS 3.1 calculator with `band()`; `info` as a fifth band; fix `vulns.py` to use the band and `state='potential'` | M | 5 | Defer v4.0, which needs the 270-row MacroVector table. On a band mismatch, warn and require a rationale in QA; do not refuse the call |
| I10 | `evidence` plus `evidence_link`: sha256, captured_at, captured_by, `contains_secret`. Refuse missing or empty files. Parse `yhwach-shot.sh` output | M | 5 | One artefact can back several findings. Excerpts are capped and redacted when they contain secrets |
| I13 | `yhwach report --check` with exit code 1: no evidence, no PoC, `$VAR`/TODO in steps, secrets in evidence, and later missing CVSS or remediation | S | 5 | Phase it on today's columns first |
| I14 | An executive-summary inputs block: severity counts including info, reached versus tested, highest privilege, credential counts without secrets, standards exercised | S | 4 | Keep the points scoreboard only when `points_target` is set |
| I12 | PoC steps keyed by finding; fence-safe regeneration that preserves prose; one submission template for bounty and client write-ups, redacted by default | M | 4 | Defer the seven-section chain-note profile work |
| I09 | Writeup pack keyed tag-first, then class, with an operator overlay directory so firm text wins | L | 4 | Templates never set CVSS or severity |
| I17 | `yhwach findings --json` with stable ids first, then one DefectDojo Generic Findings renderer | M | 4 | SARIF and three CSV dialects are premature until I07 lands |
| I18 | Retest: import a baseline with its affected assets; outcomes fixed, still open, regressed or not tested require evidence; report sections for retest results, new since baseline and not retested | L | 4 | Same-DB parent links are simpler than file import for the common case |
| I41 | ATT&CK tactics pack, `audit --attack`, Navigator layer export | L | 4 | States are EXECUTED, PROVEN, DETECTED or NOT_ATTEMPTED. Advisor PLANNED states never reach a client export |
| G2d | Password-audit appendix (see theme C) | M | 5 | |
| G4a | Typed `notice` ledger: critical notifications, status updates, stop, pause, resume, detection, scope changes. A report communications log, and a QA rule that a critical finding without a notification is blocking | M | 5 | The practitioner reviewer's favourite: today this lives in email threads |
| G4b | `yhwach status-note`: a redacted daily-update draft from the since-window | M | 4 | It is a draft the human rewrites |
| I05 | Actor on every event, an activity ledger for every sprayer attempt including blocked and cached ones, argv redacted by known flag patterns, and a model-side `yhwach_log` for commands the model ran itself | M | 4 | yhwach only sees traffic it originates. Label the ledger as partial, or it gives a SOC false assurance |
| I39 | Artifact cleanup ledger: pivot renders insert `state='rendered'` and the operator confirms the drop; outstanding items block "done" | M | 4 | The Kali-side listener is not a client artefact |
| I20 | Bounty program memory: a thin submission table and an advisory duplicate-risk line at two granularities (same endpoint and parameter; program-level class noise) | M | 4 | Never changes status, never sorts recall |

### Theme G. Data handling

| ID | Build | Effort | Value | Key correction |
|---|---|---|---|---|
| I15 | 0600 DB and 0700 directories, a doctor warning, a vault-derived masker on report, poc, dossier, brief and status, and a complete `--redact` on the board | L | 5 | `yhwach_creds` stays the clear-text verb, since the model needs the secret. A purge must checkpoint the WAL and VACUUM, or the "destruction" certificate is false |
| G5a | umask 077, harden DB plus WAL and SHM, and move secrets out of nxc and curl argv into 0600 temp files **(unverified)** | M | 4 | Today `ps` shows every sprayed password |
| G5b | Optional vault key (`[vault]` extra with Fernet, key file or OS keyring) and a `secret_fp` column so dedupe works without decrypting **(unverified)** | L | 4 | |
| G5c | Sensitivity classification at write time and a per-engagement data policy; bounty mode minimises PII by default **(unverified)** | L | 4 | |
| G5e | A wire-leak canary test that seeds markers in every secret-bearing column and calls every TOOL_SPECS verb through the server wrapper **(unverified)** | S | 4 | The data-handling counterpart of the tag-graph test |
| I16 | CLI-only `yhwach close --out <dir>`: bundle, verify hashes, set `closed_at`, refuse further writes, and print a checklist of every place secrets still live | M | 4 | No MCP close tool. In-DB scrubbing is false comfort; firms destroy the encrypted volume |
| G5f | `docs/data-handling.md`: every store, who can read it, when it is removed, and a paragraph to paste into a DPA answer **(unverified)** | S | 3 | |

### Theme H. Team memory

The gap round produced a delta export and merge design (G1a-G1e). **The practitioner reviewer's correction is the better first step: run one shared instance.** `yhwach mcp` is stdio, so each tester's Claude Code can register `ssh jumpbox env YHWACH_HOME=/opt/yh yhwach mcp`. That gives 2-3 testers one WAL database with zero new code. Ship `yhwach doctor` detection of a DB on cifs, nfs or fuse, because WAL over a network filesystem corrupts. Revisit delta and merge (G1a-G1d) only if teams genuinely work offline from each other, and never push clear-text credentials to git (G1e's Stop hook).

### Theme I. Public release and the first hour

| ID | Build | Effort | Value |
|---|---|---|---|
| I67 | Move AGENT.md, ROADMAP.md, agent-mode.md, lab.md, contract.md, ui-panel-spec.json and mockups under `docs/experimental/`. Rewrite ARCHITECTURE.md as the advisor picture. Regenerate `cli/README.md`. Add `tests/test_docs_commands.py` asserting every command and tool named in docs exists. Delete the setup step that installs exam doctrine as the global CLAUDE.md. Add SECURITY.md and CHANGELOG.md | M | 4 |
| G6a | `yhwach doctor` as the advisor preflight: tools on PATH with what each enables, the DB resolution chain, MCP registration for both CLIs, network-filesystem check, traffic state. No API-key line **(unverified)** | M | 4 |
| G6b | `yhwach init --kind K`: prints or writes the MCP registration with absolute paths and a per-kind CLAUDE.md/AGENTS.md fragment | M | 4 |
| G6c / G6d | `yhwach demo --kind X` from five synthetic real-shaped seeds (internal AD with 400 hosts and a provided account, external perimeter, bounty wildcard with thousands of subdomains, a single web app, an AI/RAG agent), and a real-shape CI suite: brief size budget, no "points" outside labs, pathfind from a provided account, and a no-network fixture proving disarmed mode sends nothing **(unverified)** | L / M | 4 |
| G6e | One-screen quickstarts per kind built from the demo's real output **(unverified)** | M | 4 |
| G6f | A README "what sends traffic and when" table, disarmed by default outside labs, pipx/uv install, a wheel without the persona, legacy runtime, fixtures and the ActiveMQ exploit script, and a relaxed `mcp` pin **(unverified)** | M | 4 |

The critic also flagged what no idea addressed: **remove the legacy runtime before a public "no key" release.** Move `ActionClass` into a small `tiers.py`, give `/report` a synthesis that does not import `judge`, expose the `interpret` extractors through I64, then delete brain, judge, orchestrator, workers, providers, control and runners with their 169 tests. Install the `ui` extra in CI so the 110 board tests stop being skipped.

---

## 6. Recommended build order

### Prerequisites nobody listed

The ideas propose about 18 new tables and 40 columns, all through the hand-mirrored `_ADDED_COLUMNS`/`_ADDED_TABLES`, which already drift from `schema.sql` (`tunnel.engagement_id`). Before the big schema work:

1. **Numbered migrations** with `PRAGMA user_version` and a test that a fresh `init()` equals a migrated DB. Nullable `host_id` on `web_app` and `vulnerability` needs a table rebuild, which the add-only migrator cannot do.
2. **One engagement-profile spec** (theme B) so five ideas stop inventing five `kind` enums.

### Phases

| Phase | Goal | Items |
|---|---|---|
| 0. Safety bugs | Nothing yhwach does can hurt a client | S1-S5, S8-S10 as one PR (I01 core, I26 slice 1, I28's link-local fix), I60 |
| 1. Safe by default | Record-only outside labs, scope enforced everywhere | Migrations, engagement profile, I02 core, I03, I04, G3b provenance, I15 slice 1 (0600 and masking), G5a argv |
| 2. The wire | The model gets runnable moves and can record what it tried | I64, I19, I65, I63, I62, I06 governor, I61 |
| 3. The deliverable | A finding that can reach a client | I07, I08, I10, I13, I14, I12, G4a notice ledger, I17 JSON |
| 4. Ingestion by kind | One engagement kind at a time | Internal AD: I44, I45, G2a, G2c, G2d, G2e, I43, I46. Then web and bounty: I29, G3c, I47, I50, I23, I49, I48, I20. Then cloud: I31, I32, I33, I34 |
| 5. Big bets | The "nobody has this" layer | See section 7 |
| Alongside | Public release | I67, G6a, G6b, G6f, legacy-runtime removal, CI `ui` extra |

### The first ten items

1. Sprayer and parser safety fixes (I01 core plus S4, S8, S9, S10).
2. Typed `ToolError` with `out_of_scope` (I60).
3. Numbered migrations with a schema-parity test.
4. The engagement-profile spec and `active_mode` record-only gate with CLI-only arming (I02 core).
5. `scope_entry` plus `assert_target` on every traffic path (I03).
6. Credential provenance and no-adapter cloud and token kinds (G3b, I26 slice 1).
7. Brief governor plus `yhwach_engagements` (I06 slice A).
8. `yhwach_attempt` (I19).
9. `yhwach_interpret` as the single text entry point (I64).
10. Finding lifecycle verb with per-instance rows and `group_key` (I07 core).

---

## 7. Big bets: where yhwach can be one of a kind

Each of these strengthens a moat item and has no equivalent in Burp, BloodHound, Ghostwriter or the autonomous agents.

- **The closed advisor loop** (I65 + I64 + I19). `next` hands over a runnable command with env-referenced secrets. The output is pasted back through `interpret`. The response says which rules just lit up. The attempt is recorded so the move never comes back. No key, no autonomy, and the model never invents a command.
- **The AI-surface assessment memory** (I52 + I54 + I55 + I53). MCP tools and data sources become typed rows with sinks and writability, plus a plant tracker with a cleanup checklist and an MCP-server checklist. It treats an MCP server's tool list the way nmap treats ports. No pentest platform has an AI asset type.
- **The AD check-every-path matrix with negative evidence** (I35 + `host_fact`). Per DC, per host and per domain, items are PRESENT, CHECKED or UNKNOWN, from typed facts, with the rule that closes each gap. This replaces the sign-off spreadsheet every internal team keeps.
- **The credential-reuse attack graph** (G2c + G2e + I46). Dumps and potfiles become reuse and local-admin-reuse edges, and ownership only comes from validated access. Pathfind answers "from the provided account, how far is Tier-0?" honestly.
- **Role-by-endpoint authorization memory** (I24). It remembers, across months of a bounty program, which endpoint was only ever seen as one user, and hands the model the exact request to replay. Autorize forgets everything between sessions.
- **The impact taxonomy plus approval ledger** (G4d + G4e). Recall says "this move adds a machine account", the gate requires a time-bounded approval naming rule and host, and the report lists every modifying action with its approval.

---

## 8. What not to build

| Idea | Why not |
|---|---|
| I11 proof ledger with dependency fingerprints and a signed bundle | Dropped by both reviewers. Daily rescans flip every finding to STALE, and no client verifies a sha256 manifest. Keep only "finding references a service the latest scan no longer shows" as a QA row |
| I30 full hybrid graph from a 40-row action-to-edge table | PMapper, Cartography, KubeHound and BloodHound CE OpenGraph exist. Policy-derived edges without Deny, SCP or boundary evaluation would make every `iam:PassRole` user a theoretical admin. Keep only confirmed trust bridges (AWS trust policies, IRSA annotations, OIDC subject wildcards) and `CROWN_BY_REALM` |
| CIS, PCI and NIST compliance matrices (I32) | Prowler and ScoutSuite ship them, and 800 posture FAILs do not change the next move |
| Full SharpHound ACE and session re-ingest (I51) | Duplicates BloodHound, gets SIDs wrong, and stores hour-old sessions as permanent edges |
| Fixture capture over MCP from client engagements (I36b) | A denylist scrubber eventually misses something, and the failure mode is client data in a public repo. Keep lessons over the wire and gap reports. Fixture capture is maintainer-only on engagements flagged synthetic |
| Mid-engagement data minimisation (G5d) | The tokenised body on day 30 is what the client disputes on day 45. Retention applies at close, workspace-wide |
| A hand-rolled GitHub Actions analyzer (I34) | Ingest zizmor, poutine and gato-x instead |
| Session uptime and listener tracking (I40 slice 2 extras) | C2 frameworks already hold this, and a copy goes stale within the hour |
| A 15-key `opsec_json` with timing presets (I21) | Testers run nmap themselves. Keep headers, proxy, delay, write-probe policy and one passthrough string |
| Persona prose files as a safety mechanism (I42) | Doctrine is advisory. Put enforceable rules in the gate and the rest in the `init` fragment |
| Qualys and Nexpose CSV parsers (G2a) | Client VM-team artefacts with template-dependent headers |
| Delta export and merge before a shared instance (G1) | One shared instance over ssh stdio solves 2-3 testers with zero code |
| `git push` of clear-text deltas from a Stop hook (G1e) | A data-handling violation at nearly every firm |

---

## 9. Open decisions for the maintainer

1. **Default traffic posture.** Record-only for every kind except lab, with arming a human CLI act and never an MCP argument? This changes the documented "a cred is not stored until tried" doctrine in AGENT.md.
2. **Unknown lockout policy.** Hard block on domain-auth protocols until a policy row exists, or a small cap such as 2 attempts per account per 30 minutes?
3. **The scope contract.** Hostnames, domains and wildcards become in-scope tokens, reversing `tests/test_scope.py:28-29`, and an empty scope refuses all traffic. Agreed?
4. **Finding granularity.** Per-instance rows with a report-time roll-up by `group_key`, as both reviewers recommend, rather than collapsing hosts into one row?
5. **Schema migration policy.** Introduce `PRAGMA user_version` and allow table rebuilds, which nullable `host_id` requires?
6. **Active tools in the public release.** Keep the scanner, sprayer and probes as armed-only features, or ship the public rebuild as record-only and let the operator's own tools generate all traffic?
7. **Legacy runtime.** Delete it before the public release, after re-exposing the extractors through `interpret`?
8. **Multi-tester.** Document the shared-instance pattern and defer merge?
9. **Secrets in views.** Which read views mask by default, and should vault encryption be an optional extra?
10. **One engagement kind enum.** Confirm the list: lab, internal, external, web, cloud, redteam, bounty, retest.

---

## 10. Decisions locked (2026-10-12)

The maintainer reviewed sections 5-9 and set scope. This supersedes the "in/out" hints above where they differ.

**Security posture.** yhwach is hosted locally; credentials stay visible (no masking, no encryption, no redaction). The one hard rule: the board must never bind all interfaces. Everything else in Theme G is dropped except cheap, non-secret file hygiene.

**Theme decisions.**

| Theme | Decision |
|---|---|
| A. Safe on a client network | In, in full |
| B. Engagement and asset model | In, in full |
| C. Ingestion | In, in full |
| D. Advisor wire and recall | In, in full |
| E. Coverage and methodology | In, in full |
| F. Findings, evidence, deliverable | Report generation is OUT. yhwach keeps the *memory* an operator pulls from: finding status lifecycle, per-instance rows, evidence bound to a finding, PoC steps, and the notice/activity/artifact/submission ledgers. It does NOT compute CVSS, draft write-ups, or render client reports. So OUT: I08 (CVSS), I09 (writeup pack), I14 (exec summary), I17 (exports), I18 report sections, I41 (Navigator export), G2d (password-audit appendix as a report), G4b (status-note), I16 report bundle. The operator structures the report himself from PoCs and creds. |
| G. Data handling | Secret-masking/encryption dropped (secrets shown is fine). Keep only: the board 0.0.0.0 refusal and cheap 0600 file perms. |
| H. Team memory | Not now. Deferred. |
| I. Public release | In |

**Open decisions (as answered).**
1. Traffic posture: record-only by default outside labs; arming is a human CLI act, never an MCP argument.
2. Unknown lockout policy: does not matter, handled manually. Keep the fix minimal (fix the parser; no hard cap).
3. Scope contract: agreed. Hostnames/domains/wildcards become in-scope tokens; empty scope refuses traffic.
4. Finding granularity: per-instance rows with a report-time roll-up key.
5. Schema migration: PRAGMA user_version and table rebuilds, agreed.
6. Active tools in the public release: kept as armed-only features.
7. Legacy runtime: delete it before the public release, after re-exposing the extractors.
8. Multi-tester: deferred (Theme H).
9. Secrets in views: shown in the clear.
10. Engagement kinds: lab, ctf, internal, external, web, cloud, redteam, bounty, retest.

## 11. Phase 0 status — DONE (branch `feat/phase0-safety`, uncommitted)

All ten verified safety bugs fixed, plus the board bind guard. Ruff clean. Full suite: 893 passed, 4 pre-existing Windows path failures (pass on Linux CI), +7 new tests.

| Bug | Fix |
|---|---|
| S1 lockout parser read 10/20/30/100 as "no lockout" | `_lockout_int` anchors the disabled-lockout match; a threshold is parsed as itself |
| S3 NTLM sprayed as `-p` | `_nxc` sends `-H` for `kind='ntlm'`; ntlm reach tightened to smb/winrm/mssql |
| S4 api_key/token sprayed as Bearer to every web root | `PROTOCOL_MATCHERS` sets api_key/token to no protocols; http-basic now needs a 401/403 baseline before a 200 counts |
| S5 'http' matched WinRM | dropped from WinRM products; WinRM is port-identified |
| S6 autospray had no off switch | `YHWACH_AUTOSPRAY=0` stopgap on both record hooks (the per-engagement record-only default is Phase 1) |
| S7 no scope check on traffic paths | `_assert_in_scope` on scan/enum/probe; sprayer candidate selection filtered to in-scope hosts (enforced only when a scope is set; empty-scope-refuses is Phase 1) |
| S8 HexStrike shell injection + weak loopback check | target validated and `shlex.quote`d, ports validated; `is_loopback` parses the host |
| S9 re-added secret never tried | changing a credential's secret clears its cached `fail` rows |
| S10 link-local materialised as a scan target | `_valid_ipv4` rejects link-local and loopback |
| board bind | `yhwach ui` refuses `0.0.0.0`/`::`, warns on any non-loopback bind |

## 12. Phase 1 status — DONE (branch `feat/phase0-safety`, uncommitted)

The foundation the rest builds on. Ruff clean. Full suite: 907 passed, 4 pre-existing Windows path failures, +14 new tests.

| Item | What landed |
|---|---|
| Versioned migrations | `SCHEMA_VERSION=3` stamped into `PRAGMA user_version`; a schema-parity test asserts a fresh `init()` DB has every column/table the self-heal migration would add |
| Engagement profile | `engagement.kind` (lab/ctf/internal/external/web/cloud/redteam/bounty/retest), `client`, `active_mode`, `status`, `ended_at`; one enum, wired through `upsert_engagement`, `tool_engage`, and `yhwach engage --kind/--client` |
| Record-only default | Non-lab/ctf engagements start `record_only`: autospray hooks skip, and scan/enum/probe/spray refuse with "run `yhwach arm`". Arming is a terminal act (`yhwach arm`/`yhwach disarm`), never an MCP argument — the model can ask the human to arm but cannot arm itself. Replaces the `YHWACH_AUTOSPRAY` env stopgap (kept as a hard override) |
| Typed scope | `scope_entry` table (ip/cidr/hostname/`*.wildcard`, include/exclude, exclude wins); `scope.assert_target` gates every traffic path; empty scope refuses traffic; `engagement.scope` kept as a derived mirror and used as a fallback so older DBs still gate. `yhwach scope list/add/exclude/remove/check` + `yhwach_scope`. Hostnames and wildcards are now valid scope (reverses the old CIDR-only contract) |
| Credential provenance | `credential.provenance` (provided/discovered/derived/guess); a `provided` (client-issued) cred is never sprayed and never counted as a compromise; `tool_add_cred(provided=True)`; provenance is never downgraded on re-record |

**Next — Phase 2 (the advisor wire):** `yhwach_interpret` single text entry point, `yhwach_attempt` negative ledger, actionable recall (`data/actions.yaml` + command/ref/unlock/why-now on candidates), `yhwach_query` read views, the brief governor. Then Phase 3 (finding lifecycle + evidence binding + per-instance rows — memory only, no report generation) and Phase 4 (ingestion per engagement kind).

## 13. Phase 2 status — DONE (branch `feat/phase0-safety`, uncommitted)

The advisor wire. Ruff clean. Full suite: 918 passed, same 4 pre-existing Windows failures, +21 new tests across Phase 1+2.

| Item | What landed |
|---|---|
| Brief governor (I06) | `build_brief(limit=60, stage=…)`; REACH/HOLD/SURFACES capped with an honest "+N more / N undiscovered placeholders — ask for the slice" footer, so a /24 of placeholders can't bury the map. `yhwach brief --limit/--stage` + MCP params |
| Attempt ledger (I19) | `yhwach_attempt(rule, result, reason, host, technique)` + `yhwach attempt`; `next` retires fail/blocked (rule,host) pairs from recall (sticky, per-host, no time-resurrection) and renders a DEAD ENDS block; success un-burns. Off-catalog moves via free-text technique. No ordering/score introduced |
| Query views (I63) | `yhwach/views.py`: 16 code-defined read views (hosts, services, surfaces, findings, creds, principals, shares, loot, objectives, attempts, events, software, vulns, web_paths, scan_coverage, probe_runs) with an allowlisted operator grammar (`=,!=,>=,<=,>,<,like,in,is_null`), parameterised SQL only, per-engagement scoping, and secret masking unless `reveal`. `yhwach_query` + `yhwach query <view> --where col=val -q text` |
| Interpret entry point (I64) | `yhwach/sniff.py` + `yhwach_interpret(text, kind=auto, host, url, dry_run)` + `yhwach interpret <file>`: sniffs nmap/netexec/bloodhound/certipy/linpeas/winpeas/web and ingests from pasted text (reusing the tested ingest path), runs any interpret extractor by `kind='x:<id>'` (the ~70 extractors are now reachable over MCP), falls back to loot+INFO for the unrecognised, and reports which recall rules the new facts UNLOCKED. `dry_run` classifies without writing |

A multi-agent adversarial review of the whole Phase 0-2 diff was run after implementation; confirmed findings were triaged and fixed.

**Remaining Phase 2 piece (deferred):** actionable recall (I65) — `data/actions.yaml` carrying the command template, ref pointer, what-it-unlocks and why-now for the ~249 emitted action ids, surfaced on each `next` candidate. It is a large data-authoring task (good fit for a parallel workflow) and is best done as its own pass.

**Then Phase 3 (memory only, no report generation per decision F):** finding status lifecycle verb + per-instance rows + `group_key` roll-up + an evidence table binding screenshots/request-response to a finding + the notice/activity/artifact/submission ledgers.

### Phase 0-2 adversarial review — 13 confirmed findings fixed

A 5-dimension review workflow (gate-bypass, query-SQL, scope-matcher, recall-ledger, interpret/migration), each finding then adversarially verified, produced 13 confirmed defects. All were fixed; one (a "masked value filter oracle") was correctly dropped since secrets are shown by decision. One declined: a model obtaining an armed engagement over MCP by passing `kind=lab` — kept, because lab/ctf armed-by-default is the intended posture and non-lab kinds are record_only regardless.

Fixed: scan queue-drain scope bypass (gated in `scanner.pending_hosts`); sprayer + probe-sweep scope filter switched from the include-only string mirror to the typed `assert_target` (so exclude rows win and hostname/wildcard scopes don't degrade to allow-all); `tool_spray` host now scope-checked; wildcard `*.example.com` no longer matches the apex; legacy-string fallback hardened so removing the last include or adding a lone exclude can't resurrect a stale scope (plus `_seed_legacy_includes` on first typed entry); secret mask no longer leaks a prefix or length; `yhwach_interpret` rejects an unknown `x:<id>` instead of silently dropping the paste; the schema-parity test now reads a raw schema.sql DB (and caught a real pre-existing drift — `credential.principal_id` was missing from schema.sql, now added); `is_null` coerces string booleans; the REACH placeholder count no longer dumps placeholders or overstates the hidden count; the `scope_entry` index is created by the migration too.

## 14. Phase 3 status — DONE (branch `feat/phase0-safety`, uncommitted)

The memory an operator pulls from — finding lifecycle and evidence binding, no report generation (decision F). Ruff clean. Full suite: 927 passed, same 4 pre-existing Windows failures, +7 new tests.

| Item | What landed |
|---|---|
| Finding lifecycle | `db.set_finding` + `yhwach_finding_set` + `yhwach finding-set`: change status (open/confirmed/exploited live; false_positive/duplicate/remediated/dead closed), severity or evidence. Closing drops a finding from recall/brief/the open register but keeps it queryable — never deletes. `db.LIVE_FINDING_STATUSES` is the one definition of "live"; all 21 `status='open'` finding queries now read `status IN ('open','confirmed','exploited')` |
| Per-instance + freeze | `add_finding` dedupe key gains `location` (same class+title on N endpoints = N rows), a `group_key` for register roll-up, and a `curated` flag so an operator edit is frozen against parser re-ingest. `tool_add_finding(location=)` |
| Evidence binding | `evidence` + `evidence_link` tables; `db.add_evidence` (file path hashed and refused if missing/empty, or pasted text stored under the workspace; deduped by sha256; one artefact backs many findings); `yhwach_add_evidence` + `yhwach evidence`; an `evidence` query view. The DB keeps a sha256 and the link so "does finding #N have proof?" is answerable; the bytes stay on disk |

A focused adversarial review found 6 confirmed defects, all fixed: unvalidated severity on the finding-set wire; evidence-link re-bind not idempotent for a finding-only bind (SQLite NULL-distinct UNIQUE, now a NULL-safe guarded insert); the brief LESSONS collector and two dossier queries not gated to live findings (a closed finding still drove recall); group_key going stale when an untagged finding is later re-detected with a tag; and a dead `if False` in the finding-set return message.

**Deferred to a later pass:** the four engagement-memory ledgers (notice/client-comms, activity/traffic, artifact/cleanup, bounty submission) and I65 actionable recall. Then Phase 4 (ingestion per engagement kind: Nessus, secretsdump/potfile, httpx/nuclei/subfinder, Burp/HAR, kubectl).
