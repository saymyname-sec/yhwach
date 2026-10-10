# Design: the UI as an information surface (8 tabs)

**Status:** implemented
**Scope:** `yhwach/ui.py` (routes, panels, CSS), one new pure-read module `yhwach/dossier.py`, one
new table `host_annotation`, two new MCP tools, and a small set of *writer* changes that gate
specific panels. No change to the orchestrator, the judge, policy, the brain, or the playbook
matcher. The board stays **read-only**.
**Goal:** put what yhwach already knows on a screen. The board queries 13 of the 32 schema tables;
web apps, discovered paths, software versions, CVEs, AD principals, privileges, shares, the
password policy and loot have no renderer anywhere, and `surface.meta_json` — the richest column
in the schema — has zero production readers. This is a wiring and decoding problem, not a new
intelligence problem.

---

## 0. Two rules this design is built on

**It informs; it does not recommend.** The operator forms their own enumeration ideas. Every panel
here is an inventory, a coverage fact, or a quote from a shipped knowledge pack. No panel ranks
techniques, scores moves, or orders work. The one existing panel that reads as a recommender —
"Next moves — the recall menu", first and largest on the board — keeps its (honestly unranked)
content and is renamed to what it is: an **applicability inventory**, which techniques are even
possible against each surface and at what risk tier.

**It stays read-only.** No approval inbox, no kill switch, no write path from a page. A hostile or
crashed UI must not be able to corrupt a run. Generated prose (§6) arrives through MCP and lands in
a typed row; the board only ever SELECTs it.

---

## 1. The nav

Five destinations become eight. Three are new; five are reworked so each earns its place instead of
duplicating the Board.

| Tab | Route | State | The one question it answers |
|---|---|---|---|
| Board | `/` | rework | What is the state of the estate right now, and what changed? |
| Recon | `/recon` | **new** | Where have I not looked yet? |
| Surfaces | `/surfaces` | **new** | What is running, and what is known about each thing? |
| Identity | `/identity` | **new** | Who is in this domain, and is it safe to spray? |
| Map | `/map` | rework | What can I reach, through what, and what segment have I never touched? |
| Vault | `/vault` | rework | What do I hold, where does it actually work, and where did it fail? |
| PoC | `/poc` | rework | Can I prove what I captured, and is the proof intact on disk? |
| Report | `/report` | rework | What do I paste into the write-up, and what lacks evidence? |

Two of the current five are strictly *poorer* than the Board beside them: `/map`'s whole body is
`_network_map`, which the Board also renders in full (`ui.py:687` vs `ui.py:811`), and `/vault`
renders `_creds_vault` alone where the Board renders that plus the credential×service matrix plus
the spray feed (`ui.py:696` vs `ui.py:814-816`). The rework moves that content *off* the Board and
*onto* the tab that owns it, in both directions.

---

## 2. What is currently unrendered

Measured by seeding a nine-host engagement with realistic web, AD, software and share rows, serving
the board, and grepping all six routes for the data.

| Table | Rows in the demo | Renderer today |
|---|---|---|
| `web_app`, `web_path` | 6, 32 | none (only `notes.render_web_overview`, into the Obsidian vault) |
| `software`, `vulnerability` | 6, 3 | none on the board (`yhwach vulns` in the CLI) |
| `principal`, `membership`, `privilege` | 8, 3, 4 | none |
| `share` | 5 | none |
| `password_policy` | 1 | none — read only by `sprayer.py` |
| `loot` | 2 | none |
| `domain` | 2 | none |
| `surface.meta_json` | every surface | **zero production readers** (`fixtures.py:101` only) |

`yhwach/notes.py` already carries six markdown renderers with no board equivalent —
`render_web_overview`, `render_users_groups`, `render_vulnerabilities`, `render_services_software`,
`render_shares`, `render_host_note`. The Obsidian vault knows more about a host than the browser
does: `_host_detail` shows five sections (`ui.py:1849-1854`), `render_host_note` shows nine
(`notes.py:156-179`).

---

## 3. Shared mechanics

### 3.1 Markup helpers

The panels below assume three helpers extracted from the repeated idioms already in `ui.py`. They
are a prerequisite, not an optional cleanup — without them each new tab copies the same markup a
fourth time.

```python
def _panel(title: str, inner: str, *, note: str | None = None) -> str   # h2.sec + .card + footer
def _rows(headers: list[str], rows: list[list[str]], *, empty: str) -> str
def _stage_badge(stage: str) -> str      # folds the 8 `_STAGE.get(..., "#5b626d")` sites
def _hlink(ip: str) -> str               # `<a href="/host?ip=…">` — IP appears in 11 panels,
                                         # is clickable in exactly one today
```

### 3.2 Escaping

Scan data comes from hostile hosts. `_esc` is already applied with real discipline on string paths;
the new panels must keep that and additionally escape the six numeric interpolations that assume
SQLite INTEGER affinity (`ui.py:1578, 1775, 2143, 2496-2497, 2562`) — SQLite does not enforce it.
`meta_json` is attacker-influenced JSON: decode with `json.loads` in a `try/except`, escape every
key *and* value, and never interpolate a value into an attribute or a JS string.

### 3.3 Cost

`/panel` costs ~220 ms and 79 KB at nine hosts, 487 KB at sixty, every three seconds — and ~90% of
each render is `knowledge.load_techniques()` re-parsing the playbook YAMLs, called **twice** per
render because `_workers_panel` (`ui.py:1178`) does not pass the `techniques=` argument that exists
precisely to avoid it. The new tabs must not make this worse:

- `load_techniques` gets an mtime-keyed cache; the two board call sites pass `techniques=`.
- **None of the new tabs poll.** `/recon`, `/surfaces`, `/identity` are one-shot renders like
  `/host`, `/vault` and `/poc`. Only `/` and `/map` have a `poll_url`.
- Uncapped tables (`_hosts`, `_findings`, `_creds_vault`, the coverage table) get a 25-row cap and
  a `+N more` footer, following the pattern `_hosts` already uses at `ui.py:2025-2029`.

### 3.4 The figure/ground prerequisite

Panels cannot be judged on a page where panels have no edges. `--surface` sits at **1.04:1** against
`--bg` and `--line` at **1.21:1** against the card, so cards have neither a visible fill nor a
visible border and `th,td{border-bottom:1px solid var(--line)}` draws nothing. Section headings
render at 11.84px while the rows they label render at 13.76px — the heading is smaller than its own
content.

```css
:root{ --surface:#241d24; --surface2:#2f2630; --line:#5a3a53; --line-strong:#7a4a6d; }
.card,.path,.gazewrap,.netwrap,.hostwrap{border-color:var(--line-strong)}
h2.sec{font-size:.95rem;color:var(--ink)}
.card{overflow-x:auto;overflow-y:hidden}   /* 157px is clipped at 1340px today */
```

Measured: `--surface` 1.04 → 1.23:1, `--line` 1.21 → 1.70:1 on the new surface (the threshold where
a 1px hairline becomes visible), `--muted` still 4.91:1 so AA holds.

---

## 4. The tabs

Panel names are the function names to add to `ui.py`. Every query below was executed against a seeded nine-host engagement; the row counts are real. Full SQL for all 44 panels lives in `docs/ui-panel-spec.json`, and `docs/mockups/` regenerates the static pages from it.

### 4.1 Board — `/`

**Answers:** "What is the state of the estate right now, and what changed in the last three seconds?" — answered with inventory and counts, never with a ranked suggestion.

| Panel | Shows | Backing |
|---|---|---|
| `_topology_strip` | Replaces the full 12KB network map with a ~90px strip that answers only "where is the estate and how deep am I": one row per /24… | `.card` ui.py:176 · `.nethead` + `.nethead .meta` ui.py:269-271 ·… <br>*5, 1 row(s)* |
| `_applicability_panel` | Stops the Board announcing a recommender. Same data, three honest changes: the heading says what the table is (an inventory of… | `_RISK_COL` ui.py:965 · `_esc` ui.py:538 ·… <br>*— row(s)* |
| `_hosts` | The host inventory table, unchanged in content, capped at 25 rows with an exact "+N more" footer, and with the undiscovered… | The whole renderer body is unchanged except the two queries and the… <br>*1, 1 row(s)* |
| `_findings` | The open-findings table, unchanged in content and ordering, capped at 25 with an exact footer. Severity-ordered, so the cap can… | Renderer body unchanged apart from the query and the footer. `_SEV`… <br>*1, 1 row(s)* |
| `_vault_strip` | Collapses three vault panels (8,367 B) into a fixed 895 B two-line strip answering only "how many keys do I hold, how many are… | `.card` ui.py:176 · `.chip` ui.py:184 · `.mono` ui.py:189 · `.dl`… <br>*1, 3 row(s)* |
| `_coverage_panel` | Unchanged in content; capped at 25 host rows. This panel is the single most expensive row in the whole board (~1,300 B per host,… | Everything. `_cov_bar` ui.py:1077 · `_copy_cmd` ui.py:1065 ·… <br>*1 row(s)* |
| `_standards_inventory` | Sits immediately beside the OWASP-LLM matrix and does for every taxonomy family what that panel does for LLM01-10: names all… | `audit.findings_by_standard` audit.py:41 · `audit._ORDER`… <br>*5, 1 row(s)* |


### 4.2 Recon — `/recon`

**Answers:** Where have I not looked yet — which addresses, which ports, which ranges, with what flags, and when?

| Panel | Shows | Backing |
|---|---|---|
| `_recon_enum_matrix` | One row per materialised host, one column per enumeration dimension, so the operator sees in a single glance which hosts are… | `.matrix` / `.mxh` / `.mxr` / `.mx` / `.mx.ok` / `.mx.bad` /… <br>*9, 9, 1 row(s)* |
| `_recon_scope_ledger` | One row per CIDR in engagement.scope answering the address half of the question: how big is it, how much of it exists as a host… | yhwach/scope.py:10-14 (is_ip_or_cidr) and scope.py:17-26… <br>*1, 9 row(s)* |
| `_recon_scan_ledger` | Lists each scan_coverage row as a line of provenance — host, protocol, the port range exactly as nmap reported it, whether the… | _copy_cmd at yhwach/ui.py:1065-1075 for the argv cell. `.card` +… <br>*8, 2 row(s)* |
| `_recon_segments` | Address space the engagement discovered after scope was written — tunnel subnets and host interface segments — each flagged… | `.chip` CSS at yhwach/ui.py:184; the tunnel-subnet read pattern… <br>*1 row(s)* |
| `_recon_provenance` | Counts hosts by discovery_source so the operator can see which intake paths are feeding the world model and which are silent,… | `.card` + plain `<table>` + `<h2 class='sec'>` idiom from… <br>*1 row(s)* |

**`_recon_enum_matrix` — the query**

```sql
SELECT h.id, h.ip, h.hostname, h.stage,
       MAX(CASE WHEN c.proto='tcp' THEN c.full_range   ELSE 0 END)  AS tcp_full,
       MAX(CASE WHEN c.proto='tcp' THEN c.version_scan ELSE 0 END)  AS tcp_sv,
       COUNT(CASE WHEN c.proto='tcp' THEN 1 END)                    AS tcp_rows,
       COUNT(CASE WHEN c.proto='udp' THEN 1 END)                    AS udp_rows,
       MAX(CASE WHEN c.proto='udp' THEN c.port_count ELSE 0 END)    AS udp_ports,
       GROUP_CONCAT(CASE WHEN c.proto='tcp' THEN c.ports END, ' ')  AS tcp_ranges,
       GROUP_CONCAT(CASE WHEN c.proto='udp' THEN c.ports END, ' ')  AS udp_ranges,
       MAX(c.scanned_at)                                            AS last_scan,
       (SELECT COUNT(*) FROM service  s  WHERE s.host_id=h.id)      AS n_svc,
       (SELECT COUNT(*) FROM surface  u  WHERE u.host_id=h.id)      AS n_surf,
       (SELECT COUNT(*) FROM web_app  w  WHERE w.host_id=h.id)      AS n_app,
       (SELECT COUNT(*) FROM web_path p JOIN web_app w2 ON w2.id=p.web_app_id
          WHERE w2.host_id=h.id)                                    AS n_path,
       (SELECT COUNT(*) FROM share    sh WHERE sh.host_id=h.id)     AS n_share,
       (SELECT COUNT(*) FROM principal pr
          WHERE pr.engagement_id = h.engagement_id
            AND (pr.home_host_id = h.id
                 OR pr.domain IN (SELECT d.name FROM domain d
                                    WHERE d.host_id = h.id AND d.type='domain'))) AS n_princ,
       (SELECT COUNT(*) FROM credential_access ca WHERE ca.host_id=h.id) AS n_cred,
       (SELECT COUNT(*) FROM credential_access ca2 WHERE ca2.host_id=h.id
          AND ca2.result IN ('success','admin'))                    AS n_cred_ok
FROM host h
LEFT JOIN scan_coverage c ON c.host_id = h.id
WHERE h.engagement_id = ? AND h.stage <> 'undiscovered'
GROUP BY h.id
ORDER BY (tcp_full + tcp_sv + (udp_rows > 0)) ASC, h.ip ASC
```

Columns: host — `<th class='mxr'>`: `<b>` the IP, `<span class='mono'>` hostname + stage; the IP links to /host?ip=…; full-TCP — mark: `✓` when tcp_full=1 (a 1-65535 run exists); `~` when tcp_rows>0 but tcp_full=0 (scanned,…; -sV — mark: `✓` when tcp_sv=1 (some TCP run carried -sV/-A); `·` otherwise. Independent of full-TCP: a host…; UDP — mark: `✓` when udp_rows>0 AND udp_ports >= coverage.UDP_FLOOR (100); `~` when udp_rows>0 but shallower…; services — count n_svc, `·` when 0. title='N service row(s) on this host'; surfaces — count n_surf, `·` when 0. title= the comma list of surface kinds from Q2, each suffixed `owes…; web — `apps/paths` as `n_app/n_path` (e.g. `2/15`); `·` only when n_app=0 AND n_path=0; `1/0` is a real and…; shares — count n_share, `·` when 0; principals — count n_princ, `·` when 0. title='principals attributed to this host (local home_host_id, or a…; cred tries — n_cred, rendered `.mx ok` when n_cred_ok=n_cred, `.mx bad` when n_cred_ok=0 and n_cred>0,…; last scan — `scanned_at` from MAX(c.scanned_at), rendered as the raw ISO string; `never` when NULL


### 4.3 Surfaces — `/surfaces`

**Answers:** What is actually running in this estate, and what is known about each thing?

| Panel | Shows | Backing |
|---|---|---|
| `_surfaces_ai_band` | Puts every AI-kind surface on screen with its meta_json unpacked: the models the box serves, the MCP tools it exposes, the… | _esc (yhwach/ui.py:538); _copy_cmd (ui.py:1065); .card/table/th,td… <br>*3 row(s)* |
| `_surfaces_asset_rollup` | Collapses the whole estate's meta_json into one de-duplicated inventory: each distinct model name, MCP tool name, agent name,… | _esc (ui.py:538); .chip (ui.py:184); .subhdr (ui.py:312); .hostchip… <br>*4 row(s)* |
| `_surfaces_service_inventory` | One row per listening service across the estate with product, version, cpe, banner, every surface kind bound to it, the auth… | _esc (ui.py:538); the `(SELECT GROUP_CONCAT(s.kind) FROM surface s… <br>*11 row(s)* |
| `_surfaces_probe_facts` | Shows the entire contents of every surface's meta_json, decoded key by key, with keys no decoder knows printed verbatim — so the… | _esc (ui.py:538); the native <details class='subnet-fold'> /… <br>*12, 0 row(s)* |
| `_surfaces_http_endpoints` | The web half of the estate inventory: each web_app with its base URL, vhost and whatever fingerprint is recorded, and under it… | _esc (ui.py:538); _copy_cmd (ui.py:1065); _cov_bar's segmented-bar… <br>*6, 32, 9 row(s)* |
| `_surfaces_kind_briefing` | For every surface kind actually present in this estate, quotes its service_matrix row (enum_ref, taxonomy, classify,… | reference._load (reference.py:29) and its _FILES map… <br>*9 row(s)* |
| `_surfaces_cve_match` | Runs the bundled CVE map against every versioned software row right now and shows three honest outcomes per row: the entries… | vulns.load_cve_map (vulns.py:36), vulns.version_matches… <br>*6, 3 row(s)* |
| `_surfaces_software` | The flat, complete list of every software row in the engagement — service products, OS packages, kernels, runtimes — with where… | _esc (ui.py:538); .subhdr (ui.py:312); .chip (ui.py:184); .star… <br>*6, 1 row(s)* |

**`_surfaces_ai_band` — the query**

```sql
SELECT s.id AS sid, h.ip AS ip, COALESCE(h.hostname,'') AS hostname, h.stage AS stage,
       sv.port AS port, COALESCE(sv.proto,'tcp') AS proto,
       COALESCE(sv.product,'') AS product,
       s.kind AS kind, COALESCE(s.auth,'unknown') AS auth,
       COALESCE(s.meta_json,'{}') AS meta_json, s.discovered_at AS seen
FROM surface s
JOIN host h ON h.id = s.host_id
LEFT JOIN service sv ON sv.id = s.service_id
WHERE h.engagement_id = ?
  AND s.kind IN ('ollama','gradio','openwebui','chatbot','rag','mcp','a2a','vectordb',
                 'openai_compat','n8n','mlflow','langflow','ray','triton','comfyui','openapi')
ORDER BY h.ip, sv.port, s.kind
```

Columns: host — `h.ip` bold, `h.hostname` after it in .mono, the whole cell an <a href='/host?ip=…'> into the…; port — `sv.port`/`sv.proto` in the `.port .pn` accent-magenta idiom (ui.py:287-291), plus `sv.product` in…; kind — `s.kind` as a .chip in --accent (ui.py:184).; auth — `s.auth` as a .badge coloured by fact, not judgement: 'none' → #d03b3b, any of…; assets — the decoded array keys, as labelled chip groups: `models` → 'models:' + one .chip per element;…; endpoint — the full address assembled from the row: `{meta.scheme or 'http'}://{ip}:{port}{meta.endpoint or…; version — decoded `meta.version`. '—' when absent, and the literal word 'null' is shown as '—' because…; facts — a count: 'N keys' linking (via an anchor) to this surface's block in the Probe facts panel below, so…; seen — `s.discovered_at`, in .mono at .72rem.


### 4.4 Identity — `/identity`

**Answers:** Who is in this domain, what do I hold, and is it safe to spray?

| Panel | Shows | Backing |
|---|---|---|
| `_identity_domain_header` | States the domain we are working, the DC that serves it, and — never collapsed — the lockout posture of EVERY observed… | Tiles: the `.tiles`/`.tile`/`.tile .k`/`.tile .v` grid at… <br>*1, 1, 1, 1, 1 row(s)* |
| `_identity_lockout_proxy` | Shows, per account, how many failed authentications the DB has recorded on the protocols that feed the AD lockout counter, so… | The guard arithmetic: import sprayer and reuse… <br>*4, 2 row(s)* |
| `_identity_roster` | Puts every known account, group and computer on one screen with the one field nothing in yhwach renders today — the full AD… | The whole panel is _creds_vault (ui.py:2104) turned inside out:… <br>*8, 4, 4, 1 row(s)* |
| `_identity_shares` | Lists every SMB/NFS share the current principal's rights were tested against, writable ones first and non-default ones ahead of… | `.card` (ui.py:176) + `table` (ui.py:177-180). Access chips: `.chip`… <br>*5, 1, 0 row(s)* |
| `_identity_edges` | Renders every edge row with both endpoints resolved from their 'principal:<id>' / 'host:<id>' string form into real names and… | This is the `.edges` / `.edge` / `.edge .k` / `.edge .arrow` block… <br>*4, 3, 1 row(s)* |
| `_identity_world_model` | States, per class of AD fact, whether yhwach holds it (PRESENT with the literal row count), holds none of it although it could… | This is _llm_coverage_panel (ui.py:2072-2100) with a different row… <br>*15, 1 row(s)* |


### 4.5 Map — `/map`

**Answers:** "What can I reach, through what, and what is sitting in a segment I have never enumerated?"

| Panel | Shows | Backing |
|---|---|---|
| `_reach_table` | One row per tunnel: the CIDR it opened, the host it runs on, the pivot tech, which arsenal binary was shipped, when it opened,… | Markup: the `.card` + `<table>`/`<thead>`/`<tbody>` idiom exactly as… <br>*1 row(s)* |
| `_segment_inventory` | One row per CIDR drawn from three independent sources — host IPs, `tunnel.subnet`, and the comma-split `engagement.scope` — so… | Markup: `.card` + table from `_coverage_panel` (yhwach/ui.py:1096);… <br>*2, 5 row(s)* |
| `_reach_tree` | The picture of the same facts: the operator eye at the crown, one band per segment ordered by pivot depth, a bright arrowed edge… | Renderers reused wholesale, not rewritten: `_pivot_tree_svg`… <br>*9, 1, 7, 3, 2 row(s)* |
| `_host_cards` | The detail layer under the tree, moved here off the Board: every non-undiscovered host as a card with its open ports, the… | This panel is mostly a lift-and-fix of `_network_map`'s card half… <br>*9, 12, 0 row(s)* |
| `_interfaces` | State plainly which hosts hold an address in more than one segment, because those are the only hosts a pivot can be built on —… | Markup: the simplest `.card` + table + `.empty` paragraph form,… <br>*0, 1 row(s)* |


### 4.6 Vault — `/vault`

**Answers:** What credentials do I hold, where do they actually work, and is spraying safe?

| Panel | Shows | Backing |
|---|---|---|
| `_vault_table` | Every credential the engagement holds, with its proven access and its proven FAILURES in separate cells, so a recorded… | `_esc` (yhwach/ui.py:538) for every cell. Lift the `_secret_cell`… <br>*4, 5 row(s)* |
| `_spray_safety_band` | Puts the lockout facts the sprayer's own guard reads on the page you open before spraying: the observed policy, and per-account… | `.tiles` / `.tile` / `.tile .k` / `.tile .v` (yhwach/ui.py:166-170)… <br>*1, 3 row(s)* |
| `_cred_service_matrix` | Which (credential, service) pairs have been tried and how they came out — and, distinctly, which pairs can never be tried… | The entire `.matrix` CSS block (yhwach/ui.py:348-367): `.matrix`,… <br>*11, 5, 4, 2 row(s)* |
| `_vault_access_ledger` | Every credential_access row this engagement holds, grouped under its credential, newest first, with the checked_at and the… | `<details>`/`<summary>` with no JS, as `.subnet-fold` does… <br>*7 row(s)* |
| `_spray_feed` | The most recent writes to credential_access across the whole vault, strictly newest first — what just happened, in one glance,… | The whole `.sprayfeed` CSS block (yhwach/ui.py:370-379) with ONE… <br>*7, 1 row(s)* |

**`_vault_table` — the query**

```sql
WITH acc AS (
    SELECT ca.credential_id, ca.host_id, ca.port, ca.proto, ca.result,
           CASE WHEN ca.result IN ('admin','success') THEN 'proven' ELSE 'failed' END AS bucket
      FROM credential_access ca WHERE ca.engagement_id = ?
),
dedup AS (
    SELECT a.* FROM acc a
     WHERE a.port IS NOT NULL OR a.proto IS NOT NULL
        OR NOT EXISTS (SELECT 1 FROM acc b
                        WHERE b.credential_id = a.credential_id AND b.host_id = a.host_id
                          AND b.bucket = a.bucket
                          AND (b.port IS NOT NULL OR b.proto IS NOT NULL))
),
agg AS (
    SELECT credential_id,
           SUM(bucket='proven')                                       AS n_proven,
           SUM(result='admin')                                        AS n_admin,
           SUM(bucket='failed')                                       AS n_failed,
           COUNT(DISTINCT CASE WHEN bucket='proven' THEN host_id END) AS n_hosts_proven
      FROM dedup GROUP BY credential_id
)
SELECT c.id, c.identifier, c.secret, c.kind, c.source,
       sh.ip AS source_host_ip, vh.ip AS validated_on_host_ip, c.discovered_at,
       COALESCE(g.n_proven,0) n_proven, COALESCE(g.n_admin,0) n_admin,
       COALESCE(g.n_failed,0) n_failed, COALESCE(g.n_hosts_proven,0) n_hosts_proven
  FROM credential c
  LEFT JOIN host sh ON sh.id = c.source_host_id
  LEFT JOIN host vh ON vh.id = c.validated_on_host_id
  LEFT JOIN agg  g  ON g.credential_id = c.id
 WHERE c.engagement_id = ?
 ORDER BY (COALESCE(g.n_admin,0)>0) DESC, (COALESCE(g.n_proven,0)>0) DESC,
          (COALESCE(g.n_failed,0)>0) DESC, c.kind, LOWER(c.identifier)
```

Columns: user — `<b>identifier</b>`; row `title=` carries "first seen <discovered_at>". No wrapping hints needed…; kind — `credential.kind` in `.mono` (password / ntlm / ssh_key / api_key / token / kerberos / dpapi).; secret — lifted `_secret_cell(secret, reveal)` (today a closure at ui.py:2118): plaintext `<code class='sec'…; access » opens — the FIRST of the two cells under the `colspan=2` header "access (proven / failed)". Inline…; access » failed — the SECOND cell under the same header. `<b>N</b> ✗` then one red `.chip` (#d03b3b on…; source — `credential.source` in `.mono` at .76rem; `@source_host_ip` appended as today (ui.py:2165-2167) but…


### 4.7 PoC — `/poc`

**Answers:** Can I prove what I captured, and is the proof still intact on disk?

| Panel | Shows | Backing |
|---|---|---|
| `_poc_chain_inventory` | Puts every row of the `objective` table on screen with its recorded step count, so a captured flag with zero PoC steps is… | Replace `_poc_panel` wholesale (yhwach/ui.py:2183-2219). Markup:… <br>*8, 0 row(s)* |
| `_poc_proof_integrity` | One flat audit row per step that is not yet proof: the command is still the scaffold TODO placeholder, there is no stored… | `.chip` (ui.py:184); `_copy_cmd` (ui.py:1065) for the script path;… <br>*0 row(s)* |
| `_poc_chain_steps` | The proof itself: one collapsible block per chain whose steps show every field add_step stores, including the four the current… | The `<details class='card'>` + `<summary>` chain-block idiom is… <br>*0 row(s)* |
| `_poc_unchained_wins` | Inventory of every successful or partial attempt in the ledger that has no PoC chain under its key — the result-yielding work… | `_attempt_feed` (ui.py:2277-2300) already renders exactly this row… <br>*7, 0 row(s)* |
| `_poc_bundle` | Gives the operator the per-chain and whole-bundle markdown downloads, and says for each chain whether a chains/<slug>.md already… | `/report.md` and `/report/full.md` routes (ui.py:758-782) are the… <br>*0 row(s)* |


### 4.8 Report — `/report`

**Answers:** What do I paste into the write-up, and what am I missing evidence for?

| Panel | Shows | Backing |
|---|---|---|
| `_report_gaps` | Puts on screen, with denominators, the five places where the engagement holds a claim but not the proof that backs it — so the… | Renderers/CSS: h2.sec (ui.py:165), .card (ui.py:176), bare… <br>*0, 1, 3, 0, 0, 1, 0, 1, 0 row(s)* |
| `_report_state` | Renders synthesis.phase_report in-page with a phase label derived from the real stage histogram instead of the hardcoded… | ui.py: .report / .r-h1 / .r-h2 / .r-li CSS (ui.py:242-246) is reused… <br>*5, 1 row(s)* |
| `_report_full` | Puts the actual paste source on the page named Report — report.build_report, which is today download-only and is the ONLY place… | ui.py: .report block + .r-h1 / .r-h2 / .r-li CSS (ui.py:242-246),… <br>*1 row(s)* |


## 5. The stage dossier — per-host context, composed offline

A written briefing on `/host?ip=`, above the existing sections: what this box *is*, what is known
about each surface kind on it, and what is still dark. The stage picks the section set; the host's
own surfaces, tags, products and OS pick the content.

**It needs no model.** Every line is either a DB fact or a verbatim quote from a shipped YAML pack,
so it works with no API key, no network and nothing installed beyond the base package — which
matters, because the project's primary mode is Claude Code over MCP with no key at all.

### 5.1 Why `/host` and not a panel on the board

`/host` is served by `_shell(lab, "map", body)` with **no `poll_url`** (`ui.py:715-724`) — unlike
`/` and `/map` it is a one-shot static render per click. So the dossier can afford a dozen SELECTs,
several YAML lookups and even a filesystem `exists()` check, and the three-second polling loop never
touches any of it. On `/panel` the same code would re-read every playbook YAML every three seconds.

### 5.2 What composes it

```python
# yhwach/dossier.py — pure read, returns markdown
def build(conn, engagement_id: int, host_ip: str) -> str: ...
```

| Source | What it contributes |
|---|---|
| `host`, `service`, `surface`, `software` | what the box is, what it runs, what version |
| `coverage.enum_gaps(conn, eid, host_ip=…)` | what is still dark, each `Gap.fix` verbatim |
| `data/service_matrix.yaml` | per surface kind: default ports, classify, taxonomy, `default_creds`, and the `enum_ref` triage line quoted in full |
| `data/ai_attacks.yaml` | for an AI surface: the `owasp_llm_checklist` summary plus the topic matching the kind (`chatbot`→`prompt_injection`, `rag`→`rag_poisoning`, `mcp`→`mcp_attack`, `a2a`→`a2a_attack`, `vectordb`→`vector_db`) |
| `reference.lessons_for(tags)` | past-lab lessons matching this host's finding tags and surface kinds |
| `data/tags.yaml` | for each open tagged finding, what that tag means and what it implies |
| `data/gtfobins.yaml` / `lolbas.yaml` / `wadcoms.yaml` | OS-appropriate reference at `foothold` and later |
| `data/default_creds.yaml`, `data/cve_map.yaml` | rows matching this host's products and versions |

Section sets per stage (the real FSM is
`undiscovered, scanned, enumerated, foothold, looted, pivoted, done` — `db.py:521`; there is no
`triaged`):

- **scanned** — what this box looks like · coverage of record · what each surface kind *is* ·
  services with no surface row · not yet looked at
- **enumerated** — surface inventory and triage state · what the packs say · web surface ·
  identity seen from here · open leads and what they mean · past-lab lessons · still unchecked
- **foothold** — what we run as and where · local inventory · on-disk secret classes ·
  privesc reference for this OS · what this host reaches · loot recorded here
- **looted / pivoted / done** — what came off this box · where those creds have and have not been
  tried · new ground behind the tunnel · re-recon debt · proof of record

### 5.3 Prerequisite: the packs do not cover the common services

Verified by running the lookups:

```
reference.render_pack('services', k)   smb 0  ldap 0  kerberos 0  winrm 0  ssh 0  rdp 0  web 0
                                       redis 298  mcp 163  rag 105     (characters returned)
reference.lessons_for({'smb','ldap','kerberos','winrm'})  ->  []
```

A Domain Controller gets **zero context**. Two separate causes, both must be fixed:

1. `reference._matches` substring-matches across *every* value of an entry, so it over-matches and
   silently returns empty. The dossier must look up by exact `kind ==` against
   `reference._load('services')`, and print `no service-matrix row for kind 'smb'` rather than a
   blank heading.
2. `service_matrix.yaml` has **no row at all** for smb, ldap, kerberos, winrm, ssh, rdp, ftp, web
   or web_upload — even though `probes/traditional.PORT_KIND` classifies all of them. Add 9–11 rows
   with `service_enum: false` (so no new coverage gate fires);
   `tests/test_service_matrix.py:30` validates the new ports against `PORT_KIND` for free.

This is an **xs** YAML change and it is the difference between the feature landing and the feature
looking broken.

### 5.4 Optional LLM enrichment

The deterministic dossier is the product, not a fallback. The model's job is the *specific* thing
the packs cannot know: what an unusual banner means on this box, what a raw probe response is
saying, a summary of a long evidence blob.

```sql
CREATE TABLE IF NOT EXISTS host_annotation (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES host(id),
    stage       TEXT NOT NULL,
    section     TEXT NOT NULL,
    body        TEXT NOT NULL,
    author      TEXT,                -- 'claude-code' | 'brain'
    model       TEXT,
    source_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE(host_id, stage, section)
);
```

Added to `db._ADDED_TABLES` so `_migrate` self-heals every existing lab DB on the next `connect`.

**Write path, the no-key case (the normal case).** Two MCP tools, following the shape of
`tool_add_finding` (`mcp_tools.py:764-810`):

- `yhwach_dossier(lab, host)` returns the *same* deterministic markdown the board renders, so the
  model annotates exactly what the operator sees;
- `yhwach_annotate(lab, host, section, text)` writes one row.

Claude Code is the model. **yhwach never calls one.** Prose arrives at the MCP wire and the engine
stores typed facts — which is the moat the advisor doctrine asks for.

**Write path, the key case.** `yhwach dossier --host X --enrich` makes one `Brain(Role.INTERPRET)`
call and writes with `author='brain'`. No board code changes; the board cannot tell which path wrote
the row.

**Staleness without a model call.** On write, store `source_hash` = sha256 of a cheap per-host
fingerprint: `host.stage` concatenated with `MAX(id)` over `service`, `surface`, `finding`,
`attempt`, `scan_coverage` and `stage_transition` for that host. All six are monotonic, so the
fingerprint is one SELECT and changes if and only if something was learned. On render the board
recomputes it and compares two strings — equal renders normally, different renders the annotation
dimmed and labelled *"written at an earlier state of this host (stage was X)"*. The board never
rewrites the hash, never deletes a stale row and never calls a model.

**Presentation.** Model-authored text sits next to scan results, so it carries visibly distinct
styling plus an author and age label. The tool description constrains it to **description, not
direction** — an annotation that says "next, do X" rebuilds the recommender in prose. The packs say
what a redis surface *is*; the model says what *this* banner means here.

### 5.5 One honest limit, stated on screen

"What evidence moved this host to this stage" is not recorded — `stage_transition.note` exists
(`schema.sql:154`) and the INSERT at `db.py:562` does not write it (§7.6). A timestamp-correlation
reconstruction ("in the 14 minutes before this transition: 2 attempts, 1 finding") is derivable and
worth showing, but it must be labelled as inference, never as causation.

---

## 6. Mockups

`docs/mockups/` renders all eight tabs as static HTML from a seeded engagement, using `ui._CSS`
itself plus the §3.4 patch, so layout can be judged before any of it is built.

```bash
python docs/mockups/pages.py docs/ui-panel-spec.json /path/to/lab.db docs/mockups/out
```

Every panel on every page is driven by its real query against a real DB — 267 rows across 41
panels in the reference run. Panels that render empty there are empty *honestly*: the PoC tab's
three blanks are precisely the gap that tab exists to expose.



---

## 7. Writer gaps — what not to build yet

A panel over an unwritten table is the worst outcome of a UI pass. Each item below gates a panel
above it; the panel ships *after* the writer, or ships with an explicit NOT-COLLECTED state.

> **All of §7 has since shipped.** 7.1 `probe_run` + the on_probe callback · 7.2 `ParsedWebPath`
> gains params/auth_required and `ingest_web` passes them · 7.3 the MCP/A2A/Qdrant/Ollama probes
> keep what they fetch · 7.4 nmap ssl-cert names become `domain` rows · 7.5 SharpHound `Members`
> become `membership` rows · 7.6 `set_host_stage(note=)` + `yhwach advance --why` · 7.7
> `craft_executed` carries payload/response/verdict and `interpret.looks_like_refusal` is public ·
> 7.8 `notes.findings_table` renders evidence and `CoverageScore.pct` returns None at zero.
> The paragraphs below are kept as the record of what was wrong and why.

### 7.1 Probe runs are recorded nowhere

`yhwach probe` writes a row only on a **hit** (`upsert_surface`, plus an optional `add_software`) —
no attempt row, no event, no timestamp. So "never probed" and "probed, nothing matched" are
indistinguishable, and `brief.py:90-92` already reports "Unprobed services" from
`LEFT JOIN surface WHERE s.id IS NULL`, which is wrong for exactly this reason. The schema comment
at `schema.sql:255` listing `probe` among the event kinds written today is stale.

*Fix:* a small `probe_run(host_id, service_id, port, probe_name, result, ts)` table written by the
probe loop. **Until it lands, no panel may show a "probed" column** — only "surfaces recorded".
A probe sweep over a /24 is thousands of invocations, so an event-per-probe would bury `_activity`.

### 7.2 `web_app` and `web_path` are half-filled by construction

`ingest_web` is the only writer (`ingest.py:86-108`) and both callers invoke it positionally:
`ingest_web(conn, host_id, url, text)` (`cli.py:213`, `mcp_tools.py:475`). Neither passes `server=`
or `tech=`, and `ingest_web` itself never passes `title`, `vhost`, `waf`, `favicon_hash`,
`service_id` or `surface_id` to `add_web_app`, nor `params`, `auth_required` or `method` to
`add_web_path` (`source` is the literal `"web"`). So in a real run a `web_app` row holds
`host_id, base_url, scheme` and nothing else, and `web_path.params` — documented as "discovered
query params / form fields (injection surface)" at `schema.sql:422` — is structurally unwritable:
`ParsedWebPath` has no `params` field at all (`parsers/web.py:36-47`).

*Fix:* widen `ParsedWebPath` and thread the kwargs through both callers; add an `httpx` JSONL
parser, which fills `title`, `server` and `tech` for the whole scope in one command and needs no new
dependency. Keep every new field optional so existing paths produce byte-identical rows
(`tests/test_schema_v1.py:272-279` pins current behaviour).

### 7.3 The AI probes discard what they fetch

No new network request is needed for any of these — the data is already in the parsed response dict,
used as a type check and then dropped:

| Probe | Fetches | Stores | The pack that wants it |
|---|---|---|---|
| MCP (`probes/ai.py:283-291`) | full tool dicts | `t.get("name")` only | `ai_attacks.mcp_attack` *is* tool descriptions |
| A2A (`:349-353`) | gates on `skills`/`capabilities` | `name` only | `a2a_attack` step 1 reads name/skills/capabilities |
| Qdrant (`:445-447`) | gates on `collections` | `{engine, endpoint}` | `vector_db` step 2 needs the collection *name* |
| Gradio (`:316-323`) | gates on components | version only | — |

Ollama records no version either, so despite `cve_map.yaml` carrying an `ollama` product the probe
path can never produce a CVE match. *Fix:* widen the `meta` dicts; truncate at ingest (paths are
already capped at 20) and escape at render. Regenerates golden fixtures
(`fixtures.py:100-113`).

### 7.4 `domain` has no writer

`db.add_domain` (`db.py:1382-1405`) has no caller anywhere in the repo, so vhosts, subdomains and
TLS SAN names are never recorded — and `notes.render_web_overview` already carries a permanently
empty "Domains / vhosts" section. The SAN data is on disk and discarded at parse time: `-sC` is in
every scanner mode template (`scanner.py:72-90`) but `parsers/nmap.py` ignores `<script>` elements
entirely (`nmap.py:246-251`). `discovery.observe_ip` already reserves the `cert_san` source name.

### 7.5 `membership` has no writer

`ingest_bloodhound_graph` (`ingest.py:113-137`) writes principals, privileges and edges but never a
membership, though the BloodHound JSON carries `MemberOf`. `notes.render_users_groups` queries it
and prints "(no members recorded)" for every group forever. **An empty Groups panel must render
NOT-COLLECTED, never ABSENT** — "this domain is flat" is a dangerous misread.

### 7.6 `stage_transition.note` is a dead column

The column exists (`schema.sql:154`); the INSERT at `db.py:562` lists only
`(host_id, from_stage, to_stage, ts)`. So "what evidence moved this host to this stage" is
unanswerable except by timestamp inference. *Fix:* pass a note through `set_host_stage` and have
`advance` supply the reason — xs effort, and it is what makes the stage dossier authoritative
rather than reconstructed.

### 7.7 Payloads and refusals are discarded

The injection phrasing that worked is persisted only when it is **not** sent —
`evidence=f"would deliver: {payload[:80]}"` sits in the dry-run branch (`actions.py:174`). On a live
craft the payload is in no return value and no column, and the response is kept only as `out[:100]`,
and only when there were no findings (`runners.py:221`). Separately, `_REFUSAL_RE`
(`interpret.py:846-852`) exists solely to *suppress* a finding, so a guardrail rejection produces
zero rows anywhere.

For an operator deciding whether to escalate direct → indirect → encoded, "this model refused this
phrasing, in these words" is the highest-value fact in the engagement. *Fix:* log a
`craft_delivered` event carrying `{payload, method, path, param, response_excerpt, verdict}` — the
`event` table already takes arbitrary JSON and `poc.add_step` proves the pattern — and emit a typed
negative (refusal matched / no signal / delivered-but-silent) alongside the positive. Both are then
an inventory panel, which fits this design's first rule exactly.

### 7.8 Two live bugs to fix in passing

- `notes.findings_table` SELECTs `evidence` and then omits it from both the header and the row
  (`notes.py:142-150`). `finding.evidence` is the best prose in the DB and reaches no screen at all;
  adding it as a column is a one-line change.
- `CoverageScore.pct` returns `100` when `considered == 0` (`coverage.py:238-239`), so a fresh
  engagement reports 100% enumeration honesty on the board, in `yhwach coverage`, and over MCP.
  Return `None` and branch in the three renderers.

---

## 8. Build order

> Followed as written. Everything in §4, §5 and §7 is implemented and tested; the only item
> deliberately not built is an evidence/screenshot blob store (§9), which is a storage decision
> rather than a UI change.

1. **§3.4 figure/ground + §3.1 helpers.** Pure CSS and three functions. Everything after this is
   easier to judge and cheaper to write.
2. **§3.3 the catalog cache.** Removes ~210 ms of a ~230 ms render and stops `_next_panel` and
   `_workers_panel` disagreeing about the candidate set because they load the playbooks at two
   different instants.
3. **Board rework.** Composition only — move `_network_map` to `/map` and the vault panels to
   `/vault`, cap the uncapped tables, rename the recall menu. No new queries, and it is what makes
   room for the new tabs.
4. **`/recon`.** Highest value per unit of effort, and entirely over well-populated tables. The
   enumeration matrix is the single most useful missing view on the board.
5. **`/surfaces`,** starting with the `meta_json` decoder — one `json.loads` plus a per-kind column
   map, no new writer, and it unlocks the AI band, the probe-facts panel and the HTTP inventory at
   once.
6. **The service-matrix rows (§5 prerequisite).** Nine to eleven YAML rows with
   `service_enum: false`. xs, and the dossier looks broken without it.
7. **`/identity`,** honest about `membership` being NOT-COLLECTED.
8. **`/map`, `/vault`, `/poc`, `/report` reworks.**
9. **The dossier (§5),** once the packs cover the common service kinds.
10. **The writer changes (§7)** in parallel throughout — each one unlocks the panel above it.

---

## 9. Out of scope

- **Approvals and kill.** Settled: the board has no control surface. `README.md:88`,
  `AGENT.md:33/49/427` and `ARCHITECTURE.md:21` still describe one and should be corrected.
- **Ranking, scoring, or ordering techniques by expected value.** See §0.
- **An evidence/screenshot blob store.** There is no `screenshot` field anywhere in the schema and
  no proof table; the only durable evidence is the ≤6000-char output excerpts, the script files and
  `loot.local_path`. That is a real storage decision, not a UI change.
- **A light theme.** The board is a night console by choice.
