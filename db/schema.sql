-- Yhwach world model
-- Single source of truth for an engagement. SQLite; one .db per lab.
--
-- Conventions
--   * Timestamps are ISO-8601 UTC (`2026-03-25T14:22:07Z`), stored as TEXT.
--   * Booleans are INTEGER 0/1.
--   * JSON blobs (meta_json, payload_json) are TEXT; the engine json-parses on read.
--   * `event` is append-only; every other table is mutable but has updated_at where useful.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- Engagement scope
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engagement (
    id             INTEGER PRIMARY KEY,
    lab            TEXT    NOT NULL UNIQUE,
    domain         TEXT,
    dc_ip          TEXT,
    scope          TEXT,                  -- comma-separated CIDRs, mirrored from scope.txt
    started_at     TEXT    NOT NULL,
    time_budget_h  REAL,                  -- e.g. 48.0 for a 2-day exam window
    points_target  INTEGER DEFAULT 75,
    points_max     INTEGER DEFAULT 100
);

-- ---------------------------------------------------------------------------
-- Hosts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS host (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagement(id),
    ip             TEXT    NOT NULL,
    hostname       TEXT,
    os             TEXT,                  -- linux | windows | unknown
    role           TEXT,                  -- dc | web | ai_host | standalone_ai | workstation | server
    stage          TEXT    NOT NULL DEFAULT 'undiscovered',
                                          -- undiscovered | scanned | enumerated | foothold | looted | pivoted | done | blocked
    points_value   INTEGER DEFAULT 0,     -- what this host is worth if fully owned
    points_scored  INTEGER DEFAULT 0,     -- what's been captured so far
    tags           TEXT,                  -- comma-separated: dev_artifact, high_ev, ai_host, ...
    first_seen     TEXT    NOT NULL,
    last_updated   TEXT,
    UNIQUE(engagement_id, ip)
);

-- ---------------------------------------------------------------------------
-- Services on hosts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS service (
    id           INTEGER PRIMARY KEY,
    host_id      INTEGER NOT NULL REFERENCES host(id),
    port         INTEGER NOT NULL,
    proto        TEXT    NOT NULL,        -- tcp | udp
    product      TEXT,
    version      TEXT,
    cpe          TEXT,                   -- cpe:2.3:... from nmap -sV; drives CVE matching
    banner       TEXT,
    discovered_at TEXT    NOT NULL,
    UNIQUE(host_id, port, proto)
);

-- ---------------------------------------------------------------------------
-- Attack surfaces — a semantic layer on top of services.
-- One service can host multiple surfaces (a web app that is both a chatbot and a RAG frontend).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS surface (
    id             INTEGER PRIMARY KEY,
    host_id        INTEGER NOT NULL REFERENCES host(id),
    service_id     INTEGER REFERENCES service(id),
    kind           TEXT    NOT NULL,      -- ollama | gradio | openwebui | chatbot | rag | mcp | a2a | vectordb | web | smb | ldap | ssh | other
    auth           TEXT,                  -- none | bearer | basic | cookie | unknown
    meta_json      TEXT,                  -- endpoints, model names, tool list, etc.
    discovered_at  TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Findings — anything the engine or operator confirms as a defect/vuln/lead.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding (
    id                INTEGER PRIMARY KEY,
    engagement_id     INTEGER REFERENCES engagement(id),  -- scopes host-less findings to a lab
    host_id           INTEGER REFERENCES host(id),
    surface_id        INTEGER REFERENCES surface(id),
    class             TEXT    NOT NULL,   -- LLM01..LLM10 | CWE-... | CVE-... | ATLAS-...
    title             TEXT    NOT NULL,
    severity          TEXT    NOT NULL,   -- critical | high | medium | low
    evidence          TEXT,                -- one-line summary; never a raw dump
    tag               TEXT,                -- chaining key matched by a rule's `findings_include`
                                           -- (e.g. rag_upload | chrome_login_data | gitlab_token)
    playbook_rule_id  TEXT,
    status            TEXT    NOT NULL DEFAULT 'open',   -- open | exploited | dead | duplicate
    discovered_at     TEXT    NOT NULL,
    updated_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_finding_tag ON finding(tag);
CREATE INDEX IF NOT EXISTS idx_finding_engagement ON finding(engagement_id, status);

-- ---------------------------------------------------------------------------
-- Credentials — the reusable primitive. NEVER exhausted per Kapi's rule.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credential (
    id                  INTEGER PRIMARY KEY,
    engagement_id       INTEGER NOT NULL REFERENCES engagement(id),
    identifier          TEXT    NOT NULL, -- user / key label / token id
    secret              TEXT,              -- plaintext, hash, or key material (or marker for out-of-band)
    kind                TEXT    NOT NULL, -- password | ntlm | kerberos | ssh_key | api_key | token | dpapi
    source              TEXT    NOT NULL, -- prompt_injection | rag | imds | dump | spray | user_provided | chrome | dpapi | keepass | unattend
    source_host_id      INTEGER REFERENCES host(id),
    validated_on_host_id INTEGER REFERENCES host(id),
    discovered_at       TEXT    NOT NULL,
    UNIQUE(engagement_id, identifier, kind)
);

-- ---------------------------------------------------------------------------
-- Tasks — the plan queue. Populated by the planner from matched playbook rules.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task (
    id                INTEGER PRIMARY KEY,
    engagement_id     INTEGER NOT NULL REFERENCES engagement(id),
    target_host_id    INTEGER REFERENCES host(id),
    target_surface_id INTEGER REFERENCES surface(id),
    kind              TEXT    NOT NULL,   -- scan | enumerate | craft_injection | probe | spray | privesc | pivot | loot | screenshot | proof
    playbook_rule_id  TEXT,
    technique_class   TEXT    NOT NULL DEFAULT 'ai',  -- ai | traditional | ad  (drives AI-first tiering)
    rationale         TEXT,
    risk              TEXT    NOT NULL,   -- read_only | exploit | destructive
    autonomy          TEXT    NOT NULL,   -- proceed | propose | ask
    ev_score          REAL    NOT NULL,   -- likelihood * points * (1 / time_cost)
    status            TEXT    NOT NULL DEFAULT 'pending',   -- pending | running | done | blocked | abandoned
    created_at        TEXT    NOT NULL,
    updated_at        TEXT,
    UNIQUE(playbook_rule_id, target_surface_id)  -- dedupe same rule vs same surface
);

-- ---------------------------------------------------------------------------
-- Proof — captured flag file + REQUIRED screenshot. The screenshot row is a hard
-- FSM gate: `foothold -> looted` refuses to fire without one bound here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS proof (
    id               INTEGER PRIMARY KEY,
    host_id          INTEGER NOT NULL REFERENCES host(id),
    flag_path        TEXT    NOT NULL,
    flag_content     TEXT,
    screenshot_path  TEXT    NOT NULL,
    obsidian_ref     TEXT,                 -- vault path where the mirror lives
    scored           INTEGER NOT NULL DEFAULT 0,
    captured_at      TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Technique state — enforces "no repeats" per engagement.
-- Populated when a technique succeeds; the ranker filters against this.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS technique_state (
    id                   INTEGER PRIMARY KEY,
    engagement_id        INTEGER NOT NULL REFERENCES engagement(id),
    technique_id         TEXT    NOT NULL, -- e.g. 'pypi_typosquat', 'rag_smb_poison', 'a2a_mitm'
    status               TEXT    NOT NULL, -- available | consumed
    consumed_on_host_id  INTEGER REFERENCES host(id),
    consumed_at          TEXT,
    UNIQUE(engagement_id, technique_id)
);

-- ---------------------------------------------------------------------------
-- Lore denylist hits — record when a scanner turns up known OffSec dev
-- artifacts (cloudbase-init and friends). Prevents the ranker from resurfacing
-- them. Entries themselves are in `playbooks/lore_denylist.yaml`.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lore_denylist_hit (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagement(id),
    host_id        INTEGER REFERENCES host(id),
    artifact       TEXT    NOT NULL,      -- 'cloudbase-init' | 'default_password_placeholder' | ...
    seen_at        TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Tunnels — pivot / subnet-reachability state. A row means the operator has a
-- route into `subnet` via the pivot host `via_host_id` (e.g. a Ligolo agent).
-- This is what gates a host's `looted -> pivoted` transition and feeds the
-- reachability picture in the report.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tunnel (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagement(id),
    via_host_id    INTEGER REFERENCES host(id),   -- pivot host running the agent
    subnet         TEXT    NOT NULL,               -- CIDR now reachable through it
    kind           TEXT    NOT NULL DEFAULT 'ligolo',
    created_at     TEXT    NOT NULL,
    UNIQUE(engagement_id, via_host_id, subnet)
);
CREATE INDEX IF NOT EXISTS idx_tunnel_host ON tunnel(via_host_id);

-- Notes are NOT stored here. The engagement notebook is the Obsidian vault, and
-- the operator (Claude Code) writes it directly via the Obsidian MCP — detailed,
-- at every objective. See persona/notebook.md for the structure. The DB is the
-- queryable world model only; the vault is the single source of truth for
-- write-ups (attack chains, PoCs, evidence).

-- ---------------------------------------------------------------------------
-- Event — append-only audit log for the report/timeline. Kinds actually written
-- today: ingest | enum | probe | stage | credential | proof | tunnel | note.
-- (`persona_hash` / `rules_hash` are RESERVED for a future replay/regression
-- story; the engine does not populate them yet — see ROADMAP Phase 6.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagement(id),
    ts             TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    persona_hash   TEXT,                  -- reserved (not populated yet)
    rules_hash     TEXT,                  -- reserved (not populated yet)
    payload_json   TEXT    NOT NULL
);

-- ===========================================================================
-- Attack-surface enrichment (schema v1)
-- Everything below expands the world model from "what listens" to "what the next
-- attack path is": versioned software + CVEs, the AD identity/privilege graph,
-- the web surface, and per-host loot/interfaces/objectives. These tables are the
-- queryable record; where a fact should drive the next move, an interpret
-- extractor also emits a tagged `finding` so the existing planner picks it up.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Software inventory — anything versioned on a host, listening or not.
-- `service` records what listens; `software` also captures post-foothold finds
-- (kernel, sudo, installed packages, a CMS behind a web port) — the raw material
-- for version -> CVE matching and privesc.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS software (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES host(id),
    service_id    INTEGER REFERENCES service(id),   -- set when tied to a listening service
    name          TEXT    NOT NULL,      -- 'Apache ActiveMQ' | 'sudo' | 'Linux kernel' | 'WordPress'
    version       TEXT,
    cpe           TEXT,                  -- cpe:2.3:a:apache:activemq:5.17.4 — drives CVE match
    kind          TEXT    NOT NULL DEFAULT 'service',  -- service|package|kernel|runtime|cms|driver|lib
    source        TEXT,                  -- nmap|banner|linpeas|winpeas|dpkg|manual
    evidence      TEXT,
    discovered_at TEXT    NOT NULL,
    updated_at    TEXT,
    UNIQUE(host_id, name, version)
);
CREATE INDEX IF NOT EXISTS idx_software_host ON software(host_id);

-- ---------------------------------------------------------------------------
-- Vulnerabilities — version -> CVE hypotheses with a lifecycle. Distinct from
-- `finding`: a finding is a confirmed defect/lead the operator stands behind; a
-- vulnerability starts as a `potential` match and is promoted to a finding + task
-- once confirmed. Keeps the CVE noise out of the findings ledger until it's real.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability (
    id                INTEGER PRIMARY KEY,
    engagement_id     INTEGER NOT NULL REFERENCES engagement(id),
    host_id           INTEGER NOT NULL REFERENCES host(id),
    software_id       INTEGER REFERENCES software(id),
    service_id        INTEGER REFERENCES service(id),
    cve               TEXT,              -- CVE-2023-46604 (or a vendor advisory id)
    title             TEXT,
    cvss              REAL,
    state             TEXT    NOT NULL DEFAULT 'potential',  -- potential|confirmed|exploited|patched|false_positive
    exploit_ref       TEXT,              -- searchsploit id | msf module | nuclei template | URL
    exploit_available INTEGER DEFAULT 0,
    source            TEXT,              -- version_match|nuclei|searchsploit|nvd|manual
    discovered_at     TEXT    NOT NULL,
    updated_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulnerability(host_id, state);

-- ---------------------------------------------------------------------------
-- Principals — accounts, groups, computers. The identity layer credentials and
-- privileges hang off: a credential is a secret FOR a principal, and a principal
-- can hold several (password + NT hash + kerberos + ssh key). This is what the
-- BloodHound / enum4linux / DCSync data has had nowhere to land.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS principal (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id),
    name          TEXT    NOT NULL,      -- sAMAccountName / local user / group name
    domain        TEXT,                  -- aldinervaide.com | WORKGROUP | <hostname> for local
    type          TEXT    NOT NULL DEFAULT 'user',  -- user|group|computer|service|local
    sid           TEXT,
    rid           INTEGER,
    enabled       INTEGER DEFAULT 1,
    flags         TEXT,                  -- comma list: dont_require_preauth,adminCount,unconstrained_deleg,passwd_notreqd,spn
    spn           TEXT,
    description   TEXT,
    home_host_id  INTEGER REFERENCES host(id),   -- for local accounts / where first seen
    source        TEXT,                  -- bloodhound|enum4linux|rid_brute|dcsync|manual
    discovered_at TEXT    NOT NULL,
    updated_at    TEXT,
    UNIQUE(engagement_id, name, domain, type)
);
CREATE INDEX IF NOT EXISTS idx_principal_eng ON principal(engagement_id, type);

-- Group membership (principal -> group; both rows in `principal`).
CREATE TABLE IF NOT EXISTS membership (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id),
    member_id     INTEGER NOT NULL REFERENCES principal(id),
    group_id      INTEGER NOT NULL REFERENCES principal(id),
    source        TEXT,
    discovered_at TEXT    NOT NULL,
    UNIQUE(member_id, group_id)
);

-- Privileges / rights a principal holds; host-scoped when local, NULL host = domain-wide.
CREATE TABLE IF NOT EXISTS privilege (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id),
    principal_id  INTEGER REFERENCES principal(id),
    host_id       INTEGER REFERENCES host(id),   -- NULL = domain-wide
    right         TEXT    NOT NULL,      -- local_admin|SeImpersonate|SeBackupPrivilege|sudo_all|docker|DCSync|GenericAll|WriteDacl|ForceChangePassword|ESC1|...
    target        TEXT,                  -- what the right is over (principal name, cert template, share)
    source        TEXT,
    discovered_at TEXT    NOT NULL,
    UNIQUE(engagement_id, principal_id, host_id, right, target)
);

-- Attack-graph edges — reachability + escalation between nodes. A node is
-- addressed as 'principal:<id>' or 'host:<id>'. One recursive query over this
-- table answers "shortest path from what I own -> Domain Admin / the objective".
CREATE TABLE IF NOT EXISTS edge (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id),
    src           TEXT    NOT NULL,      -- 'principal:12' | 'host:3'
    dst           TEXT    NOT NULL,
    kind          TEXT    NOT NULL,      -- AdminTo|HasSession|MemberOf|CanRDP|CanPSRemote|CredReuse|ESC1|GenericAll|TunnelReachable|...
    confidence    TEXT    DEFAULT 'confirmed',  -- confirmed|likely|theoretical
    source        TEXT,
    discovered_at TEXT    NOT NULL,
    UNIQUE(engagement_id, src, dst, kind)
);
CREATE INDEX IF NOT EXISTS idx_edge_src ON edge(engagement_id, src);

-- ---------------------------------------------------------------------------
-- Web surface — a real model on top of a `web` surface: the app, its vhosts,
-- and every path/route found by content discovery. `service`/`surface` say a web
-- port exists; these say what's ON it and where to attack.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS web_app (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES host(id),
    service_id    INTEGER REFERENCES service(id),
    surface_id    INTEGER REFERENCES surface(id),
    base_url      TEXT    NOT NULL,      -- http://192.168.239.10:80
    vhost         TEXT,                  -- Host header when virtual-hosted
    scheme        TEXT,                  -- http|https
    title         TEXT,
    server        TEXT,                  -- 'nginx 1.28.3'
    tech          TEXT,                  -- framework/CMS + versions (JSON or comma list): 'WordPress 6.4, PHP 8.2'
    waf           TEXT,
    favicon_hash  TEXT,
    notes         TEXT,
    discovered_at TEXT    NOT NULL,
    updated_at    TEXT,
    UNIQUE(host_id, base_url, vhost)
);

CREATE TABLE IF NOT EXISTS web_path (
    id            INTEGER PRIMARY KEY,
    web_app_id    INTEGER NOT NULL REFERENCES web_app(id),
    path          TEXT    NOT NULL,
    method        TEXT    DEFAULT 'GET',
    status        INTEGER,
    length        INTEGER,
    kind          TEXT,                  -- login|upload|admin|api|backup|config|source|redirect|dir|other
    auth_required INTEGER DEFAULT 0,
    params        TEXT,                  -- discovered query params / form fields (injection surface)
    interesting   INTEGER DEFAULT 0,
    source        TEXT,                  -- gobuster|ffuf|feroxbuster|dirb|nikto|manual
    notes         TEXT,
    discovered_at TEXT    NOT NULL,
    UNIQUE(web_app_id, path, method)
);
CREATE INDEX IF NOT EXISTS idx_webpath_app ON web_path(web_app_id, interesting);

-- Domains / vhosts / subdomains discovered (DNS, cert SANs, vhost fuzzing, LDAP).
CREATE TABLE IF NOT EXISTS domain (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id),
    name          TEXT    NOT NULL,      -- careers.forge.local | dev.example.com | aldinervaide.com
    type          TEXT    NOT NULL DEFAULT 'vhost',  -- vhost|subdomain|ad_domain|dns
    ip            TEXT,
    host_id       INTEGER REFERENCES host(id),
    source        TEXT,                  -- vhost_fuzz|cert|dns|ldap|manual
    discovered_at TEXT    NOT NULL,
    UNIQUE(engagement_id, name, type)
);

-- ---------------------------------------------------------------------------
-- Host enrichment — the "note everything on each host" layer.
-- ---------------------------------------------------------------------------

-- Interfaces: multi-homing as rows, not prose. Feeds the Network Map + pivots.
CREATE TABLE IF NOT EXISTS host_interface (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES host(id),
    ip            TEXT    NOT NULL,
    mac           TEXT,
    segment       TEXT,                  -- CIDR or label ('edge' | '172.16.239.0/24')
    is_primary    INTEGER DEFAULT 0,
    source        TEXT,                  -- nmap|ip_a|arp|manual
    discovered_at TEXT    NOT NULL,
    UNIQUE(host_id, ip)
);

-- Loot: files/keys/dumps found on a host, and whether they carry a secret.
CREATE TABLE IF NOT EXISTS loot (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER NOT NULL REFERENCES engagement(id),
    host_id         INTEGER REFERENCES host(id),
    path            TEXT,                -- remote path where found (C:\helpdesk\app.py)
    local_path      TEXT,                -- where saved on Kali
    type            TEXT,                -- config|key|db|source|dump|hash|note|binary
    contains_secret INTEGER DEFAULT 0,
    credential_id   INTEGER REFERENCES credential(id),
    summary         TEXT,
    discovered_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loot_host ON loot(host_id);

-- Password policy — gates SAFE spraying. Spraying blind into a lockout is a
-- self-own; the ranker should consult this before proposing a spray.
CREATE TABLE IF NOT EXISTS password_policy (
    id                 INTEGER PRIMARY KEY,
    engagement_id      INTEGER NOT NULL REFERENCES engagement(id),
    domain             TEXT,
    host_id            INTEGER REFERENCES host(id),
    min_length         INTEGER,
    lockout_threshold  INTEGER,          -- 0 = no lockout
    lockout_window_min INTEGER,
    complexity         INTEGER,
    source             TEXT,
    discovered_at      TEXT    NOT NULL
);

-- Objectives — the point-bearing goals, tied to proof + host.points_value.
CREATE TABLE IF NOT EXISTS objective (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id),
    host_id       INTEGER REFERENCES host(id),
    kind          TEXT    NOT NULL DEFAULT 'flag',  -- flag|data|access|domain_admin
    label         TEXT    NOT NULL,      -- 'local.txt' | 'proof.txt' | 'exfil customer DB'
    points        INTEGER DEFAULT 0,
    captured      INTEGER DEFAULT 0,
    proof_id      INTEGER REFERENCES proof(id),
    notes         TEXT,
    discovered_at TEXT    NOT NULL
);

-- SMB / NFS shares — the lateral-movement + loot surface NetExec enumerates.
-- `access` reflects the CURRENT principal's rights (READ / WRITE / READ,WRITE);
-- a writable share is a foothold/relay lead, a readable one is loot.
CREATE TABLE IF NOT EXISTS share (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES host(id),
    name          TEXT    NOT NULL,      -- C$ | NETLOGON | backups | /export/home (NFS)
    proto         TEXT    NOT NULL DEFAULT 'smb',  -- smb|nfs
    access        TEXT,                  -- READ | WRITE | READ,WRITE | none
    remark        TEXT,
    source        TEXT,                  -- netexec|smbclient|enum4linux|showmount|manual
    discovered_at TEXT    NOT NULL,
    UNIQUE(host_id, name, proto)
);
CREATE INDEX IF NOT EXISTS idx_share_host ON share(host_id);

CREATE INDEX IF NOT EXISTS idx_event_engagement_ts ON event(engagement_id, ts);
CREATE INDEX IF NOT EXISTS idx_host_stage ON host(engagement_id, stage);
CREATE INDEX IF NOT EXISTS idx_task_status ON task(engagement_id, status, ev_score DESC);
CREATE INDEX IF NOT EXISTS idx_surface_kind ON surface(kind);
CREATE INDEX IF NOT EXISTS idx_finding_status ON finding(status);

-- Surface deduplication.
-- SQLite treats NULLs as distinct in a straight UNIQUE, so we use two partial
-- unique indexes to cover both cases:
--   * surface tied to a specific service -> unique per (host, service, kind)
--   * surface bound to the host generally -> unique per (host, kind)
CREATE UNIQUE INDEX IF NOT EXISTS ux_surface_hosted_svc
    ON surface(host_id, service_id, kind)
    WHERE service_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_surface_hosted_no_svc
    ON surface(host_id, kind)
    WHERE service_id IS NULL;

-- ---------------------------------------------------------------------------
-- Attempt ledger — what the operator actually TRIED and how it went.
--
-- `technique_state` only records success (a consumed technique). This table is
-- the other half: the negative feedback loop. A recorded `fail` / `blocked`
-- retires the task, decays the EV of that rule on that host at the next plan,
-- and surfaces in the operator handoff as a DEAD END so a model whose context
-- was compacted never re-proposes a move it already burned.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attempt (
    id                INTEGER PRIMARY KEY,
    engagement_id     INTEGER NOT NULL REFERENCES engagement(id),
    task_id           INTEGER REFERENCES task(id),
    host_id           INTEGER REFERENCES host(id),
    playbook_rule_id  TEXT,
    technique_id      TEXT,               -- exhaustion key (rule.technique), for consume-on-success
    result            TEXT    NOT NULL,   -- success | fail | blocked | partial
    reason            TEXT,               -- one line: WHY it went that way (operator judgement)
    evidence          TEXT,               -- loot path / Obsidian ref / one-line output excerpt
    attempted_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempt_engagement ON attempt(engagement_id, result);
CREATE INDEX IF NOT EXISTS idx_attempt_rule ON attempt(playbook_rule_id, host_id);

-- ---------------------------------------------------------------------------
-- Scan coverage — what was actually SCANNED, not just what was found.
--
-- Under-enumeration is the top OSAI failure mode, and the world model could not
-- see it: a 1-1000 scan and a -p- scan produced identical host rows. Ingest now
-- records the run's port range / version-scan flag per host (from nmap's
-- <scaninfo> + run args), so `yhwach gaps` can name the hosts that were never
-- full-ported and the handoff can warn before the operator calls enum "done".
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_coverage (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES host(id),
    proto         TEXT    NOT NULL,              -- tcp | udp
    ports         TEXT    NOT NULL,              -- range as nmap reported it ('1-65535', '1-1000')
    port_count    INTEGER NOT NULL DEFAULT 0,    -- number of ports in that range
    full_range    INTEGER NOT NULL DEFAULT 0,    -- 1 when the whole 1-65535 space was covered
    version_scan  INTEGER NOT NULL DEFAULT 0,    -- 1 when the run carried -sV / -A
    source        TEXT,                          -- the nmap args line, when available
    scanned_at    TEXT    NOT NULL,
    UNIQUE(host_id, proto, ports)
);
CREATE INDEX IF NOT EXISTS idx_coverage_host ON scan_coverage(host_id, proto);
