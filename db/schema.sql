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
    host_id           INTEGER REFERENCES host(id),
    surface_id        INTEGER REFERENCES surface(id),
    class             TEXT    NOT NULL,   -- LLM01..LLM10 | CWE-... | CVE-... | ATLAS-...
    title             TEXT    NOT NULL,
    severity          TEXT    NOT NULL,   -- critical | high | medium | low
    evidence          TEXT,                -- one-line summary; never a raw dump
    playbook_rule_id  TEXT,
    status            TEXT    NOT NULL DEFAULT 'open',   -- open | exploited | dead | duplicate
    discovered_at     TEXT    NOT NULL,
    updated_at        TEXT
);

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
-- Notes — the engagement notebook. Every objective reached (FSM advance, loot,
-- finding, PoC) produces a note. Rendered to Obsidian-ready Markdown by notes.py.
-- Kapi's rule: take notes every time we reach the next objective — attack chain,
-- instructions, PoC, evidence, screenshot.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS note (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER NOT NULL REFERENCES engagement(id),
    host_id         INTEGER REFERENCES host(id),
    objective       TEXT    NOT NULL,   -- milestone slug: foothold | looted | pivoted | cve-2023-46604 | ...
    category        TEXT    NOT NULL,   -- attack_chain | instructions | poc | evidence | loot | recon | screenshot
    title           TEXT    NOT NULL,
    body            TEXT    NOT NULL DEFAULT '',  -- freeform Markdown
    command         TEXT,               -- exact reproducible command / payload (the PoC)
    output          TEXT,               -- captured evidence (trimmed)
    screenshot_path TEXT,               -- path to a screenshot / capture on disk
    tags            TEXT,               -- comma-separated Obsidian tags
    created_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_note_host ON note(engagement_id, host_id, created_at);
CREATE INDEX IF NOT EXISTS idx_note_objective ON note(engagement_id, objective);

-- ---------------------------------------------------------------------------
-- Event — append-only audit log. Drives the report and the replay/regression tests.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagement(id),
    ts             TEXT    NOT NULL,
    kind           TEXT    NOT NULL,      -- ingest | next | craft | interpret | action_run | finding | proof | heartbeat | override
    persona_hash   TEXT,                  -- content hash of persona at call time (for LLM events)
    rules_hash     TEXT,                  -- content hash of playbooks at call time
    payload_json   TEXT    NOT NULL
);

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
