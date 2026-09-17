"""MCP tool logic — pure functions returning text, independent of the MCP SDK.

These back the Yhwach MCP server (mcp_server.py) but carry no `mcp` dependency,
so they are unit-tested directly. Each takes a db path + args and returns a
string the operator's Claude reads. Yhwach never calls a model; `tool_next`
returns the persona-framed context block for the host to reason over.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.context import build_context
from yhwach.planner import match_rules
from yhwach.playbooks import default_playbook_dir, load_rules
from yhwach.report import build_report
from yhwach.spray import build_spray_plan


def _eng(conn, lab: str) -> int:
    eid = yhdb.engagement_id_for(conn, lab)
    if eid is None:
        raise ValueError(f"unknown lab '{lab}' — run engage first")
    return eid


def tool_status(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        stages = conn.execute(
            "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage ORDER BY stage",
            (eid,)).fetchall()
        svc = conn.execute(
            "SELECT COUNT(*) n FROM service s JOIN host h ON h.id=s.host_id WHERE h.engagement_id=?",
            (eid,)).fetchone()["n"]
        pend = conn.execute(
            "SELECT COUNT(*) n FROM task WHERE engagement_id=? AND status='pending'", (eid,)).fetchone()["n"]
        vault_rows = yhdb.list_credentials(conn, eid)
    lines = [f"Engagement '{lab}':"]
    lines += [f"  {r['stage']}: {r['n']}" for r in stages] or ["  (no hosts)"]
    lines.append(f"  services={svc}  pending_tasks={pend}  vault={len(vault_rows)}")
    if vault_rows:
        # Compact vault preview — identifier(kind); full secrets via yhwach_creds.
        preview = ", ".join(f"{r['identifier']}({r['kind']})" for r in vault_rows[:8])
        more = f" +{len(vault_rows) - 8} more" if len(vault_rows) > 8 else ""
        lines.append(f"  vault_ids: {preview}{more}")
    return "\n".join(lines)


def tool_plan(db_path: Path | str, lab: str) -> str:
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rep = match_rules(conn, eid, rules)
    msg = (f"rules matched {rep.rules_matched}; tasks {rep.tasks_created} new, "
           f"{rep.tasks_updated} updated")
    if rep.rules_skipped_consumed:
        msg += f"; skipped consumed: {', '.join(rep.rules_skipped_consumed)}"
    if rep.surfaces_filtered_denylist:
        msg += f"; filtered {rep.surfaces_filtered_denylist} denylisted surface(s)"
    return msg


def tool_next(db_path: Path | str, lab: str, limit: int = 4) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_context(conn, eid, limit=limit)


def tool_findings(db_path: Path | str, lab: str) -> str:
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 ELSE 3 END")
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rows = conn.execute(
            "SELECT f.class, f.title, f.severity, h.ip ip FROM finding f "
            "LEFT JOIN host h ON h.id=f.host_id "
            "WHERE (h.engagement_id=? OR f.host_id IS NULL) AND f.status='open' "
            f"ORDER BY {order}, f.id", (eid,)).fetchall()
    if not rows:
        return "no findings"
    return "\n".join(f"[{r['severity'].upper()}] {r['class']} {r['ip'] or '-'} {r['title']}"
                     for r in rows)


def tool_report(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_report(conn, eid)


def tool_spray(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        cmds = build_spray_plan(conn, eid)
    return "\n".join(cmds) if cmds else "nothing to spray (empty vault or no sprayable surfaces)"


def tool_add_cred(db_path: Path | str, lab: str, user: str, secret: str,
                  kind: str = "password", source: str = "operator",
                  source_host: str | None = None) -> str:
    """Store a credential in the vault.

    `user` is the login/identifier (username, key label, token id).
    `secret` is the plaintext, hash, or key material (raw SSH private key blob
    is fine — newlines are preserved by SQLite). `kind` picks the credential
    class (`password` | `ntlm` | `kerberos` | `ssh_key` | `api_key` | `token`
    | `dpapi`). `source_host`, if given, is the host IP where the cred was
    dumped and gets joined back on read. On update the `source` string is
    appended (not clobbered), so provenance survives re-discovery.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        source_host_id: int | None = None
        if source_host:
            row = conn.execute(
                "SELECT id FROM host WHERE engagement_id=? AND ip=?",
                (eid, source_host)).fetchone()
            source_host_id = int(row["id"]) if row else None
        _, created = yhdb.add_credential(
            conn, eid, user, secret, kind, source, source_host_id=source_host_id
        )
        yhdb.log_event(conn, eid, "credential",
                       {"id": user, "kind": kind, "source": source,
                        "source_host": source_host})
    return f"credential '{user}' ({kind}) {'added' if created else 'updated'}"


def tool_creds(db_path: Path | str, lab: str, kind: str | None = None) -> str:
    """Print the full credential vault — identifier, secret, kind, source, source_host.

    Every stored cred is returned in the clear: the vault is the operator's
    authoritative access ledger and spraying/reuse depends on it being
    directly readable. `kind`, if given, filters (`password` | `ntlm` |
    `ssh_key` | `api_key` | `token` | `dpapi` | `kerberos`).
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rows = yhdb.list_credentials(conn, eid, kind=kind)
    if not rows:
        return f"vault empty ({'kind=' + kind if kind else 'no filter'})"
    header = f"== Vault for '{lab}' ({len(rows)}{' ' + kind if kind else ''}) =="
    lines = [header,
             f"{'IDENTIFIER':<24} {'KIND':<10} {'SECRET':<40} SOURCE"]
    for r in rows:
        sec = r["secret"] or "(none)"
        # SSH keys / long tokens: keep one-line for the table, mark truncation.
        if "\n" in sec:
            sec = sec.split("\n", 1)[0][:36] + " …(multiline)"
        elif len(sec) > 38:
            sec = sec[:35] + "..."
        src = r["source"] or ""
        if r["source_host_ip"]:
            src = f"{src} @ {r['source_host_ip']}"
        lines.append(f"{r['identifier']:<24} {r['kind']:<10} {sec:<40} {src}")
    return "\n".join(lines)


def tool_advance(db_path: Path | str, lab: str, host: str, stage: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        changed, msg = yhdb.set_host_stage(conn, eid, host, stage)
        if changed:
            yhdb.log_event(conn, eid, "stage", {"host": host, "stage": stage})
    return f"{host} -> {stage}" if changed else f"refused: {msg}"


# Registry of (name, fn, description) for the server to expose.
TOOL_SPECS = [
    ("yhwach_status", tool_status, "Engagement scoreboard: hosts by stage, services, tasks, vault."),
    ("yhwach_plan", tool_plan, "Match playbooks against the world model; populate the task queue."),
    ("yhwach_next", tool_next, "The operator context block (persona + state + ranked candidates + commands)."),
    ("yhwach_findings", tool_findings, "Recorded findings, most severe first."),
    ("yhwach_report", tool_report, "Full Markdown engagement report."),
    ("yhwach_spray", tool_spray, "Credential-spray commands (vault creds x sprayable surfaces)."),
    ("yhwach_add_cred", tool_add_cred,
     "Add a credential to the vault (username/label + secret + kind + source; "
     "source is appended on update, never clobbered)."),
    ("yhwach_creds", tool_creds,
     "List the credential vault in full (identifier, secret, kind, source, source_host). "
     "Every access-granting artifact — passwords, hashes, SSH keys, API tokens — lives here. "
     "Query before attacking anything new."),
    ("yhwach_advance", tool_advance, "Advance a host's FSM stage (foothold/looted/pivoted/...)."),
]
