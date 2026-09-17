"""MCP tool logic — pure functions returning text, independent of the MCP SDK.

These back the Yhwach MCP server (mcp_server.py) but carry no `mcp` dependency,
so they are unit-tested directly. Each takes a db path + args and returns a
string the operator's Claude reads. Yhwach never calls a model; `tool_next`
returns the persona-framed context block for the host to reason over.
"""
from __future__ import annotations

import os
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


def tool_engage(db_path: Path | str, lab: str, scope: str,
                domain: str | None = None, dc: str | None = None) -> str:
    """Initialise an engagement: create the DB if needed and upsert the engagement row.

    `scope` is a comma-separated list of IPs/CIDRs (validated). This is the entry
    point — call it before the other tools; they all resolve the same DB from the
    server's $YHWACH_DB."""
    from yhwach.scope import validate_scope

    bad = validate_scope(scope)
    if bad:
        raise ValueError(f"invalid scope token(s): {', '.join(bad)} — use IPs/CIDRs")
    path = Path(db_path)
    if not path.exists():
        yhdb.init(path)
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab=lab, scope=scope, domain=domain, dc_ip=dc)
    dom = f", domain {domain}" if domain else ""
    return f"engagement '{lab}' ready (id={eid}); scope {scope}{dom}"


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
            "WHERE f.engagement_id=? AND f.status='open' "
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


def tool_ingest(db_path: Path | str, lab: str, file: str, kind: str = "nmap",
                host: str | None = None) -> str:
    """Ingest a tool output FILE (on the operator host) into the world model.

    kind=nmap: nmap XML -> hosts + services. kind=linpeas|winpeas: privesc
    findings on `host` (advances it to 'enumerated'). kind=bloodhound: AD
    findings + chaining tags on `host` (the DC); no stage change. All set the
    `findings_include` chaining tags their parser detects."""
    from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if kind == "nmap":
            h, s = insert_hosts(conn, eid, parse_nmap_xml(file))
            yhdb.log_event(conn, eid, "ingest", {"kind": "nmap", "hosts": h, "services": s})
            return f"nmap ingested: {h} hosts, {s} services"
        if kind not in ("linpeas", "winpeas", "bloodhound", "certipy"):
            raise ValueError(
                f"unknown kind '{kind}' (use nmap|linpeas|winpeas|bloodhound|certipy)")
        if not host:
            raise ValueError(f"host is required for {kind}")
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                            (eid, host)).fetchone()
        if hrow is None:
            raise ValueError(f"host {host} not found — ingest an nmap scan first")
        text = Path(file).read_text(encoding="utf-8", errors="replace")
        note = ""
        if kind == "bloodhound":
            from yhwach.parsers.bloodhound import parse_bloodhound
            found = parse_bloodhound(text)
        elif kind == "certipy":
            from yhwach.parsers.adcs import parse_certipy
            found = parse_certipy(text)
        else:
            from yhwach.parsers.peas import parse_peas
            found = parse_peas(text, kind)
            yhdb.set_host_stage(conn, eid, host, "enumerated")
            note = "; host -> enumerated"
        for f in found:
            yhdb.add_finding(conn, hrow["id"], None, f.cls, f.title, f.severity, f.evidence,
                             tag=f.tag)
        yhdb.log_event(conn, eid, "ingest", {"kind": kind, "host": host, "findings": len(found)})
    tags = [f.tag for f in found if f.tag]
    extra = f"; tags: {', '.join(sorted(set(tags)))}" if tags else ""
    return f"{kind} on {host}: {len(found)} finding(s){note}{extra}"


def tool_enum(db_path: Path | str, lab: str, target: str, ports: str | None = None,
              hexstrike_url: str | None = None) -> str:
    """Run nmap through HexStrike and ingest the result (delegated enumeration)."""
    from yhwach.engine import artifact_dir
    from yhwach.hexstrike import DEFAULT_URL, HexStrikeClient, HexStrikeError, is_loopback
    from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml_text

    url = hexstrike_url or DEFAULT_URL
    client = HexStrikeClient(url)
    try:
        client.health()
    except Exception as e:  # noqa: BLE001 — surface as tool error text
        raise RuntimeError(f"HexStrike not reachable at {url}: {e}") from e
    try:
        xml = client.nmap_xml(target, ports=ports)
    except HexStrikeError as e:
        raise RuntimeError(str(e)) from e

    recon = artifact_dir(db_path, "recon")
    try:
        recon.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
        (recon / f"hexstrike_nmap_{safe}.xml").write_text(xml, encoding="utf-8")
    except OSError:
        pass  # best-effort; the ingest is what matters

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        h, s = insert_hosts(conn, eid, parse_nmap_xml_text(xml))
        yhdb.log_event(conn, eid, "enum",
                       {"target": target, "hosts": h, "services": s, "via": "hexstrike"})
    warn = "" if is_loopback(url) else f"  [OPSEC: {url} is not loopback]"
    return f"HexStrike nmap {target}: {h} hosts, {s} services ingested{warn}"


def tool_probe(db_path: Path | str, lab: str, host: str | None = None,
               timeout: float = 3.0) -> str:
    """Probe scanned hosts for AI + traditional attack surfaces; upsert them."""
    import json as _json

    from yhwach.probes import PROBES_BY_PORT, new_session, run_probes
    from yhwach.probes.traditional import detect_traditional

    session = new_session()
    found = 0
    new = 0
    lines: list[str] = []
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        services = yhdb.all_services_for_scanned_hosts(conn, eid)
        if host:
            services = [s for s in services if s["ip"] == host]
        for s in services:
            hits = []
            if s["port"] in PROBES_BY_PORT:
                ai = run_probes(session, s["ip"], s["port"], timeout=timeout)
                if ai:
                    hits.append(ai)
            trad = detect_traditional(session, s["ip"], s["port"], s["product"], timeout=timeout)
            if trad:
                hits.append(trad)
            for r in hits:
                _, created = yhdb.upsert_surface(
                    conn, host_id=s["host_id"], service_id=s["service_id"],
                    kind=r.kind, auth=r.auth, meta_json=_json.dumps(r.meta, sort_keys=True))
                found += 1
                new += 1 if created else 0
                lines.append(f"{s['ip']}:{s['port']} -> {r.kind} (auth={r.auth}) "
                             f"{'NEW' if created else 'UPD'}")
    head = f"{found} surfaces detected ({new} new)."
    return head + ("\n" + "\n".join(lines) if lines else "")


def tool_run(db_path: Path | str, lab: str, task_id: int, go: bool = False,
             hexstrike_url: str | None = None) -> str:
    """Render (and with go=True, execute read-only) a task's actions.

    Read-only/self-contained actions run and their output is captured + findings
    extracted; proposal/render-only actions are printed for the operator. With
    hexstrike_url, read-only actions run through HexStrike. Shares
    engine.execute_task with the CLI `run` command."""
    from yhwach.engine import execute_task

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
    lines, _ok = execute_task(db_path, eid, task_id, go=go, hexstrike_url=hexstrike_url)
    return "\n".join(lines)


def tool_proof(db_path: Path | str, lab: str, host: str, screenshot: str,
               flag: str | None = None, flag_content: str | None = None,
               advance: bool = True) -> str:
    """Bind a flag + screenshot to a host (evidence) and advance foothold -> looted.

    The screenshot file must exist — it is the evidence that gates 'looted'."""
    shot = Path(os.path.expanduser(screenshot))
    if not shot.is_file():
        raise ValueError(f"screenshot not found: {shot} — a proof needs a real screenshot")
    if flag_content is None and flag:
        fp = Path(os.path.expanduser(flag))
        if fp.is_file():
            flag_content = fp.read_text(encoding="utf-8", errors="replace").strip()
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                            (eid, host)).fetchone()
        if hrow is None:
            raise ValueError(f"host {host} not found")
        pid = yhdb.add_proof(conn, hrow["id"], flag or "-", str(shot), flag_content=flag_content)
        yhdb.log_event(conn, eid, "proof", {"host": host, "screenshot": str(shot)})
        msg = f"proof #{pid} recorded for {host}"
        if advance:
            adv, m = yhdb.set_host_stage(conn, eid, host, "looted")
            if adv:
                yhdb.log_event(conn, eid, "stage", {"host": host, "stage": "looted"})
                msg += "; host -> looted"
            else:
                msg += f"; stage unchanged ({m})"
    return msg


def tool_pivot(db_path: Path | str, lab: str, via_host: str, subnet: str,
               lport: int = 11601, advance: bool = True) -> str:
    """Record a pivot (subnet reachable via a host) and render the deploy commands.

    Unblocks the pivot host's looted -> pivoted transition. Uses the pre-staged
    obfuscated Ligolo agent for a Windows pivot, a stock agent otherwise."""
    from yhwach.engine import render_pivot

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        hrow = conn.execute("SELECT id, os FROM host WHERE engagement_id=? AND ip=?",
                            (eid, via_host)).fetchone()
        if hrow is None:
            raise ValueError(f"pivot host {via_host} not found")
        _, created = yhdb.add_tunnel(conn, eid, hrow["id"], subnet)
        yhdb.log_event(conn, eid, "tunnel", {"via": via_host, "subnet": subnet})
        msg = f"tunnel {'recorded' if created else 'already known'}: {subnet} via {via_host}"
        if advance:
            adv, m = yhdb.set_host_stage(conn, eid, via_host, "pivoted")
            if adv:
                yhdb.log_event(conn, eid, "stage", {"host": via_host, "stage": "pivoted"})
                msg += f"; {via_host} -> pivoted"
            else:
                msg += f"; stage unchanged ({m})"
        os_name = hrow["os"]
    lines = [msg, "== Deploy (propose — operator runs) =="]
    lines += render_pivot(via_host, subnet, os_name, lport=lport)
    return "\n".join(lines)


def tool_consume(db_path: Path | str, lab: str, technique: str,
                 host: str | None = None) -> str:
    """Mark a technique consumed — the planner stops proposing it this engagement."""
    from yhwach.primitives import mark_technique_consumed

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        host_id = None
        if host:
            r = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                             (eid, host)).fetchone()
            host_id = r["id"] if r else None
        mark_technique_consumed(conn, eid, technique, host_id)
    return f"technique '{technique}' consumed for '{lab}' — re-run plan to drop it"


# Registry of (name, fn, description) for the server to expose.
TOOL_SPECS = [
    ("yhwach_engage", tool_engage,
     "Initialise/resume a lab: create the DB and upsert the engagement (lab + scope "
     "[+ domain/dc]). Call this first; scope is validated as IPs/CIDRs."),
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
    ("yhwach_ingest", tool_ingest,
     "Ingest a tool-output file into the world model (kind=nmap|linpeas|winpeas; "
     "linpeas/winpeas need a host and set chaining tags)."),
    ("yhwach_enum", tool_enum,
     "Run nmap through HexStrike against a target and ingest the result (delegated enumeration)."),
    ("yhwach_probe", tool_probe,
     "Probe scanned hosts for AI + traditional attack surfaces and record them."),
    ("yhwach_run", tool_run,
     "Render a task's actions; with go=true, execute read-only ones and extract findings."),
    ("yhwach_proof", tool_proof,
     "Bind a flag + screenshot to a host as evidence and advance foothold -> looted."),
    ("yhwach_pivot", tool_pivot,
     "Record a pivot (subnet reachable via a host), render the Ligolo deploy, and advance "
     "the host looted -> pivoted."),
    ("yhwach_consume", tool_consume,
     "Mark a technique consumed so the planner stops proposing it this engagement."),
]
