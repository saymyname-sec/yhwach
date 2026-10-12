"""MCP tool logic — pure functions returning text, independent of the MCP SDK.

These back the Yhwach MCP server (mcp_server.py) but carry no `mcp` dependency,
so they are unit-tested directly. Each takes a db path + args and returns a
string the operator's Claude reads. Yhwach never calls a model; `tool_next`
returns the persona-framed context block for the host to reason over.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import discovery as yhdisc
from yhwach.report import build_report


def _eng(conn, lab: str) -> int:
    eid = yhdb.engagement_id_for(conn, lab)
    if eid is None:
        raise ValueError(f"unknown lab '{lab}' — run engage first")
    return eid


def _assert_in_scope(conn, eid: int, target: str) -> None:
    """Refuse a traffic-sending action against an out-of-scope target.

    Uses the typed scope matcher (scope_entry rows, falling back to the legacy
    scope string). An engagement with no scope coverage refuses traffic.
    """
    from yhwach import scope as yhscope

    ok, reason = yhscope.assert_target(conn, eid, target)
    if not ok:
        raise ValueError(f"refusing to send traffic to {target}: {reason}")


def _env_autospray_off() -> bool:
    """Env hard-off: ``YHWACH_AUTOSPRAY=0`` disables every active path."""
    import os

    return os.environ.get("YHWACH_AUTOSPRAY", "1").strip().lower() in (
        "0", "off", "false", "no",
    )


def _armed(conn, eid: int) -> bool:
    """True when active traffic is allowed: engagement armed AND env not off."""
    if _env_autospray_off():
        return False
    return yhdb.engagement_armed(conn, eid)


def _assert_armed(conn, eid: int, action: str = "active tools") -> None:
    """Raise unless the engagement is armed (and the env kill switch is off).

    Arming is a deliberate terminal act (`yhwach arm`), never an MCP argument —
    so the model cannot turn traffic on; it can only ask the human to.
    """
    if _env_autospray_off():
        raise ValueError(f"{action} disabled by YHWACH_AUTOSPRAY=0")
    if not yhdb.engagement_armed(conn, eid):
        raise ValueError(
            f"engagement is record_only — {action} refused. Run `yhwach arm` "
            "in a terminal to enable active traffic for this engagement."
        )


def tool_engage(db_path: Path | str, lab: str, scope: str,
                domain: str | None = None, dc: str | None = None,
                kind: str | None = None, client: str | None = None) -> str:
    """Initialise an engagement: create the DB if needed and upsert the engagement row.

    `scope` is a comma-separated list of IPs, CIDRs, hostnames or wildcards
    (`*.example.com`), stored as typed scope_entry rows. `kind` picks the
    engagement profile (lab|ctf|internal|external|web|cloud|redteam|bounty|
    retest; default lab). Non-lab/ctf engagements start in record_only mode:
    recording facts never sends traffic until you run `yhwach arm` in a
    terminal. This is the entry point — call it before the other tools."""
    from yhwach import scope as yhscope

    bad = yhscope.validate_tokens(scope)
    if bad:
        raise ValueError(
            f"invalid scope token(s): {', '.join(bad)} — use IPs/CIDRs/hostnames/*.wildcards")
    path = Path(db_path)
    if not path.exists():
        yhdb.init(path)
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(
            conn, lab=lab, scope=scope, domain=domain, dc_ip=dc, kind=kind, client=client)
        yhscope.sync_from_string(conn, eid, scope, source="engage")
        # Materialise every scope IP as an ``undiscovered`` host so the UI /
        # brief / gaps see the FULL estate from turn one. Fixes the
        # "10 IPs, 2 in UI" bug that hid internal /24s until the operator
        # remembered to nmap each one. Networks bigger than /20 are skipped
        # by discovery.py and reported here so the operator can widen the
        # cap explicitly if they meant it.
        new_hosts, skipped = yhdisc.upsert_hosts_from_scope(
            conn, eid, scope, source="scope",
        )
    dom = f", domain {domain}" if domain else ""
    hosts_note = ""
    if new_hosts:
        hosts_note = f"; +{new_hosts} host(s) queued for scan"
    if skipped:
        hosts_note += f" (skipped: {'; '.join(skipped)})"
    mode = yhdb.default_active_mode(kind)
    mode_note = ""
    if mode == "record_only":
        mode_note = " · record_only (active tools disarmed — run `yhwach arm` in a terminal)"
    return (f"engagement '{lab}' ready (id={eid}); kind {kind or 'lab'}; "
            f"scope {scope}{dom}{hosts_note}{mode_note}")


def tool_status(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        stages = conn.execute(
            "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage ORDER BY stage",
            (eid,)).fetchall()
        svc = conn.execute(
            "SELECT COUNT(*) n FROM service s JOIN host h ON h.id=s.host_id WHERE h.engagement_id=?",
            (eid,)).fetchone()["n"]
        reach = dict(conn.execute(
            "SELECT COALESCE(alive,'unseen') a, COUNT(*) n FROM host WHERE engagement_id=? "
            "GROUP BY COALESCE(alive,'unseen')", (eid,)).fetchall())
        vault_rows = yhdb.list_credentials(conn, eid)
    lines = [f"Engagement '{lab}':"]
    lines += [f"  {r['stage']}: {r['n']}" for r in stages] or ["  (no hosts)"]
    if reach:
        lines.append("  reach: " + ", ".join(
            f"{k}={reach[k]}" for k in ("alive", "unanswered", "unseen") if reach.get(k)))
    lines.append(f"  services={svc}  vault={len(vault_rows)}")
    if vault_rows:
        # Compact vault preview — identifier(kind); full secrets via yhwach_creds.
        preview = ", ".join(f"{r['identifier']}({r['kind']})" for r in vault_rows[:8])
        more = f" +{len(vault_rows) - 8} more" if len(vault_rows) > 8 else ""
        lines.append(f"  vault_ids: {preview}{more}")
    return "\n".join(lines)


def tool_gaps(db_path: Path | str, lab: str, host: str | None = None) -> str:
    """Under-enumerated hosts + the exact scan that closes each gap.

    Derived from what the ingested nmap runs actually COVERED (port range,
    -sV, UDP), not what they found. A host is complete only with a full-port
    TCP scan, service versions and a UDP top-100 sweep — under-enumeration is
    the top scoring failure in engagements.
    """
    from yhwach.coverage import enum_gaps, render_gaps

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        found = enum_gaps(conn, eid, host_ip=host)
        # Also surface the scan_needed=1 queue — hosts that were discovered
        # (from scope expansion, cert SAN, evidence) but have never been
        # nmapped at all. These already appear in `found` above with the
        # "no scan coverage recorded" gap, but the pending count is what
        # answers "how many scans do I owe?" at a glance.
        pending = conn.execute(
            "SELECT COUNT(*) FROM host WHERE engagement_id=? AND scan_needed=1",
            (eid,),
        ).fetchone()[0]
    header = f"== Enumeration gaps for '{lab}' ({len(found)} host(s)) =="
    if pending:
        header += f"  [{pending} pending scan · yhwach_scan --pending]"
    return "\n".join([header, *render_gaps(found)])


def tool_next(db_path: Path | str, lab: str, host: str | None = None) -> str:
    """The recall menu + what you're about to miss — the 'what do I do next' move.

    Every technique that applies to the world model right now (grouped by host,
    split read-only vs. gated), fused with under-enumeration gaps, untried vault
    creds and uncaptured objectives. This is the deterministic menu the brain
    reasons FROM — yhwach recalls every applicable move so you never miss one; it
    ranks nothing. Pass host to scope to a single IP.
    """
    from yhwach import nextmoves as nm_

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        nm = nm_.next_moves(conn, eid, host_ip=host)
        body = nm_.render_next(nm)
    scope = f" host {host}" if host else ""
    header = (
        f"== Next moves for '{lab}'{scope} "
        f"({len(nm.auto)} read-only, {len(nm.gated)} gated) =="
    )
    if nm.pending_scan:
        header += f"  [{nm.pending_scan} pending scan · yhwach_scan]"
    return "\n".join([header, *body])


def tool_coverage(db_path: Path | str, lab: str, host: str | None = None) -> str:
    """World-model honesty: how thoroughly the hosts you've reached are enumerated.

    The completeness half of "check every path" — a host can be scanned and still
    under-enumerated (a discovered service never triaged). Returns a coverage score
    (started hosts fully enumerated) + each started host's remaining gaps with the
    exact command that closes them. `yhwach_gaps` shows the same for the WHOLE
    estate (incl. never-scanned hosts); this one scores what you've started.
    """
    from yhwach.coverage import coverage_score, render_gaps, started_gaps

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        cs = coverage_score(conn, eid)
        gaps = started_gaps(conn, eid, host_ip=host)
    scope = f" host {host}" if host else ""
    honesty = "n/a (no hosts reached yet)" if cs.pct is None else f"{cs.pct}%"
    header = (
        f"== Enumeration coverage for '{lab}'{scope} — honesty {honesty} "
        f"({cs.complete}/{cs.considered} started hosts fully enumerated) =="
    )
    if cs.pending_scan:
        header += f"  [{cs.pending_scan} pending scan · yhwach_scan]"
    return "\n".join([header, *render_gaps(gaps)])


def tool_objective(db_path: Path | str, lab: str, add: str | None = None,
                   capture: str | None = None, host: str | None = None,
                   points: int = 0, kind: str = "flag") -> str:
    """The engagement scoreboard — record flags/objectives + points and see pace to target.

    Call with `add` (a label; + optional host/points/kind) to record an objective,
    `capture` (a label) to mark one captured, or neither to just read the board.
    Engagements can be scored and timed; this tracks points/flags/pace.
    """
    from yhwach import scoreboard as sb_

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        msgs: list[str] = []
        if add:
            hid = None
            if host:
                hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                    (eid, host)).fetchone()
                if hrow is None:
                    raise ValueError(f"host {host} not found")
                hid = hrow["id"]
            yhdb.add_objective(conn, eid, add, host_id=hid, points=points, kind=kind)
            msgs.append(f"recorded objective '{add}'" + (f" ({points}pts)" if points else ""))
        if capture:
            n, m = yhdb.capture_objective(conn, eid, capture, host_ip=host)
            msgs.append(f"captured {n}: {capture}" if n else (m or "nothing captured"))
        body = sb_.render(conn, eid)
    header = f"== Scoreboard for '{lab}' =="
    return "\n".join([header, *([" ; ".join(msgs)] if msgs else []), *body])


def tool_audit(db_path: Path | str, lab: str) -> str:
    """Methodology audit: coverage BY standard (ATT&CK / ATLAS / OWASP-LLM / CWE /
    CVE) from classified findings, plus the paths NOT yet checked (service_enum /
    scan-coverage gaps). The 'what tactics did we exercise, and what did we skip?'
    self-assessment — a report-grade deliverable. Read-only."""
    from yhwach.audit import methodology_audit

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return methodology_audit(conn, eid)


def tool_brief(db_path: Path | str, lab: str, section: str | None = None,
               limit: int = 60, stage: str | None = None) -> str:
    """The AI-legible engagement map (REACH/HOLD/SURFACES/UNLOCKS/UNEXPLORED/OBJECTIVES).
    Read this to reason over the memory; yhwach decides nothing.

    `limit` caps each host/cred/surface list (default 60) so a large scope does
    not bury the map — a capped section prints a '+N more' footer naming the
    slice to ask for. `stage` filters REACH to one FSM stage (e.g. 'scanned')."""
    from yhwach.brief import build_brief
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_brief(conn, eid, section=section, limit=limit, stage=stage)


def tool_findings(db_path: Path | str, lab: str) -> str:
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 ELSE 3 END")
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rows = conn.execute(
            "SELECT f.class, f.title, f.severity, h.ip ip FROM finding f "
            "LEFT JOIN host h ON h.id=f.host_id "
            "WHERE f.engagement_id=? AND f.status IN ('open','confirmed','exploited') "
            f"ORDER BY {order}, f.id", (eid,)).fetchall()
    if not rows:
        return "no findings"
    return "\n".join(f"[{r['severity'].upper()}] {r['class']} {r['ip'] or '-'} {r['title']}"
                     for r in rows)


def tool_report_check(db_path: Path | str, lab: str) -> str:
    """Readiness gate (I13): is the memory reproducible enough to write up? Flags
    proven findings with no evidence, PoC steps with $VAR/TODO placeholders,
    secrets inline in evidence, uncommunicated criticals, and outstanding
    cleanup artefacts. FAIL items block; warn items are advisory.
    """
    from yhwach.report import report_check

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        problems = report_check(conn, eid)
    if not problems:
        return "report-ready: no readiness problems found."
    fails = sum(1 for lvl, _ in problems if lvl == "fail")
    lines = [f"readiness: {fails} blocking, {len(problems) - fails} advisory"]
    lines += [f"  [{'FAIL' if lvl == 'fail' else 'warn'}] {m}" for lvl, m in problems]
    return "\n".join(lines)


def tool_report(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_report(conn, eid)


def _parse_validated_on(spec: str) -> tuple[str, int | None, str | None]:
    """Parse a compact `validated_on` spec into (ip, port, proto).

    Accepts `IP`, `IP:PORT`, `IP/PROTO`, or `IP:PORT/PROTO`
    (e.g. `10.0.0.72:5985/winrm`). Missing parts come back None."""
    proto: str | None = None
    rest = spec.strip()
    if "/" in rest:
        rest, proto = rest.rsplit("/", 1)
        proto = proto.strip() or None
    ip = rest
    port: int | None = None
    if ":" in rest:
        ip, _, p = rest.rpartition(":")
        p = p.strip()
        if p.isdigit():
            port = int(p)
        else:  # not a port — treat the whole thing as the IP
            ip = rest
    return ip.strip(), port, proto


def tool_add_cred(db_path: Path | str, lab: str, user: str, secret: str,
                  kind: str = "password", source: str = "operator",
                  source_host: str | None = None,
                  validated_on: str | None = None, admin: bool = False,
                  provided: bool = False) -> str:
    """Store a credential in the vault.

    `user` is the login/identifier (username, key label, token id).
    `secret` is the plaintext, hash, or key material (raw SSH private key blob
    is fine — newlines are preserved by SQLite). `kind` picks the credential
    class (`password` | `ntlm` | `kerberos` | `ssh_key` | `api_key` | `token`
    | `dpapi`). `source_host`, if given, is the host IP where the cred was
    dumped and gets joined back on read. On update the `source` string is
    appended (not clobbered), so provenance survives re-discovery.

    `provided=True` marks a client-issued credential (an assumed-breach or test
    account). A provided cred is NEVER sprayed and is not counted as a
    compromise — it is the access you were given, kept distinct from what you
    captured.

    `validated_on` proves the cred against a host you already authenticated to,
    as `IP`, `IP:PORT`, `IP/PROTO`, or `IP:PORT/PROTO`
    (e.g. `10.0.0.72:5985/winrm`). Pass `admin=True` when that access is
    local/domain admin. This fills the Vault "opens" column and marks the cred
    validated instead of untried.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        source_host_id: int | None = None
        if source_host:
            # Auto-materialise the source host if it's the first we've heard
            # of it (in-scope) — an internal .60 that only ever appeared as a
            # cred's origin used to silently drop this id, so credentials had
            # no provenance link. observe_ip returns None if the IP is out of
            # scope; fall back to the legacy lookup so an operator can still
            # tag a host by hostname or an out-of-scope pivot IP.
            source_host_id = yhdisc.observe_ip(
                conn, eid, source_host, source="cred",
            )
            if source_host_id is None:
                row = conn.execute(
                    "SELECT id FROM host WHERE engagement_id=? AND ip=?",
                    (eid, source_host)).fetchone()
                source_host_id = int(row["id"]) if row else None
        cred_id, created = yhdb.add_credential(
            conn, eid, user, secret, kind, source, source_host_id=source_host_id,
            provenance="provided" if provided else None,
        )
        proven = ""
        if validated_on:
            ip, port, proto = _parse_validated_on(validated_on)
            # Auto-materialise the host if we've never seen it — matches the
            # add_finding / add_loot fix; a validated_on IP should NEVER be
            # silently dropped just because nothing else recorded that host
            # first. Falls back to a lookup for out-of-scope IPs.
            host_id = yhdisc.observe_ip(conn, eid, ip, source="cred_validated_on")
            if host_id is None:
                hrow = conn.execute(
                    "SELECT id FROM host WHERE engagement_id=? AND ip=?", (eid, ip)).fetchone()
                host_id = int(hrow["id"]) if hrow else None
            if host_id is None:
                proven = f" (validated_on host {ip} out of scope — skipped)"
            else:
                yhdb.mark_credential_validated(
                    conn, eid, cred_id, host_id, port=port, proto=proto,
                    service_kind=proto, result="admin" if admin else "success",
                    source=source,
                )
                proven = f" · opens {ip}" + (f":{port}" if port else "") + (
                    f"/{proto}" if proto else "") + (" (admin)" if admin else "")
        yhdb.log_event(conn, eid, "credential",
                       {"id": user, "kind": kind, "source": source,
                        "source_host": source_host, "validated_on": validated_on})
        # Auto-spray hook: every new/updated cred is immediately tried against
        # every existing service whose protocol matches its kind. Fixes the
        # symptom where a SQL SA cred sat in the vault untried
        # against the DB host:1433 for hours. Errors from missing tooling
        # (no nxc / no curl) are swallowed so the cred still records cleanly.
        spray_note = ""
        if not _armed(conn, eid):
            spray_note = (
                " (autospray off: record_only)" if not _env_autospray_off()
                else " (autospray off: YHWACH_AUTOSPRAY=0)"
            )
        else:
            try:
                from yhwach import sprayer as yhspray

                batch = yhspray.spray_cred(conn, eid, cred_id)
                if batch.hits or batch.admins:
                    bits = []
                    if batch.admins:
                        bits.append(f"{len(batch.admins)} admin")
                    new_hits = [h for h in batch.hits if "cached" not in h.detail]
                    if new_hits:
                        bits.append(f"{len(new_hits)} new hit(s)")
                    if bits:
                        spray_note = " · autospray: " + ", ".join(bits)
                        # Name the top hit so the operator sees the win inline.
                        top = batch.admins[0] if batch.admins else new_hits[0] if new_hits else None
                        if top is not None:
                            spray_note += f" [{top.ip}:{top.port}/{top.protocol}]"
            except Exception as exc:  # noqa: BLE001
                # Never let a broken adapter block a cred insert.
                spray_note = f" (autospray error: {type(exc).__name__})"
    return f"credential '{user}' ({kind}) {'added' if created else 'updated'}{proven}{spray_note}"


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


def tool_advance(db_path: Path | str, lab: str, host: str, stage: str,
                 why: str | None = None) -> str:
    """Advance a host's FSM stage. Monotonic; 'looted'/'pivoted' need proof/tunnel.

    `why` records what moved it — stored on the transition and shown in the host
    dossier. Without it the evidence for a stage change is unrecoverable.

    Advancing to 'enumerated' also reports any remaining scan coverage gaps —
    advisory, not a refusal, but calling a half-scanned host enumerated is how
    engagements lose points."""
    from yhwach.coverage import enum_gaps

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        changed, msg = yhdb.set_host_stage(conn, eid, host, stage, note=why)
        warn: list = []
        if changed:
            yhdb.log_event(conn, eid, "stage",
                           {"host": host, "stage": stage, "why": why})
            if stage == "enumerated":
                warn = enum_gaps(conn, eid, host_ip=host)
    if not changed:
        return f"refused: {msg}"
    out = f"{host} -> {stage}"
    if warn:
        out += f"\n[!] NOT fully enumerated: {warn[0].summary}"
        out += "".join(f"\n    $ {g.fix}" for g in warn[0].gaps)
    return out


def tool_ingest(db_path: Path | str, lab: str, file: str, kind: str = "nmap",
                host: str | None = None, url: str | None = None,
                server: str | None = None, tech: str | None = None,
                page_title: str | None = None, vhost: str | None = None) -> str:
    """Ingest a tool output FILE (on the operator host) into the world model.

    kind=nmap: hosts + services + software (CPE). kind=linpeas|winpeas: privesc
    findings + software on `host` (advances it to 'enumerated'). kind=bloodhound:
    AD findings + the principal/privilege/edge graph on `host` (the DC).
    kind=netexec: SMB shares, users, admin edges, password policy on `host`.
    kind=web: web_app + discovered paths (needs `url`). All set the
    `findings_include` chaining tags their parser detects."""
    from yhwach.parsers.nmap import insert_hosts, parse_nmap

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if kind == "nmap":
            from yhwach.coverage import enum_gaps
            from yhwach.parsers.nmap import parse_scan_meta

            nmap_text = Path(file).read_text(encoding="utf-8", errors="replace")
            meta = parse_scan_meta(nmap_text)
            parsed = parse_nmap(nmap_text)
            h, s = insert_hosts(conn, eid, parsed, meta)
            # An out-of-band full-range TCP pass (-p-) settles the scan debt for
            # the hosts it covered. UDP is additive and never clears it. (The
            # scanner clears its own quick/full runs by mode; this is for files
            # the operator ingests by hand.)
            if any(c.full_range and c.proto == "tcp" for c in meta.coverage):
                for ph in parsed:
                    conn.execute("UPDATE host SET scan_needed = 0 "
                                 "WHERE engagement_id = ? AND ip = ?", (eid, ph.ip))
            yhdb.log_event(conn, eid, "ingest", {"kind": "nmap", "hosts": h, "services": s})
            cov = ("ping sweep (no ports scanned)" if meta.ping_only
                   else "; ".join(f"{c.proto} {c.ports}" for c in meta.coverage) or "unknown")
            gaps = enum_gaps(conn, eid)
            tail = f"; {len(gaps)} host(s) under-enumerated (yhwach_gaps)" if gaps else ""
            # Auto-spray hook: for each host that just got new services, try
            # every vault cred against them. This is the "when a protocol
            # lets you connect, try every cred we know" behaviour the user
            # explicitly asked for. Restricted to the ingest's IPs to keep
            # each ingest bounded.
            spray_note = ""
            if not _armed(conn, eid):
                spray_note = (
                    "; autospray off (record_only)" if not _env_autospray_off()
                    else "; autospray off (YHWACH_AUTOSPRAY=0)"
                )
            else:
                try:
                    from yhwach import sprayer as yhspray

                    total_new = 0
                    total_admins = 0
                    for parsed_host in parsed:
                        b = yhspray.spray_all(conn, eid, host_ip=parsed_host.ip)
                        total_new += sum(1 for a in b.hits if "cached" not in a.detail)
                        total_admins += len(b.admins)
                    if total_new or total_admins:
                        spray_note = (
                            f"; autospray: {total_new} new hit(s), "
                            f"{total_admins} admin"
                        )
                except Exception as exc:  # noqa: BLE001
                    spray_note = f"; autospray error: {type(exc).__name__}"
            return f"nmap ingested: {h} hosts, {s} services; coverage {cov}{tail}{spray_note}"

        # Dumped secrets are domain-wide, not host-bound, and land in the vault
        # flagged spray_policy='manual' so they are NEVER auto-sprayed (G2c).
        if kind == "secretsdump":
            from yhwach.parsers.secrets import parse_secretsdump

            creds = parse_secretsdump(Path(file).read_text(encoding="utf-8", errors="replace"))
            src_host = _host_id_for(conn, eid, host)
            new = machines = empties = 0
            for c in creds:
                machines += c.is_machine
                empties += c.empty_password
                prow = conn.execute(
                    "SELECT id FROM principal WHERE engagement_id=? AND lower(name)=lower(?) "
                    "LIMIT 1", (eid, c.identifier)).fetchone()
                _cid, created = yhdb.add_credential(
                    conn, eid, c.identifier, c.nt_hash, "ntlm", "secretsdump",
                    source_host_id=src_host, provenance="discovered",
                    principal_id=int(prow["id"]) if prow else None, spray_policy="manual")
                new += created
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": "secretsdump", "hashes": len(creds), "new": new})
            from yhwach.reuse import derive_reuse_edges
            reuse = sum(derive_reuse_edges(conn, eid).values())
            reuse_note = f" {reuse} reuse edge(s) derived (yhwach_paths)." if reuse else ""
            return (f"secretsdump: {len(creds)} NT hash(es) ({machines} machine, "
                    f"{empties} empty-password), {new} new. spray_policy=manual — never "
                    f"auto-sprayed; crack offline, then ingest the potfile.{reuse_note}")

        if kind == "potfile":
            from yhwach.parsers.secrets import parse_potfile

            cracked = parse_potfile(Path(file).read_text(encoding="utf-8", errors="replace"))
            promoted = unmatched = 0
            for ch in cracked:
                rows = conn.execute(
                    "SELECT identifier, principal_id FROM credential WHERE engagement_id=? "
                    "AND kind='ntlm' AND lower(secret)=?", (eid, ch.nt_hash)).fetchall()
                if not rows:
                    unmatched += 1
                for r in rows:
                    yhdb.add_credential(
                        conn, eid, r["identifier"], ch.plaintext, "password", "cracked",
                        provenance="discovered", principal_id=r["principal_id"],
                        spray_policy="manual")
                    promoted += 1
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": "potfile", "cracked": len(cracked), "promoted": promoted})
            from yhwach.reuse import derive_reuse_edges
            reuse = sum(derive_reuse_edges(conn, eid).values())
            reuse_note = f" {reuse} reuse edge(s) derived." if reuse else ""
            return (f"potfile: {len(cracked)} cracked hash(es), {promoted} promoted to "
                    f"plaintext ({unmatched} not matching a dumped hash). "
                    f"spray_policy=manual.{reuse_note}")

        # Vuln-scanner exports are host-keyed by their own content (each row names
        # its host), so no `host` arg; info-severity rows are kept for coverage.
        if kind in ("nessus", "openvas"):
            from yhwach.parsers.nessus import parse_nessus, parse_openvas, promote_tag

            text = Path(file).read_text(encoding="utf-8", errors="replace")
            vulns = (parse_nessus if kind == "nessus" else parse_openvas)(text)
            rows = promoted = 0
            for v in vulns:
                if not v.host_ip:
                    continue
                hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                    (eid, v.host_ip)).fetchone()
                if hrow is None:
                    cur = conn.execute(
                        "INSERT INTO host (engagement_id, ip, stage, discovery_source, "
                        "alive, first_seen) VALUES (?, ?, 'scanned', ?, 'alive', ?)",
                        (eid, v.host_ip, kind, yhdb._now_utc()))
                    hid = int(cur.lastrowid)
                else:
                    hid = int(hrow["id"])
                yhdb.add_vulnerability(
                    conn, eid, hid, v.cves[0] if v.cves else None, title=v.title,
                    cvss=v.cvss, state="potential", source=kind, plugin_id=v.plugin_id,
                    port=v.port, solution=v.solution, plugin_output=v.output)
                rows += 1
                tag = promote_tag(v)
                if tag:
                    yhdb.add_finding(conn, hid, None, "scanner", v.title,
                                     v.severity if v.severity != "info" else "low",
                                     (v.output or v.title)[:200], tag=tag, engagement_id=eid)
                    promoted += 1
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": kind, "vulns": rows, "promoted": promoted})
            return (f"{kind}: {rows} vulnerability row(s) across hosts, {promoted} promoted "
                    f"to a chaining tag (smb_signing_off / exploitable_cve).")

        # nuclei JSONL -> potential vulnerabilities keyed on the template id; a
        # credential-category template's extracts are loot, never sprayable creds.
        if kind == "nuclei":
            from yhwach.parsers.nuclei import parse_nuclei

            findings = parse_nuclei(Path(file).read_text(encoding="utf-8", errors="replace"))
            rows = promoted = looted = 0
            for nf in findings:
                if not nf.host_ip:
                    continue
                hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                    (eid, nf.host_ip)).fetchone()
                if hrow is None:
                    cur = conn.execute(
                        "INSERT INTO host (engagement_id, ip, stage, discovery_source, "
                        "alive, first_seen) VALUES (?, ?, 'scanned', 'nuclei', 'alive', ?)",
                        (eid, nf.host_ip, yhdb._now_utc()))
                    hid = int(cur.lastrowid)
                else:
                    hid = int(hrow["id"])
                _vid, created = yhdb.add_vulnerability(
                    conn, eid, hid, nf.cves[0] if nf.cves else None, title=nf.name,
                    cvss=nf.cvss, state="potential", source="nuclei",
                    plugin_id=nf.template_id, port=nf.port,
                    plugin_output=("; ".join(nf.extracted)[:600] or None))
                rows += 1
                if created and nf.is_credential:
                    yhdb.add_loot(conn, eid, host_id=hid, type="nuclei_extract",
                                  contains_secret=True,
                                  summary=f"{nf.template_id}: {'; '.join(nf.extracted)[:140]}")
                    looted += 1
                if created and nf.promote_tag and nf.severity in ("critical", "high", "medium"):
                    yhdb.add_finding(conn, hid, None, "scanner", nf.name,
                                     nf.severity if nf.severity != "unknown" else "low",
                                     (nf.url or nf.name)[:200], tag=nf.promote_tag,
                                     engagement_id=eid)
                    promoted += 1
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": "nuclei", "vulns": rows, "promoted": promoted, "loot": looted})
            return (f"nuclei: {rows} potential vuln(s), {promoted} promoted to a chaining tag, "
                    f"{looted} credential extract(s) to loot.")

        # External recon: subdomain + web_app rows, scope-gated. Domain-keyed, so
        # NO spray hook fires; a CDN-fronted asset never gets a host row.
        if kind in ("httpx", "subfinder", "bbot"):
            from yhwach import scope as yhscope
            from yhwach.parsers.pd import parse_bbot, parse_httpx, parse_subfinder

            parser = {"httpx": parse_httpx, "subfinder": parse_subfinder,
                      "bbot": parse_bbot}[kind]
            assets = parser(Path(file).read_text(encoding="utf-8", errors="replace"))
            matcher = yhscope.build_matcher(conn, eid)
            domains = webapps = skipped = cdn_n = 0
            for a in assets:
                # Scope gate: the name (or its resolved IP) must be in scope.
                in_scope = matcher.allows(a.name)[0] or (bool(a.ip) and matcher.allows(a.ip)[0])
                if not in_scope:
                    skipped += 1
                    continue
                dtype = "subdomain" if a.name.count(".") >= 2 else "dns"
                yhdb.add_domain(conn, eid, a.name, type=dtype, ip=a.ip,
                                source=f"{a.source}{'/cdn:' + a.cdn_name if a.cdn and a.cdn_name else ''}")
                domains += 1
                if a.cdn:
                    cdn_n += 1
                    continue   # correction: never a host row for a CDN IP
                # The in-scope NAME authorises recording its resolved host — this
                # only records data; outbound traffic stays separately scope-gated.
                if a.url and a.ip:
                    hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                        (eid, a.ip)).fetchone()
                    if hrow is None:
                        cur = conn.execute(
                            "INSERT INTO host (engagement_id, ip, hostname, stage, "
                            "discovery_source, alive, first_seen) "
                            "VALUES (?, ?, ?, 'scanned', ?, 'alive', ?)",
                            (eid, a.ip, a.name, a.source, yhdb._now_utc()))
                        hid = int(cur.lastrowid)
                    else:
                        hid = int(hrow["id"])
                    base = a.url.split("?", 1)[0].rstrip("/")
                    yhdb.add_web_app(conn, hid, base, vhost=a.name,
                                     scheme=base.split("://", 1)[0] if "://" in base else None,
                                     title=a.title, server=a.server,
                                     tech=",".join(a.tech) or None)
                    webapps += 1
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": kind, "domains": domains, "web_apps": webapps,
                            "cdn": cdn_n, "out_of_scope": skipped})
            return (f"{kind}: {domains} in-scope domain(s), {webapps} web_app(s), "
                    f"{cdn_n} CDN-fronted (no host row), {skipped} out-of-scope skipped.")

        # Captured proxy traffic -> web_path METADATA (method/params/auth/status)
        # for requests whose host we already track. Bodies are NEVER stored here.
        if kind in ("burp", "har"):
            from yhwach.parsers.httpcap import parse_burp, parse_har

            reqs = (parse_burp if kind == "burp" else parse_har)(
                Path(file).read_text(encoding="utf-8", errors="replace"))
            paths = unresolved = 0
            app_cache: dict[tuple, int] = {}
            for rq in reqs:
                # Resolve the request's host to a tracked host: by captured IP,
                # then by hostname, then via the domain table. Never invent one.
                hid = None
                for sql, val in (
                    ("SELECT id FROM host WHERE engagement_id=? AND ip=?", rq.ip),
                    ("SELECT id FROM host WHERE engagement_id=? AND ip=?", rq.host),
                    ("SELECT id FROM host WHERE engagement_id=? AND LOWER(hostname)=LOWER(?)", rq.host),
                    ("SELECT host_id FROM domain WHERE engagement_id=? AND LOWER(name)=LOWER(?) "
                     "AND host_id IS NOT NULL", rq.host),
                ):
                    if not val:
                        continue
                    row = conn.execute(sql, (eid, val)).fetchone()
                    if row and row[0] is not None:
                        hid = int(row[0])
                        break
                if hid is None:
                    unresolved += 1
                    continue
                key = (hid, rq.base_url)
                if key not in app_cache:
                    wid, _ = yhdb.add_web_app(conn, hid, rq.base_url, scheme=rq.scheme)
                    app_cache[key] = wid
                yhdb.add_web_path(
                    conn, app_cache[key], rq.path, method=rq.method, status=rq.status,
                    params=",".join(rq.params) or None, auth_required=rq.auth_required,
                    source=kind)
                paths += 1
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": kind, "paths": paths, "unresolved_host": unresolved})
            return (f"{kind}: {paths} web_path(s) recorded (metadata only — no bodies), "
                    f"{unresolved} request(s) to untracked hosts skipped.")

        # Cloud / k8s enumeration -> findings on the cloud chaining tags + facts.
        # Engagement-level (host optional); no secret values are ever stored.
        if kind in ("kubectl", "aws"):
            from yhwach.parsers import cloud as yhcloud

            body = Path(file).read_text(encoding="utf-8", errors="replace")
            if kind == "aws":
                cres = yhcloud.parse_aws_sts(body)
            else:
                sub = yhcloud.detect_cloud_kind(body)
                cres = {"pods": yhcloud.parse_pods_json,
                        "secrets": yhcloud.parse_secrets_count,
                        "can_i": yhcloud.parse_can_i}.get(sub, yhcloud.parse_can_i)(body)
            hid = _host_id_for(conn, eid, host)
            for key, value in cres.facts.items():
                yhdb.add_domain_fact(conn, eid, key, value, source=kind)
            for f in cres.findings:
                yhdb.add_finding(conn, hid, None, f.cls, f.title, f.severity, f.evidence,
                                 tag=f.tag, engagement_id=eid)
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": kind, "findings": len(cres.findings),
                            "facts": len(cres.facts)})
            tnote = (" tags: " + ", ".join(sorted({f.tag for f in cres.findings if f.tag}))
                     if cres.findings else "")
            return (f"{kind}: {len(cres.findings)} finding(s), {len(cres.facts)} fact(s).{tnote}")

        # trivy -> vuln/software on a host; prowler FAILs -> attack-relevant
        # cloud findings (engagement-level). Compliance-matrix rows are dropped.
        if kind in ("trivy", "prowler"):
            from yhwach.parsers.cloudposture import parse_prowler, parse_trivy

            body = Path(file).read_text(encoding="utf-8", errors="replace")
            if kind == "trivy":
                if not host:
                    raise ValueError("kind=trivy needs a host (the node/image's host)")
                hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                    (eid, host)).fetchone()
                if hrow is None:
                    raise ValueError(f"host {host} not found — ingest a scan first")
                hid = int(hrow["id"])
                n = 0
                for v in parse_trivy(body):
                    yhdb.add_vulnerability(
                        conn, eid, hid, v.cve, title=v.title[:200],
                        state="confirmed", source="trivy",
                        plugin_id=f"trivy:{v.pkg}:{v.cve}",
                        solution=(f"upgrade {v.pkg} to {v.fixed}" if v.fixed else None),
                        exploit_available=False)
                    n += 1
                yhdb.log_event(conn, eid, "ingest", {"kind": "trivy", "vulns": n})
                return f"trivy: {n} vulnerability row(s) on {host}."
            findings = parse_prowler(body)
            for f in findings:
                yhdb.add_finding(conn, None, None, "cloud-posture",
                                 f"{f.title}" + (f" ({f.resource})" if f.resource else ""),
                                 f.severity, f"{f.check_id} [{f.service}]", tag=f.tag,
                                 location=f.resource or None, engagement_id=eid)
            yhdb.log_event(conn, eid, "ingest", {"kind": "prowler", "findings": len(findings)})
            tnote = (" tags: " + ", ".join(sorted({f.tag for f in findings}))) if findings else ""
            return (f"prowler: {len(findings)} attack-relevant FAIL(s) recorded "
                    f"(compliance noise dropped).{tnote}")

        # CI/CD scanner output -> gha_* tagged findings (engagement-level).
        if kind in ("sarif", "poutine"):
            from yhwach.parsers.cicd import parse_poutine, parse_sarif

            body = Path(file).read_text(encoding="utf-8", errors="replace")
            cf = (parse_sarif if kind == "sarif" else parse_poutine)(body)
            for f in cf:
                yhdb.add_finding(conn, None, None, "cicd",
                                 f"{f.tool}: {f.title}", f.severity,
                                 f"{f.rule} @ {f.path}" if f.path else f.rule,
                                 tag=f.tag, location=f.path or None, engagement_id=eid)
            yhdb.log_event(conn, eid, "ingest", {"kind": kind, "findings": len(cf)})
            tnote = (" tags: " + ", ".join(sorted({f.tag for f in cf}))) if cf else ""
            return f"{kind}: {len(cf)} CI/CD finding(s) recorded.{tnote}"

        # MCP server enumeration -> the I52 asset model. Tool-list drift between
        # probes is logged as an event (promoted to a finding only after review).
        if kind == "mcp":
            from yhwach.aisurface import DANGEROUS_SINKS
            from yhwach.parsers.mcp import parse_mcp

            if not host:
                raise ValueError("kind=mcp needs a host (the MCP server)")
            hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                (eid, host)).fetchone()
            if hrow is None:
                raise ValueError(f"host {host} not found — scan/probe it first")
            hid = int(hrow["id"])
            srow = conn.execute(
                "SELECT id FROM surface WHERE host_id=? AND kind='mcp' LIMIT 1", (hid,)).fetchone()
            sid = int(srow["id"]) if srow else None
            m = parse_mcp(Path(file).read_text(encoding="utf-8", errors="replace"))
            drift = []
            dangerous = 0
            for t in m.tools:
                _tid, _created, rugpulled = yhdb.add_ai_tool(
                    conn, eid, t["name"], surface_id=sid, description=t["description"])
                if rugpulled:
                    drift.append(t["name"])
                sk = conn.execute("SELECT sink FROM ai_tool WHERE engagement_id=? AND name=? "
                                  "AND surface_id IS ?", (eid, t["name"], sid)).fetchone()
                if sk and sk["sink"] in DANGEROUS_SINKS:
                    yhdb.add_finding(conn, hid, None, "LLM06",
                                     f"MCP tool reaches {sk['sink']}", "high",
                                     f"'{t['name']}' -> {sk['sink']} sink (excessive agency)",
                                     tag="excessive_agency", location=t["name"], engagement_id=eid)
                    dangerous += 1
            for r in m.resources:
                yhdb.add_ai_data_source(conn, eid, r["name"], surface_id=sid, kind="resource")
            if drift:
                yhdb.log_event(conn, eid, "mcp_drift",
                               {"host": host, "changed_tools": drift})
            yhdb.log_event(conn, eid, "ingest", {"kind": "mcp", "tools": len(m.tools),
                                                 "resources": len(m.resources),
                                                 "prompts": len(m.prompts)})
            drift_note = (f" ⚠ DRIFT: {len(drift)} tool desc changed ({', '.join(drift[:5])}) "
                          "— logged as an event, review before promoting to a finding"
                          if drift else "")
            return (f"mcp on {host}: {len(m.tools)} tool(s) ({dangerous} dangerous-sink), "
                    f"{len(m.resources)} resource(s), {len(m.prompts)} prompt(s).{drift_note}")

        valid = ("linpeas", "winpeas", "bloodhound", "certipy", "netexec", "web")
        if kind not in valid:
            raise ValueError(f"unknown kind '{kind}' (use nmap|{'|'.join(valid)})")
        if not host:
            raise ValueError(f"host is required for {kind}")
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                            (eid, host)).fetchone()
        if hrow is None:
            raise ValueError(f"host {host} not found — ingest an nmap scan first")
        text = Path(file).read_text(encoding="utf-8", errors="replace")

        if kind == "netexec":
            from yhwach.ingest import ingest_netexec
            summ = ingest_netexec(conn, eid, hrow["id"], text)
            yhdb.log_event(conn, eid, "ingest", {"kind": kind, "host": host, **summ})
            facts = f", {summ['domain_facts']} domain-fact(s)" if summ.get("domain_facts") else ""
            kerb = f", {summ['kerberos']} roastable hash(es)" if summ.get("kerberos") else ""
            return (f"netexec on {host}: {summ['shares']} share(s), {summ['principals']} user(s), "
                    f"{summ['admin']} admin{facts}{kerb}, {summ['findings']} finding(s)")
        if kind == "web":
            if not url:
                raise ValueError("url is required for kind=web")
            from yhwach.ingest import ingest_web
            summ = ingest_web(conn, hrow["id"], url, text, server=server, tech=tech,
                              title=page_title, vhost=vhost)
            yhdb.log_event(conn, eid, "ingest", {"kind": kind, "host": host, **summ})
            return (f"web on {url}: {summ['paths']} path(s), {summ['interesting']} interesting, "
                    f"{summ['with_params']} with params, {summ['auth_gated']} auth-gated")

        note = ""
        if kind == "bloodhound":
            from yhwach.ingest import ingest_bloodhound_graph
            from yhwach.parsers.bloodhound import parse_bloodhound
            found = parse_bloodhound(text)
            g = ingest_bloodhound_graph(conn, eid, text)
            from yhwach.entra import derive_entra_findings
            entra = sum(derive_entra_findings(conn, eid).values())
            note = (f"; graph: {g['principals']} principals, {g['privileges']} privs, "
                    f"{g['edges']} edges"
                    + (f"; {entra} hybrid-identity producer(s)" if entra else ""))
        elif kind == "certipy":
            from yhwach.parsers.adcs import parse_certipy
            found = parse_certipy(text)
        else:
            from yhwach.ingest import ingest_peas_software
            from yhwach.parsers.peas import parse_peas
            found = parse_peas(text, kind)
            sw = ingest_peas_software(conn, hrow["id"], text, kind)
            yhdb.set_host_stage(conn, eid, host, "enumerated",
                                note=f"ingest {kind}")
            note = f"; {sw} software row(s); host -> enumerated"
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
    from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml_text, parse_scan_meta

    url = hexstrike_url or DEFAULT_URL
    # Refuse if disarmed or out of scope before any HexStrike traffic — the MCP
    # enum path had no check at all (only the CLI did a scope check).
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        _assert_armed(conn, eid, "yhwach_enum")
        _assert_in_scope(conn, eid, target)
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
        h, s = insert_hosts(conn, eid, parse_nmap_xml_text(xml), parse_scan_meta(xml))
        yhdb.log_event(conn, eid, "enum",
                       {"target": target, "hosts": h, "services": s, "via": "hexstrike"})
    warn = "" if is_loopback(url) else f"  [OPSEC: {url} is not loopback]"
    return f"HexStrike nmap {target}: {h} hosts, {s} services ingested{warn}"


def tool_probe(db_path: Path | str, lab: str, host: str | None = None,
               timeout: float = 3.0) -> str:
    """Probe scanned hosts for AI + traditional attack surfaces; upsert them."""
    import json as _json

    from yhwach.probes import (
        PROBES_BY_PORT,
        new_session,
        run_probes,
        software_from_result,
    )
    from yhwach.probes.traditional import detect_traditional

    session = new_session()
    found = 0
    new = 0
    lines: list[str] = []
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        _assert_armed(conn, eid, "yhwach_probe")
        services = yhdb.all_services_for_scanned_hosts(conn, eid)
        if host:
            _assert_in_scope(conn, eid, host)
            services = [s for s in services if s["ip"] == host]
        else:
            # Sweep mode: never probe a host that drifted out of scope (typed
            # matcher — honors excludes and hostname/wildcard scopes).
            from yhwach import scope as yhscope

            services = [s for s in services
                        if yhscope.assert_target(conn, eid, s["ip"])[0]]
        for s in services:
            hits = []
            if s["port"] in PROBES_BY_PORT:
                ai = run_probes(
                    session, s["ip"], s["port"], timeout=timeout,
                    on_probe=lambda name, outcome, kind, _s=s: yhdb.record_probe_run(
                        conn, eid, _s["host_id"], _s["port"], name, outcome, kind=kind),
                )
                if ai:
                    hits.append(ai)
            trad = detect_traditional(session, s["ip"], s["port"], s["product"],
                                     proto=s.get("proto", "tcp"), timeout=timeout)
            # The traditional detector is a probe run too: without a row, a
            # service with no surface might have been swept and matched nothing,
            # or never been touched at all.
            yhdb.record_probe_run(
                conn, eid, s["host_id"], s["port"], "detect_traditional",
                "hit" if trad is not None else "miss",
                kind=trad.kind if trad is not None else None)
            if trad:
                hits.append(trad)
            for r in hits:
                _, created = yhdb.upsert_surface(
                    conn, host_id=s["host_id"], service_id=s["service_id"],
                    kind=r.kind, auth=r.auth, meta_json=_json.dumps(r.meta, sort_keys=True))
                found += 1
                new += 1 if created else 0
                sw = software_from_result(r)
                if sw is not None:
                    yhdb.add_software(
                        conn, s["host_id"], sw[0], sw[1],
                        service_id=s["service_id"], source="probe")
                lines.append(f"{s['ip']}:{s['port']} -> {r.kind} (auth={r.auth}) "
                             f"{'NEW' if created else 'UPD'}"
                             + (f" [sw: {sw[0]} {sw[1]}]" if sw else ""))
    head = f"{found} surfaces detected ({new} new)."
    return head + ("\n" + "\n".join(lines) if lines else "")


def tool_pivot(
    db_path: Path | str, lab: str, via_host: str, subnet: str,
    lport: int = 11601, advance: bool = True,
    kind: str | None = None, os_hint: str | None = None,
) -> str:
    """Record a pivot (subnet reachable via a host) and render the deploy commands.

    Unblocks the pivot host's ``looted -> pivoted`` transition. Uses CANONICAL
    absolute arsenal paths (:mod:`yhwach.arsenal`):

      * Windows targets  -> the arsenal ``svcmon.exe`` (obfuscated ligolo agent)
      * Linux targets    -> ``/usr/local/bin/chisel`` (reverse-SOCKS, no root needed)
                            or the arsenal ``ligolo-agent-linux`` with ``kind='ligolo'``.

    ``kind`` overrides the auto-pick (``chisel`` on Linux, ``ligolo`` on Windows).
    ``os_hint`` overrides the DB's recorded OS when it is missing or wrong.
    The recorded tunnel row carries ``kind`` + the arsenal key of the shipped
    binary so the DB remembers ground truth (``svcmon`` is Windows-only —
    the ``./agent`` line the previous docstring implied for Linux was a lie).
    """
    from yhwach import arsenal
    from yhwach.db import TUNNEL_KINDS
    from yhwach.engine import render_pivot

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        hrow = conn.execute("SELECT id, os FROM host WHERE engagement_id=? AND ip=?",
                            (eid, via_host)).fetchone()
        if hrow is None:
            raise ValueError(f"pivot host {via_host} not found")
        os_name = os_hint or hrow["os"]
        # Pick the tunnel kind from the operator hint, else the OS heuristic
        # (Linux -> chisel is the fast path; Windows -> ligolo via svcmon).
        resolved_kind = kind
        if resolved_kind is None:
            resolved_kind = "ligolo" if (os_name or "").lower().startswith("win") else "chisel"
        if resolved_kind not in TUNNEL_KINDS:
            raise ValueError(f"unknown pivot kind {resolved_kind!r}; expected {TUNNEL_KINDS}")

        # Record which arsenal binary this tunnel ships (canonical key, not path)
        # so a future audit can trace the actually-deployed binary from the DB.
        if resolved_kind == "chisel":
            agent_key = "CHISEL"
        elif (os_name or "").lower().startswith("win"):
            agent_key = "SVCMON_WIN"
        else:
            agent_key = "LIGOLO_AGENT_LINUX"

        _, created = yhdb.add_tunnel(
            conn, eid, hrow["id"], subnet,
            kind=resolved_kind, agent_path=agent_key,
        )
        yhdb.log_event(
            conn, eid, "tunnel",
            {"via": via_host, "subnet": subnet, "kind": resolved_kind, "agent": agent_key},
        )
        # Cleanup ledger (I39): the agent binary lands on the CLIENT host and must
        # be removed at close. The Kali-side proxy/listener is NOT a client
        # artefact, so it is never recorded. Only on first render to avoid dupes.
        if created:
            yhdb.add_artifact(
                conn, eid, kind="tunnel_agent",
                location=f"{agent_key} on {via_host}", host_id=hrow["id"],
                note=f"{resolved_kind} agent for tunnel to {subnet}; confirm removal at cleanup",
            )
        msg = (
            f"tunnel {'recorded' if created else 'already known'}: "
            f"{subnet} via {via_host} [kind={resolved_kind}, agent={agent_key}]"
        )
        if advance:
            adv, m = yhdb.set_host_stage(conn, eid, via_host, "pivoted",
                                         note=f"tunnel to {subnet}")
            if adv:
                yhdb.log_event(conn, eid, "stage", {"host": via_host, "stage": "pivoted"})
                msg += f"; {via_host} -> pivoted"
            else:
                msg += f"; stage unchanged ({m})"

    lines = [msg, "== Deploy (propose — operator runs) =="]
    lines += render_pivot(via_host, subnet, os_name, lport=lport, pivot_kind=resolved_kind)
    # Sanity: name the canonical arsenal binary in the response so an
    # operator scanning the tail sees exactly which file to ship.
    canonical_path = arsenal.get(agent_key).path
    lines.append(f"[canonical arsenal binary] {agent_key} = {canonical_path}")
    return "\n".join(lines)


def tool_ref(db_path: Path | str, pack: str, query: str | None = None) -> str:
    """Query a bundled reference knowledge pack (offline; db_path ignored).
    pack = default-creds | esc | gtfobins | lessons | services | tags | lolbas |
    wadcoms | arsenal | ai-attacks. `query` filters to matching entries."""
    from yhwach.reference import render_pack

    out = render_pack(pack, query)
    return out or f"no {pack} entries matching '{query}'"


def tool_vulns(db_path: Path | str, lab: str) -> str:
    """Match recorded software versions against the offline CVE knowledge base;
    record vulnerability rows + `exploitable_cve` findings. Offline/deterministic."""
    from yhwach.vulns import enrich

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        summ = enrich(conn, eid)
        yhdb.log_event(conn, eid, "vulns",
                       {"checked": summ["software_checked"], "matched": summ["matched"]})
    head = (f"checked {summ['software_checked']} software row(s): {summ['matched']} CVE "
            f"match(es), {summ['exploitable']} exploitable")
    return head + ("\n  " + "\n  ".join(summ["hits"]) if summ["hits"] else "")


def tool_recon(db_path: Path | str, lab: str, host: str) -> str:
    """Full recon picture for one host: services, software, vulns, web, shares,
    on-host privileges, loot, interfaces, findings — everything the world model
    holds. The 'note everything on this host' read."""
    from yhwach import notes

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                            (eid, host)).fetchone()
        if hrow is None:
            raise ValueError(f"host {host} not found")
        return notes.render_host_note(conn, hrow["id"])


def tool_path(db_path: Path | str, lab: str, src: str, dst: str = "Domain Admins") -> str:
    """Shortest attack-graph path between two nodes (owned -> objective).

    src/dst are names ('svc_sql', 'DC01', 'Domain Admins') or explicit
    'principal:<id>' / 'host:<id>'. Answers 'what's my route to DA from here?'."""
    from yhwach.cli import _fmt_path, _resolve_node

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        s = _resolve_node(conn, eid, src)
        d = _resolve_node(conn, eid, dst)
        if s is None:
            raise ValueError(f"could not resolve source '{src}'")
        if d is None:
            raise ValueError(f"could not resolve target '{dst}'")
        result = yhdb.shortest_path(conn, eid, s, d)
        if result is None:
            return (f"no known path {src} -> {dst}; enumerate more edges "
                    "(bloodhound/netexec) or it may not exist yet")
        return f"{src} -> {dst} ({len(result) - 1} hop(s)):\n  {_fmt_path(conn, result)}"


def tool_paths(db_path: Path | str, lab: str) -> str:
    """Shortest attack-graph path from what you OWN to EVERY objective / Domain Admins.

    Unlike yhwach_path (one hand-named pair), this derives the owned nodes
    (principals you hold creds for + owned hosts) and the targets (uncaptured
    objective hosts + the Domain/Enterprise Admins groups) and renders the shortest
    path to each. 'no known path yet' means enumerate more edges (bloodhound/netexec).
    Answers 'where do I stand relative to the crown?' in one call.
    """
    from yhwach import pathfind

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        found = pathfind.paths_to_objectives(conn, eid)
        lines = pathfind.render_objectives(conn, found)
    reach = sum(1 for p in found if p.reachable)
    header = f"== Paths to objectives for '{lab}' ({reach}/{len(found)} reachable) =="
    return "\n".join([header, *lines])


def tool_export_notes(db_path: Path | str, lab: str, out_dir: str | None = None) -> str:
    """Auto-scaffold the Obsidian notebook from the world model: standing notes
    (Services & Software, Vulnerabilities, Web, Users & Groups, Shares) + one per
    host, every table derived from the DB. Operator syncs the tree into the vault."""
    from yhwach import notes
    from yhwach.engine import artifact_dir

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        target = Path(out_dir) if out_dir else artifact_dir(db_path, "notes")
        written = notes.export_notes(conn, eid, target)
    return f"wrote {len(written)} note(s) to {target}:\n  " + "\n  ".join(written)


# Registry of (name, fn, description) for the server to expose.
def tool_add_finding(db_path: Path | str, lab: str, title: str, severity: str,
                     evidence: str, cls: str = "INFO", host: str | None = None,
                     tag: str | None = None, location: str | None = None) -> str:
    """Record an operator-confirmed finding/lead into the world model.

    For intel that has no deterministic extractor — a doc/wiki disclosure, a
    config leak, an auth-bypass lead, an enumerated username set — so it lands in
    the DB (and therefore the live board / report), not just the operator's head.
    `severity` is critical|high|medium|low|info; `cls` is the class label
    (LLM01.. | CWE-.. | CVE-.. | INFO). `host` is the IP it belongs to (omit for
    an engagement-wide finding). `tag` is the optional chaining key a rule's
    `findings_include` matches on — set it to unlock a follow-on technique.
    """
    sev = severity.strip().lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        return f"[yhwach error] severity must be critical|high|medium|low|info, got {severity!r}"
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        host_id: int | None = None
        surface_id: int | None = None
        if host:
            # Auto-materialise the host if it's in scope but not yet a row.
            # Fixes the pathology where findings tagged to internal .30/.55/.60
            # got mis-attributed to a pivot host or lost entirely
            # because the operator hadn't yet ingested those hosts. Out-of-
            # scope IPs still fail — keep that guard so we don't spam the DB
            # with typos.
            host_id = yhdisc.observe_ip(conn, eid, host, source="finding")
            if host_id is None:
                row = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                   (eid, host)).fetchone()
                if row is None:
                    return f"[yhwach error] host {host} out of scope for lab '{lab}'"
                host_id = int(row["id"])
        # Every IPv4 mentioned in the evidence body is a lead. Materialise
        # them too so a finding like "leaked config points to 198.51.100.55"
        # spawns that host row without a second tool call.
        yhdisc.observe_ips_in_text(conn, eid, evidence, source="finding_evidence")
        fid, created = yhdb.add_finding(
            conn, host_id, surface_id, cls, title, sev, evidence,
            tag=tag, engagement_id=eid, location=location)
        yhdb.log_event(conn, eid, "finding",
                       {"id": fid, "title": title, "severity": sev, "host": host, "tag": tag})
    where = f" on {host}" if host else ""
    chain = f" [tag: {tag}]" if tag else ""
    return f"finding #{fid} {'recorded' if created else 'updated'}{where}: [{sev}] {title}{chain}"


def tool_finding_set(db_path: Path | str, lab: str, finding_id: int,
                     status: str | None = None, severity: str | None = None,
                     evidence: str | None = None, reason: str = "") -> str:
    """Correct a finding: change its status, severity, or evidence.

    status is open | confirmed | exploited (live) | false_positive | duplicate |
    remediated | dead (closed — drops out of recall and the open register but
    stays queryable). A finding is never deleted; a wrong one is closed. Marking
    it also freezes it: a later parser re-ingest will not overwrite your edits.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        row = conn.execute("SELECT id FROM finding WHERE id=? AND engagement_id=?",
                           (finding_id, eid)).fetchone()
        if row is None:
            raise ValueError(f"no finding #{finding_id} in lab '{lab}'")
        old = yhdb.set_finding(conn, finding_id, status=status, severity=severity,
                               evidence=evidence, author="operator")
        yhdb.log_event(conn, eid, "finding_set",
                       {"id": finding_id, "from": old["status"], "to": status or old["status"],
                        "severity": severity, "reason": reason})
    parts = []
    if status:
        parts.append(f"status -> {status}")
    if severity:
        parts.append(f"severity -> {severity}")
    if evidence:
        parts.append("evidence updated")
    detail = ("; " + ", ".join(parts)) if parts else ""
    return f"finding #{finding_id} updated (from {old['status']}){detail}"


def tool_add_evidence(db_path: Path | str, lab: str, kind: str,
                      path: str | None = None, text: str | None = None,
                      finding: int | None = None, objective: str | None = None,
                      caption: str | None = None, contains_secret: bool = False) -> str:
    """Bind a proof artefact to a finding (or a PoC objective).

    kind is screenshot | request | response | output | file | log. Pass `path`
    to a saved file (hashed at record time; refused if missing/empty) OR `text`
    to store pasted output under the engagement workspace. One artefact can back
    several findings. The bytes stay on disk; the DB keeps a sha256 and the link,
    so `yhwach_query evidence` can answer 'does finding #N have proof?'.
    """
    from yhwach.engine import artifact_dir

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if finding is not None:
            row = conn.execute("SELECT id FROM finding WHERE id=? AND engagement_id=?",
                               (finding, eid)).fetchone()
            if row is None:
                raise ValueError(f"no finding #{finding} in lab '{lab}'")
        ev_id, created = yhdb.add_evidence(
            conn, eid, kind=kind, path=path, text=text, finding_id=finding,
            objective=objective, caption=caption, contains_secret=contains_secret,
            captured_by="operator", artifact_dir=artifact_dir(db_path, "evidence"))
        yhdb.log_event(conn, eid, "evidence",
                       {"id": ev_id, "kind": kind, "finding": finding, "objective": objective})
    bind = (f" -> finding #{finding}" if finding else "") + (f" -> {objective}" if objective else "")
    return f"evidence #{ev_id} ({kind}) {'recorded' if created else 'already stored'}{bind}"


def tool_add_loot(db_path: Path | str, lab: str, summary: str, host: str | None = None,
                  path: str | None = None, local_path: str | None = None,
                  type: str | None = None, contains_secret: bool = False) -> str:
    """Record a loot artifact (a file/key/dump recovered from a host) in the model.

    Closes the operator-as-brain gap where a recovered file had no MCP path into
    memory. `summary` is a one-line description; `host` the IP it came from; `path`
    the remote path where found; `local_path` where it was saved on Kali; `type`
    is config|key|db|source|dump|hash|note|binary; `contains_secret` flags that a
    credential should also be added to the vault (do that with yhwach_add_cred).
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        host_id: int | None = None
        if host:
            # Auto-materialise (same fix as add_finding) so a first-time-seen
            # internal host doesn't reject a loot record just because nmap
            # hasn't run on it yet.
            host_id = yhdisc.observe_ip(conn, eid, host, source="loot")
            if host_id is None:
                row = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                   (eid, host)).fetchone()
                if row is None:
                    return f"[yhwach error] host {host} out of scope for lab '{lab}'"
                host_id = int(row["id"])
        lid = yhdb.add_loot(conn, eid, host_id=host_id, path=path, local_path=local_path,
                            type=type, contains_secret=contains_secret, summary=summary)
        yhdb.log_event(conn, eid, "loot",
                       {"id": lid, "host": host, "path": path, "secret": contains_secret})
    where = f" on {host}" if host else ""
    sec = " [contains secret]" if contains_secret else ""
    return f"loot #{lid} recorded{where}: {summary}{sec}"


def tool_poc_step(db_path: Path | str, lab: str, objective: str, title: str,
                  command: str = "", output: str = "", script_content: str = "",
                  script_name: str = "", cve: str | None = None,
                  source: str | None = None, host: str | None = None,
                  finding: int | None = None) -> str:
    """Append one reproducible step to a PoC kill-chain (how to recreate it).

    `objective` groups steps into one chain (e.g. 'n8n-intake-rce'). Record the
    verbatim `command`, its `output` (key excerpt), and — for any exploit/payload
    — pass its `script_content` (+ `script_name`); it is saved verbatim into the
    engagement's scripts/ dir and referenced from the rendered chain. `cve`,
    `source` (exploit URL / arsenal path) and `host` feed the PoC / report standard.
    Call it for every step so `yhwach_poc` reproduces the whole chain.
    """
    from yhwach import poc as pocmod
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        script_path = None
        if script_content:
            script_path = str(pocmod.save_script(
                db_path, objective, script_name or "payload.txt", script_content))
        seq = pocmod.add_step(conn, eid, objective, title=title, command=command,
                              output=output, script_path=script_path, cve=cve,
                              source=source, host=host, finding_id=finding)
    tail = f" [script: {script_path}]" if script_path else ""
    return f"PoC '{pocmod.slug(objective)}' step #{seq} recorded: {title}{tail}"


def tool_poc(db_path: Path | str, lab: str, objective: str | None = None,
             redact: bool = False) -> str:
    """Render a reproducible PoC chain (chains/<objective>.md), or list objectives.

    With `objective`, returns the full copy-paste kill-chain (every command,
    output, script, CVE/source) and writes it to chains/<objective>.md. Without
    it, lists the recorded objectives and their step counts. `redact=True` returns
    the submission template — vault secrets masked to [REDACTED], safe to paste
    into a bounty/client report — and is not written to disk.
    """
    from yhwach import poc as pocmod
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if objective is None:
            objs = pocmod.list_objectives(conn, eid)
            if not objs:
                return "No PoC steps recorded yet. Use yhwach_poc_step."
            return "PoC objectives:\n" + "\n".join(f"  {lbl} ({n} step(s))" for lbl, n in objs)
        return pocmod.render_poc(conn, eid, objective, lab=lab, write=not redact,
                                 db_path=db_path, redact=redact)


def tool_set_host(db_path: Path | str, lab: str, host: str,
                  hostname: str | None = None, os: str | None = None,
                  role: str | None = None) -> str:
    """Name/classify a host: set its `hostname` (DC01), `os` (windows/linux), and
    `role` — what it mainly hosts (Domain Controller | Jenkins CI | ActiveMQ
    broker | File server | AI - IT Service Desk | Workstation | Printer). Only
    the fields you pass are changed. Feeds the board/map labels."""
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        # Auto-materialise before applying operator-supplied metadata: naming
        # a box is a first-class discovery signal ("this .60 is DC01"), we
        # shouldn't reject it just because nmap hasn't landed yet.
        yhdisc.observe_ip(conn, eid, host, source="set_host", hostname=hostname)
        if not yhdb.set_host_meta(conn, eid, host, hostname=hostname, os=os, role=role):
            return f"[yhwach error] host {host} out of scope for lab '{lab}'"
        yhdb.log_event(conn, eid, "host_set",
                       {"host": host, "hostname": hostname, "os": os, "role": role})
    bits = ", ".join(f"{k}={v}" for k, v in
                     (("hostname", hostname), ("os", os), ("role", role)) if v)
    return f"host {host} updated ({bits})"


def tool_add_interface(db_path: Path | str, lab: str, host: str, ip: str,
                       segment: str | None = None, mac: str | None = None,
                       primary: bool = False) -> str:
    """Record an additional network interface/IP on a host — how yhwach learns a
    box is DUAL-HOMED (e.g. a DMZ host with a second NIC into an internal
    subnet). `segment` is the subnet/label (10.0.0.0/24). Dual-homing is the
    basis of the pivot tree on the map."""
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        # Auto-materialise: recording a second interface on a host we haven't
        # nmapped yet is still a valid signal (pivot mapping) — don't reject.
        yhdisc.observe_ip(conn, eid, host, source="add_interface")
        # Also observe the additional interface itself; a dual-homed host's
        # second IP is often the next scan target on its own subnet.
        yhdisc.observe_ip(conn, eid, ip, source="add_interface")
        row = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                           (eid, host)).fetchone()
        if row is None:
            return f"[yhwach error] host {host} out of scope for lab '{lab}'"
        _, created = yhdb.add_host_interface(
            conn, int(row["id"]), ip, mac=mac, segment=segment,
            is_primary=primary, source="operator")
        yhdb.log_event(conn, eid, "interface",
                       {"host": host, "ip": ip, "segment": segment})
    seg = f" on {segment}" if segment else ""
    return f"interface {ip}{seg} recorded for {host} ({'added' if created else 'updated'})"


def tool_tag(db_path: Path | str, lab: str, host: str, tag: str,
             note: str | None = None) -> str:
    """Tag a host with a free-form label (orthogonal to its FSM stage): e.g.
    windows | linux | dc | adcs-ca | jenkins | ai-target | ai-exploited |
    domain-admin | creds-here | loot-here | pivot-point | dual-homed | tier0 |
    objective | dead-end | gated | blocked | persistence-installed. Deduped."""
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        # Auto-materialise: tagging a host is another form of discovery
        # ("mark .60 as dc"), don't reject the tag just because nmap hasn't
        # created the row yet.
        yhdisc.observe_ip(conn, eid, host, source="tag")
        ok, msg = yhdb.add_host_tag(conn, eid, host, tag, note=note)
        if not ok:
            return f"[yhwach error] {msg}"
        yhdb.log_event(conn, eid, "host_tag", {"host": host, "tag": tag.strip().lower()})
    return f"tagged {host}: {tag.strip().lower()}"


def tool_untag(db_path: Path | str, lab: str, host: str, tag: str) -> str:
    """Remove a free-form tag from a host."""
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        removed = yhdb.remove_host_tag(conn, eid, host, tag)
    return f"{'removed' if removed else 'no such tag on'} {host}: {tag.strip().lower()}"


def tool_spray(db_path: Path | str, lab: str,
               host: str | None = None, protocol: str | None = None,
               cred: str | None = None, force: bool = False,
               dry_run: bool = False) -> str:
    """Spray the credential vault against reachable services.

    The full matrix by default (every cred × every service whose protocol
    it can speak — ssh, smb, winrm, ldap/ldaps, mssql, rdp, ftp, http-basic).
    Filters:
      * ``host``     — only that IP.
      * ``protocol`` — only that adapter (ssh|smb|winrm|ldap|mssql|rdp|...).
      * ``cred``     — only that credential's identifier.
      * ``force``    — reattempt (cred, service) pairs already recorded in
                       credential_access, otherwise cached results are used.
      * ``dry_run``  — plan only, no adapter calls.

    Results (success/fail) are written to ``credential_access`` so the same
    pair is never retried — that's the source of truth the vault matrix
    reads. This tool is also invoked automatically on every add_cred and
    every new service from an nmap ingest, so most operators never need to
    call it explicitly.
    """
    from yhwach import sprayer as yhspray

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if not dry_run:
            _assert_armed(conn, eid, "yhwach_spray")
            if host:
                _assert_in_scope(conn, eid, host)
        cred_id: int | None = None
        if cred is not None:
            row = conn.execute(
                "SELECT id FROM credential WHERE engagement_id=? AND identifier=?",
                (eid, cred),
            ).fetchone()
            if row is None:
                return f"[yhwach error] credential '{cred}' not in vault"
            cred_id = int(row["id"])
        if cred_id is not None:
            batch = yhspray.spray_cred(
                conn, eid, cred_id, host_ip=host, protocol=protocol,
                dry_run=dry_run, force=force,
            )
        else:
            batch = yhspray.spray_all(
                conn, eid, host_ip=host, protocol=protocol,
                dry_run=dry_run, force=force,
            )
    lines = [batch.summarize()]
    for r in batch.admins + [h for h in batch.hits if h not in batch.admins]:
        badge = "ADMIN" if r.result == "admin" else "OK"
        lines.append(f"  [{badge}] {r.identifier} -> {r.ip}:{r.port}/{r.protocol}  {r.detail}")
    if len(lines) == 1 and batch.attempts:
        lines.append("  (no positive auths; see yhwach_creds for the vault matrix)")
    return "\n".join(lines)


def tool_derive(db_path: Path | str, lab: str,
                spray: bool = False, targets: str | None = None) -> str:
    """Derive credential candidates from vault patterns (see yhwach.patterns).

    Reads the existing vault, extracts naming templates (year tokens, role
    tokens, prefix leetspeak, suffix tails like '#Acme2025'), and generates
    high-probability candidates for common service accounts (sa, svc_sql,
    svc_backup, ...). NOT a brute — it emits ~5 candidates per
    known pattern, not a wordlist.

    Without ``spray=True`` this only PRINTS the suggestions so the operator
    can review them. With ``spray=True``, each candidate is inserted into
    the vault as a normal cred, which triggers the add_cred autospray hook
    (PR-3) — the sprayer's per-service backoff protects the estate.

    ``targets``, if given, is a comma-separated list of usernames to
    generate FOR (defaults to the built-in service-user list).
    """
    from yhwach import db as yhdb
    from yhwach import patterns as pat

    target_list: list[str] | None = None
    if targets:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rows = yhdb.list_credentials(conn, eid)
        candidates = pat.derive_candidates(rows, targets=target_list)
        if not candidates:
            return "derive: no candidates (vault empty or no patterns detected)"
        if spray:
            added = 0
            for c in candidates:
                _, created = yhdb.add_credential(
                    conn, eid, c.username, c.password,
                    kind="password",
                    source=f"pattern-derive from '{c.source_cred}' ({c.reason})",
                )
                if created:
                    added += 1
            # Let the operator manually run yhwach_spray if they want the
            # autospray to fire for these — the add_cred hook still runs
            # inside this transaction (spray_cred is called per-cred by
            # yhdb.add_credential's caller path via tool_add_cred; but here
            # we insert directly for speed, so tell the operator).
            return (
                f"derive: {len(candidates)} candidate(s), {added} added to vault. "
                "Run yhwach_spray to try them."
            )
    lines = [f"derive: {len(candidates)} candidate(s) (dry-run — pass spray=True to enqueue)"]
    for c in candidates:
        lines.append(f"  {c.username:<20} {c.password:<30}  ← {c.source_cred}  [{c.reason}]")
    return "\n".join(lines)


def tool_scan(db_path: Path | str, lab: str,
              host: str | None = None, mode: str = "full",
              max_hosts: int = 8) -> str:
    """Run nmap against hosts + ingest the result — the "always full-scan"
    fix (see yhwach.scanner).

    Modes:
      * ``quick`` — ``-sV -sC --top-ports 1000`` (fast baseline).
      * ``full``  — ``-sV -sC -p-`` (the "no missed ports" guarantee).
      * ``udp``   — ``-sU --top-ports 100`` (the other coverage floor).

    Args:
      * ``host``       — one IP to scan. Omit to drain the queue.
      * ``max_hosts``  — cap on queue mode (default 8). Ignored with ``host``.

    Every scan ingests through the same code path as ``yhwach_ingest`` so
    the sprayer's per-new-service hook fires for new services. Successful
    quick/full scans flip ``scan_needed=0`` on the host so ``yhwach_gaps``
    stops flagging it. Results land in <workspace>/recon/<ip>_<mode>.xml
    for later re-ingest.
    """
    from yhwach import scanner as yhscan

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        _assert_armed(conn, eid, "yhwach_scan")
        if host:
            # Explicit target: run even if scan_needed=0 (the operator asked).
            # Refuse an out-of-scope target before sending a packet, then
            # auto-materialise the host — same policy as add_finding.
            _assert_in_scope(conn, eid, host)
            yhdisc.observe_ip(conn, eid, host, source="scan")
            results = [yhscan.scan_host(conn, eid, host, mode=mode)]
        else:
            results = yhscan.scan_pending(conn, eid, max_hosts=max_hosts, mode=mode)
    if not results:
        return f"scan: nothing pending (queue empty for lab '{lab}')"
    lines = [f"scan {mode}: {len(results)} host(s)"]
    for r in results:
        badge = "OK " if r.success else "FAIL"
        stat = (f"+{r.hosts_ingested}h/{r.services_ingested}s" if r.success
                else r.detail)
        lines.append(f"  [{badge}] {r.ip:<18} {stat}")
    return "\n".join(lines)


def tool_dossier(db_path: Path | str, lab: str, host: str) -> str:
    """The per-host briefing the operator sees on the live board.

    Composed entirely from the world model and the shipped knowledge packs — no
    model is called to produce it. Read this before annotating, so what you add
    sits beside exactly what the operator is looking at.
    """
    from yhwach import dossier

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        md = dossier.build(conn, eid, host)
        notes = []
        row = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                           (eid, host)).fetchone()
        if row:
            for a in yhdb.host_annotations(conn, int(row["id"])):
                flag = " (STALE — written at an earlier state of this host)" if a["stale"] else ""
                notes.append(f"\n## {a['section']} — annotation by "
                             f"{a['author'] or 'unknown'}{flag}\n{a['body']}")
    if not md:
        return f"[yhwach error] no host {host} in '{lab}'"
    return md + "".join(notes)


def tool_annotate(db_path: Path | str, lab: str, host: str, section: str, text: str) -> str:
    """Attach a short written note about a host to the world model.

    DESCRIPTION, NOT DIRECTION. Say what something IS or what a piece of raw
    output MEANS on this box — "the banner is ActiveMQ 5.17.4 behind a proxy that
    strips /admin", "this evidence blob is a truncated NTDS dump". Do NOT write
    what to do next: the operator does not want the UI recommending moves, and an
    annotation that says "next, try X" rebuilds that recommender in prose.

    Call `yhwach_dossier` first so the note sits beside what the operator sees.
    One note per (host, stage, section); re-annotating the same section replaces
    it. The note is stamped with the world-model state it was written against and
    is shown dimmed and labelled once that state moves on.
    """
    body = (text or "").strip()
    if not body:
        return "[yhwach error] text is required"
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        row = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                           (eid, host)).fetchone()
        if row is None:
            return f"[yhwach error] no host {host} in '{lab}'"
        fp = yhdb.add_host_annotation(conn, int(row["id"]), section.strip() or "note",
                                      body, author="claude-code")
        yhdb.log_event(conn, eid, "host_annotated",
                       {"host": host, "section": section, "chars": len(body)})
    return f"annotated {host} [{section}] ({len(body)} chars, state {fp[:8]})"


def tool_scope(db_path: Path | str, lab: str, action: str = "list",
               target: str | None = None, note: str | None = None) -> str:
    """Manage the typed engagement scope (no traffic — this is memory).

    action:
      * ``list``    — show include and exclude entries.
      * ``add``     — add an in-scope token (ip | cidr | hostname | *.wildcard).
      * ``exclude`` — add an out-of-scope token (exclude always wins).
      * ``remove``  — soft-delete the matching include token.
      * ``check``   — report whether `target` is in scope (and why).

    Empty scope means no target is in scope, so the traffic tools refuse until
    something is added.
    """
    from yhwach import scope as yhscope

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if action in ("add", "exclude"):
            if not target:
                raise ValueError(f"target required for scope {action}")
            _, kind = yhscope.add_scope_entry(
                conn, eid, target, include=(action == "add"), source="operator", note=note)
            return f"scope {action}: {kind} {target}"
        if action == "remove":
            if not target:
                raise ValueError("target required for scope remove")
            n = yhscope.remove_scope_entry(conn, eid, target, include=True)
            return f"scope remove: {target} ({n} row(s))"
        if action == "check":
            if not target:
                raise ValueError("target required for scope check")
            ok, reason = yhscope.assert_target(conn, eid, target)
            return f"{target}: {'IN SCOPE' if ok else 'OUT OF SCOPE'}" + (f" — {reason}" if reason else "")
        # list
        rows = yhscope.list_scope_entries(conn, eid)
        if not rows:
            return "scope: (empty — traffic tools are refused until a target is added)"
        inc = [f"{r['kind']}:{r['value']}" for r in rows if r["include"]]
        exc = [f"{r['kind']}:{r['value']}" for r in rows if not r["include"]]
        out = [f"in-scope ({len(inc)}): " + (", ".join(inc) or "none")]
        if exc:
            out.append(f"excluded ({len(exc)}): " + ", ".join(exc))
        return "\n".join(out)


def _candidate_ids(db_path: Path | str, lab: str, host: str | None) -> set[str]:
    """(technique_id) set currently applicable to `host` — for the unlocked diff."""
    if not host:
        return set()
    from yhwach import knowledge as kn

    try:
        with yhdb.transaction(db_path) as conn:
            eid = _eng(conn, lab)
            return {c.technique_id for c in kn.candidates_for(conn, eid, host_ip=host)}
    except Exception:  # noqa: BLE001 — the diff is advisory, never fatal
        return set()


_INTERPRET_PARSERS = ("nmap", "netexec", "bloodhound", "certipy", "linpeas", "winpeas",
                      "web", "secretsdump", "potfile", "nessus", "openvas", "nuclei",
                      "httpx", "subfinder", "bbot", "burp", "har", "kubectl", "aws",
                      "trivy", "prowler", "sarif", "poutine", "mcp")


def tool_interpret(db_path: Path | str, lab: str, text: str, kind: str = "auto",
                   host: str | None = None, url: str | None = None,
                   title: str | None = None, dry_run: bool = False) -> str:
    """Turn pasted tool output into typed rows — the single text entry point.

    `kind='auto'` sniffs the output (nmap, netexec, secretsdump, potfile, bloodhound,
    certipy, linpeas, winpeas, web) and ingests it the same way `yhwach_ingest` would, but from
    text you paste rather than a file on the server. Name `kind='x:<action_id>'`
    to run one of the deterministic interpret extractors on the text. Anything
    unrecognised is stored as loot plus an INFO finding so nothing is lost.
    When `host` is given, the result names which recall rules the new facts
    UNLOCKED. `dry_run=True` classifies without writing.
    """
    from yhwach import sniff
    from yhwach.engine import artifact_dir

    if kind == "auto":
        kind = sniff.detect(text)

    # Deterministic extractor by action id (exposes interpret.* over the wire).
    if kind.startswith("x:"):
        from yhwach.interpret import _EXTRACTORS, interpret_all

        action_id = kind[2:]
        if action_id not in _EXTRACTORS:
            import difflib

            near = difflib.get_close_matches(action_id, list(_EXTRACTORS), n=3)
            hint = f" (did you mean: {', '.join(near)}?)" if near else ""
            raise ValueError(
                f"unknown extractor id '{action_id}'{hint} — use kind='auto' to sniff, "
                "or a parser kind. The pasted text was NOT recorded.")
        findings = interpret_all(action_id, text, {"IP": host, "URL": url})
        tags = sorted({f.tag for f in findings if f.tag})
        if dry_run:
            return (f"dry_run: extractor {action_id} would write {len(findings)} "
                    f"finding(s)" + (f" [tags: {', '.join(tags)}]" if tags else ""))
        before = _candidate_ids(db_path, lab, host)
        with yhdb.transaction(db_path) as conn:
            eid = _eng(conn, lab)
            host_id = yhdisc.observe_ip(conn, eid, host, source="interpret") if host else None
            if host_id is None and host:
                hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                    (eid, host)).fetchone()
                host_id = int(hrow["id"]) if hrow else None
            for f in findings:
                yhdb.add_finding(conn, host_id, None, f.cls, f.title, f.severity,
                                 f.evidence, tag=f.tag, engagement_id=eid)
            yhdb.log_event(conn, eid, "ingest",
                           {"kind": f"interpret:{action_id}", "host": host,
                            "findings": len(findings)})
        unlocked = sorted(_candidate_ids(db_path, lab, host) - before)
        ext = f" [tags: {', '.join(tags)}]" if tags else ""
        unl = f"; unlocked: {', '.join(unlocked)}" if unlocked else ""
        return f"interpret {action_id}: {len(findings)} finding(s){ext}{unl}"

    # Known file-parser kinds — reuse the tested ingest path via a temp file.
    if kind in _INTERPRET_PARSERS:
        if dry_run:
            return f"dry_run: classified as {kind} ({text.count(chr(10)) + 1} lines) — would ingest"
        before = _candidate_ids(db_path, lab, host)
        loot = artifact_dir(db_path, "loot")
        loot.mkdir(parents=True, exist_ok=True)
        ext = {"nmap": "xml", "bloodhound": "json", "certipy": "json", "web": "txt"}.get(kind, "txt")
        tmp = loot / f"interpret_{kind}.{ext}"
        tmp.write_text(text, encoding="utf-8")
        msg = tool_ingest(db_path, lab, file=str(tmp), kind=kind, host=host, url=url,
                          page_title=title)
        unlocked = sorted(_candidate_ids(db_path, lab, host) - before)
        return msg + (f"; unlocked: {', '.join(unlocked)}" if unlocked else "")

    # Raw fallback: loot + one INFO finding (evidence is never a raw dump).
    from yhwach import config as yhconfig

    ttl = title or next((ln.strip() for ln in text.splitlines() if ln.strip()), "raw output")[:60]
    if dry_run:
        return f"dry_run: unrecognised — would store as loot + INFO finding ('{ttl}')"
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        host_id = None
        if host:
            hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                                (eid, host)).fetchone()
            host_id = int(hrow["id"]) if hrow else None
        loot_dir = yhconfig.loot_dir()
        loot_dir.mkdir(parents=True, exist_ok=True)
        slug = "".join(c if c.isalnum() else "_" for c in ttl)[:48]
        lp = loot_dir / f"raw_{slug}.txt"
        lp.write_text(text, encoding="utf-8")
        excerpt = " ".join(text.split())[:180]
        fid, _ = yhdb.add_finding(conn, host_id, None, "INFO", ttl, "info",
                                  f"{excerpt}  [full: {lp}]", engagement_id=eid)
        yhdb.log_event(conn, eid, "ingest",
                       {"kind": "raw", "host": host, "finding": fid, "loot": str(lp)})
    return (f"unparsed — stored as loot + INFO finding #{fid} ('{ttl}'). "
            f"Name kind='x:<action_id>' to run an extractor, or a parser kind.")


def tool_action(db_path: Path | str, lab: str, action_id: str,
                host: str | None = None, port: int | None = None) -> str:
    """Render one recall action as a runnable command for a concrete target.

    Fills {host}/{port}; a secret stays a `$YH_SECRET` env reference (never the
    value — compose it in your shell). Returns the command, the fold-back call
    to make with its output, and a ref. An action with no template is 'manual'.
    """
    from yhwach import actions_ref

    # Resolve the engagement so an unknown lab still errors consistently.
    with yhdb.transaction(db_path) as conn:
        _eng(conn, lab)
    r = actions_ref.render(action_id, host=host, port=port)
    if r is None:
        return (f"{action_id}: manual (no command template) — run it by hand, "
                f"then record the result with yhwach_interpret or yhwach_add_finding.")
    out = [f"$ {r['cmd']}"]
    missing = actions_ref.unfilled(r["cmd"])
    if missing:
        _flag = {"{host}": "host", "{port}": "port", "{url}": "url", "{domain}": "domain"}
        out.append("# incomplete — not runnable as-is; pass "
                   + ", ".join(_flag.get(m, m) for m in missing)
                   + f" (unfilled: {', '.join(missing)})")
    if r.get("needs"):
        out.append(f"needs: {', '.join(r['needs'])}")
    if r.get("then"):
        out.append(f"then: yhwach_interpret(kind='{r['then']['kind']}'"
                   + (f", host={host}" if host else "") + ")  # feed the output back")
    if r.get("ref"):
        out.append(f"ref: {r['ref']}")
    return "\n".join(out)


def tool_schema(db_path: Path | str, tool: str | None = None) -> str:
    """Discover the tool surface: argument meanings and a runnable example.

    No `tool` lists every yhwach tool, the yhwach_query views and operators, and
    the shared argument vocabulary. With `tool='yhwach_<name>'` it returns that
    one tool's args and an example call. Pure discovery — reads nothing, needs no
    lab. Call it when unsure what an argument means or what a view is named.
    """
    from yhwach import vocab

    return vocab.catalog(TOOL_SPECS, tool=tool)


def _host_id_for(conn, eid: int, ip: str | None) -> int | None:
    if not ip:
        return None
    row = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                       (eid, ip)).fetchone()
    return int(row["id"]) if row else None


def _critical_warning(conn, eid: int) -> str | None:
    missing = yhdb.uncommunicated_critical_findings(conn, eid)
    if not missing:
        return None
    names = ", ".join(f"#{r['id']} {r['title']}" for r in missing[:5])
    more = f" (+{len(missing) - 5} more)" if len(missing) > 5 else ""
    return (f"⚠ {len(missing)} live CRITICAL finding(s) not yet notified: {names}{more} — "
            "record a critical_notification before close.")


def tool_notice(db_path: Path | str, lab: str, body: str | None = None,
                kind: str = "status_update", finding: int | None = None,
                channel: str | None = None, actor: str | None = None) -> str:
    """The client communications log (G4a). With `body`, record what was said
    (kind: critical_notification|status_update|stop|pause|resume|detection|
    scope_change; link a critical to its finding). Without `body`, list the log.
    Always flags live critical findings that have not been communicated.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if body:
            try:
                nid = yhdb.add_notice(conn, eid, kind=kind, body=body,
                                      finding_id=finding, channel=channel, actor=actor)
            except ValueError as e:
                return f"[!] {e}"
            yhdb.log_event(conn, eid, "notice", {"kind": kind, "finding": finding})
            out = [f"recorded notice #{nid} [{kind}]"]
        else:
            rows = yhdb.list_notices(conn, eid, limit=50)
            out = [f"{r['at']} [{r['kind']}]"
                   + (f" f#{r['finding_id']}" if r["finding_id"] else "")
                   + (f" ({r['channel']})" if r["channel"] else "") + f" — {r['body']}"
                   for r in rows] or ["(no notices recorded)"]
        warn = _critical_warning(conn, eid)
        if warn:
            out.append(warn)
        return "\n".join(out)


def tool_log(db_path: Path | str, lab: str, action: str, command: str | None = None,
             host: str | None = None, target: str | None = None,
             result: str | None = None) -> str:
    """Record a command YOU (the model) ran yourself into the activity ledger
    (I05), so the originated-traffic log is complete. The command is stored with
    secrets redacted. yhwach's own spray/scan already log here; this covers the
    moves you make by hand. The ledger is PARTIAL — only traffic yhwach or you
    report, never what other tools sent.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        hid = _host_id_for(conn, eid, host)
        aid = yhdb.add_activity(conn, eid, actor="model", action=action, host_id=hid,
                                target=target, command=command, result=result)
        return f"logged activity #{aid} [{action}]"


def tool_artifact(db_path: Path | str, lab: str, location: str | None = None,
                  kind: str = "file", host: str | None = None,
                  note: str | None = None, remove: int | None = None) -> str:
    """The artifact cleanup ledger (I39): what you LEFT on client systems. With
    `location`, record one (kind: tunnel_agent|implant|webshell|file|account|
    service). With `remove=<id>`, mark it confirmed removed. Without either, list
    — outstanding (not-removed) artefacts block a clean close. The Kali-side
    listener/proxy is not a client artefact; do not record it.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if remove is not None:
            yhdb.set_artifact_state(conn, int(remove), "removed")
            out = [f"artifact #{remove} marked removed"]
        elif location:
            hid = _host_id_for(conn, eid, host)
            aid = yhdb.add_artifact(conn, eid, kind=kind, location=location,
                                    host_id=hid, note=note)
            out = [f"recorded artifact #{aid} [{kind}] @ {location}"]
        else:
            rows = yhdb.list_artifacts(conn, eid)
            out = [f"#{r['id']} [{r['state']}] {r['kind']} @ {r['location']}"
                   + (f" ({r['host_ip']})" if r["host_ip"] else "")
                   for r in rows] or ["(no artefacts recorded)"]
        outstanding = yhdb.outstanding_artifacts(conn, eid)
        if outstanding:
            out.append(f"⚠ {len(outstanding)} artefact(s) not confirmed removed — "
                       "not clean to close.")
        return "\n".join(out)


def tool_submission(db_path: Path | str, lab: str, program: str | None = None,
                    finding: int | None = None, endpoint: str | None = None,
                    param: str | None = None, cls: str | None = None,
                    status: str | None = None, note: str | None = None) -> str:
    """Bounty submission memory (I20). With an endpoint/finding/program, record a
    submission and get an advisory duplicate-risk line (same endpoint+param, or
    same class program-wide). Without, list submissions. Advisory ONLY — it never
    changes a finding's status and never reorders recall.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        adding = any(x is not None for x in (program, finding, endpoint))
        if adding:
            risk = yhdb.submission_duplicate_risk(
                conn, eid, endpoint=endpoint, param=param, cls=cls, program=program)
            sid = yhdb.add_submission(conn, eid, program=program, finding_id=finding,
                                      endpoint=endpoint, param=param, cls=cls,
                                      status=status, note=note)
            out = [f"recorded submission #{sid}"]
            out += [f"  ~ {r}" for r in risk]
            return "\n".join(out)
        rows = yhdb.list_submissions(conn, eid, limit=50)
        out = [f"#{r['id']} {r['program'] or '-'} {r['endpoint'] or ''} "
               f"{('param=' + r['param']) if r['param'] else ''} [{r['status'] or 'submitted'}]"
               for r in rows] or ["(no submissions recorded)"]
        return "\n".join(out)


def tool_add_findings(db_path: Path | str, lab: str, findings: list) -> str:
    """Record MANY findings in one call (I66). Each item is a dict:
    {title, severity, cls?, host?, tag?, evidence?, location?}. One transaction;
    the same per-instance dedupe and curated-freeze as yhwach_add_finding. Use
    when an out-of-band tool produced a batch, instead of N round-trips.
    """
    if not isinstance(findings, list) or not findings:
        return "pass a non-empty list of {title, severity, ...} findings."
    added = updated = 0
    tags: set[str] = set()
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        for f in findings:
            if not isinstance(f, dict) or not f.get("title") or not f.get("severity"):
                raise ValueError("each finding needs at least title and severity")
            host_id = _host_id_for(conn, eid, f.get("host"))
            _fid, created = yhdb.add_finding(
                conn, host_id, None, f.get("cls") or "info", f["title"], f["severity"],
                f.get("evidence") or f["title"], tag=f.get("tag"),
                location=f.get("location"), engagement_id=eid)
            added += int(created)
            updated += int(not created)
            if f.get("tag"):
                tags.add(f["tag"])
        yhdb.log_event(conn, eid, "finding", {"bulk": len(findings), "new": added})
    tnote = f"; tags: {', '.join(sorted(tags))}" if tags else ""
    return f"recorded {added} new + {updated} updated finding(s){tnote}"


def tool_add_creds(db_path: Path | str, lab: str, creds: list) -> str:
    """Record MANY credentials in one call (I66). Each item is a dict:
    {identifier|user, secret, kind?, source?, provided?, spray_policy?}. One
    transaction, then ONE autospray pass IF the engagement is armed (the spray
    default comes from the engagement mode, never forced). Dumped-hash batches
    should pass spray_policy='manual'.
    """
    if not isinstance(creds, list) or not creds:
        return "pass a non-empty list of {identifier, secret, kind} creds."
    added = updated = 0
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        for c in creds:
            ident = c.get("identifier") or c.get("user")
            if not isinstance(c, dict) or not ident:
                raise ValueError("each cred needs an identifier and a secret")
            _cid, created = yhdb.add_credential(
                conn, eid, ident, c.get("secret"), c.get("kind") or "password",
                c.get("source") or "bulk",
                provenance="provided" if c.get("provided") else c.get("provenance"),
                spray_policy=c.get("spray_policy"))
            added += int(created)
            updated += int(not created)
        armed = _armed(conn, eid)
        spray_note = " (autospray off: not armed)"
        if armed:
            try:
                from yhwach import sprayer as yhspray

                batch = yhspray.spray_all(conn, eid)
                spray_note = f" (autospray: {len(batch.hits)} hit)"
            except Exception as exc:  # noqa: BLE001
                spray_note = f" (autospray error: {type(exc).__name__})"
        yhdb.log_event(conn, eid, "credential", {"bulk": len(creds), "new": added})
    return f"recorded {added} new + {updated} updated credential(s){spray_note}"


def tool_own(db_path: Path | str, lab: str, host: str | None = None,
             principal: str | None = None) -> str:
    """Assert ownership of a host or principal won OUT-OF-BAND (a shell, a console,
    an RDP session yhwach did not originate), so pathfind starts from it. Ownership
    otherwise comes only from validated access — never an unproven guess. A host is
    advanced to 'foothold'; a principal is flagged owned (created if unknown).
    """
    if not host and not principal:
        return "pass host= and/or principal= to assert ownership."
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        out: list[str] = []
        if host:
            adv, m = yhdb.set_host_stage(conn, eid, host, "foothold",
                                         note="operator-asserted ownership (yhwach_own)")
            out.append(f"{host} -> foothold (owned)" if adv else f"{host}: {m}")
        if principal:
            yhdb.set_principal_owned(conn, eid, principal)
            out.append(f"principal '{principal}' marked owned")
        yhdb.log_event(conn, eid, "own", {"host": host, "principal": principal})
        return "; ".join(out)


def tool_methodology(db_path: Path | str, lab: str, host: str) -> str:
    """Per-asset methodology matrix (I35) for one host: each AD checklist item is
    PRESENT (weakness found), CHECKED (enumerated, not vulnerable) or UNKNOWN (no
    evidence — enumerate it). State is DERIVED from host_fact/domain_fact, never
    operator-typed, so UNKNOWN honestly means 'not yet checked'.
    """
    from yhwach import methodology as meth

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        hrow = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                            (eid, host)).fetchone()
        if hrow is None:
            raise ValueError(f"host {host} not found")
        matrix = meth.methodology_for_host(conn, eid, int(hrow["id"]))
        counts = meth.coverage_counts(matrix)
    lines = [f"methodology — {host}: {counts['PRESENT']} present, {counts['CHECKED']} checked, "
             f"{counts['UNKNOWN']} unknown"]
    lines += [f"  [{r['state']:<7}] {r['label']}"
              + (f" ({r['value']})" if r["value"] is not None else "") for r in matrix]
    return "\n".join(lines)


def tool_plant(db_path: Path | str, lab: str, location: str | None = None,
               payload: str | None = None, kind: str | None = None,
               sight: int | None = None, context: str | None = None,
               remove: int | None = None) -> str:
    """Indirect-injection plant tracker (I54). With location+payload, record a
    plant and get a NEUTRAL canary to embed. sight=<id> records a sighting (the
    canary fired somewhere). remove=<id> marks it cleaned up. No arg lists, with
    the outstanding cleanup checklist. A plant left in client data blocks a clean
    close.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if sight is not None:
            yhdb.add_plant_sighting(conn, int(sight), context=context)
            return f"sighting recorded for plant #{sight}"
        if remove is not None:
            yhdb.set_plant_removed(conn, int(remove))
            return f"plant #{remove} marked removed"
        if location and payload:
            pid, canary = yhdb.add_plant(conn, eid, location=location, payload=payload, kind=kind)
            return (f"plant #{pid} at {location} — embed this neutral canary so a sighting "
                    f"attributes back: {canary}")
        rows = yhdb.list_plants(conn, eid)
        out = [f"#{r['id']} [{'removed' if r['removed_at'] else 'LIVE'}] {r['kind'] or ''} "
               f"@ {r['location']} · {r['sightings']} sighting(s) · canary {r['canary']}"
               for r in rows] or ["(no plants recorded)"]
        live = yhdb.outstanding_plants(conn, eid)
        if live:
            out.append(f"⚠ CLEANUP: {len(live)} plant(s) still live — remove before close.")
        return "\n".join(out)


def tool_ai_tool(db_path: Path | str, lab: str, name: str | None = None,
                 description: str | None = None, host: str | None = None,
                 sink: str | None = None) -> str:
    """Record an agent tool exposed by an AI surface (I52). The sink it can reach
    is classified from name/description (override with sink=); a dangerous sink
    (shell/code/sql/email) raises an excessive-agency finding, and a changed
    description since last seen raises a rug-pull finding. No name = list.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if not name:
            rows = yhdb.list_ai_tools(conn, eid)
            return "\n".join(f"#{r['id']} [{r['sink']}] {r['name']}" for r in rows) \
                or "(no agent tools recorded)"
        from yhwach.aisurface import DANGEROUS_SINKS

        hid = _host_id_for(conn, eid, host)
        tid, created, rugpulled = yhdb.add_ai_tool(
            conn, eid, name, description=description, sink=sink)
        row = conn.execute("SELECT sink FROM ai_tool WHERE id=?", (tid,)).fetchone()
        eff_sink = row["sink"]
        out = [f"tool '{name}' recorded (sink={eff_sink})"]
        if eff_sink in DANGEROUS_SINKS:
            yhdb.add_finding(conn, hid, None, "LLM06", f"Agent tool reaches {eff_sink}",
                             "high", f"tool '{name}' -> {eff_sink} sink (excessive agency)",
                             tag="excessive_agency", location=name, engagement_id=eid)
            out.append(f"⚠ excessive-agency finding ({eff_sink})")
        if rugpulled:
            yhdb.add_finding(conn, hid, None, "LLM05", f"Agent tool changed: {name}",
                             "high", f"'{name}' description changed since last seen — "
                             "possible rug-pull / supply-chain swap",
                             tag="tool_rugpull", location=name, engagement_id=eid)
            out.append("⚠ RUG-PULL: description changed since last seen")
        return "; ".join(out)


def tool_ai_source(db_path: Path | str, lab: str, name: str | None = None,
                   kind: str | None = None, host: str | None = None,
                   writable: bool = False) -> str:
    """Record a data source an AI agent reads (RAG/vector-db/file/db/web) (I52).
    writable=True marks an attacker-controllable source — the indirect-injection
    vector — and raises a finding. No name = list.
    """
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if not name:
            rows = yhdb.list_ai_data_sources(conn, eid)
            return "\n".join(f"#{r['id']} {r['name']} ({r['kind'] or '?'})"
                             + (" [writable]" if r["writable"] else "") for r in rows) \
                or "(no data sources recorded)"
        hid = _host_id_for(conn, eid, host)
        yhdb.add_ai_data_source(conn, eid, name, kind=kind, writable=writable)
        out = [f"data source '{name}' recorded"]
        if writable:
            yhdb.add_finding(conn, hid, None, "LLM01", f"Writable agent data source: {name}",
                             "high", f"'{name}' is attacker-writable -> indirect prompt injection",
                             tag="rag_poisoning", location=name, engagement_id=eid)
            out.append("⚠ writable: indirect-injection vector")
        return "; ".join(out)


def tool_payload(db_path: Path | str, lab: str, payload: str | None = None,
                 response: str | None = None, surface: str | None = None,
                 host: str | None = None, verdict: str | None = None,
                 set_id: int | None = None, canary: bool = False) -> str:
    """The injection payload/response/verdict ledger (I53). With `payload`, record
    a test (+ optional `response`); a heuristic suggests a verdict but the stored
    verdict stays 'unclear' until you confirm it — the regex is never the fact of
    record. `set_id`+`verdict` records your verdict. `canary=True` returns this
    engagement's neutral canary to seed indirect-injection payloads. No arg lists.
    """
    from yhwach import payloads as plmod

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if canary:
            return f"engagement canary: {yhdb.engagement_canary(conn, eid)}"
        if set_id is not None:
            if not verdict:
                return "pass verdict= (success|refused|blocked|unclear) with set_id"
            try:
                yhdb.set_payload_verdict(conn, int(set_id), verdict)
            except ValueError as e:
                return f"[!] {e}"
            return f"payload #{set_id} verdict -> {verdict}"
        if payload:
            can = yhdb.engagement_canary(conn, eid)
            auto = plmod.classify_payload_response(payload, response, canary=can)
            hid = _host_id_for(conn, eid, host)
            pid = yhdb.add_payload(conn, eid, payload=payload, response=response,
                                   surface=surface, host_id=hid, canary=can,
                                   auto_verdict=auto, verdict="unclear")
            return (f"payload #{pid} recorded. heuristic suggests '{auto}' (advisory) — "
                    f"confirm with yhwach_payload(set_id={pid}, verdict=...).")
        rows = yhdb.list_payloads(conn, eid, limit=50)
        out = [f"#{r['id']} [{r['verdict']}" + (f"/auto:{r['auto_verdict']}"
               if r["auto_verdict"] and r["auto_verdict"] != r["verdict"] else "")
               + f"] {(r['surface'] or '')} {r['payload'][:60]}" for r in rows]
        return "\n".join(out) or "(no payloads recorded)"


def tool_reuse(db_path: Path | str, lab: str) -> str:
    """Derive credential-reuse attack-graph edges from dumped hashes and validated
    access (G2e): CredValidOn (a proven cred links its principal to the host),
    LocalAdminReuse (hosts one admin secret opens are mutually reachable — a star,
    not a clique), and SameHash (principals sharing a secret). Idempotent; run it
    after spraying provided creds or ingesting a secretsdump, then yhwach_paths.
    """
    from yhwach.reuse import derive_reuse_edges

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        counts = derive_reuse_edges(conn, eid)
        yhdb.log_event(conn, eid, "reuse", counts)
    total = sum(counts.values())
    if not total:
        return ("no new reuse edges — need validated access (spray provided creds) or "
                "dumped hashes/accounts that share a secret.")
    return ("reuse edges added: "
            + ", ".join(f"{k}={v}" for k, v in counts.items() if v)
            + " — check yhwach_paths / yhwach_path.")


def tool_query(db_path: Path | str, lab: str, view: str,
               where: dict | None = None, q: str | None = None,
               fields: list | None = None, order: str | None = None,
               limit: int = 25, offset: int = 0, reveal: bool = False,
               fmt: str = "text", max_chars: int | None = None) -> str:
    """Query a named read view of the world model (read-only, no traffic).

    views: hosts, services, surfaces, findings, creds, principals, shares, loot,
    objectives, attempts, events, software, vulns, web_paths, scan_coverage,
    probe_runs. `where` filters by column with an operator in the key, e.g.
    {"port": 445}, {"severity in": ["high","critical"]}, {"at>=": "2026-10-11T14:00Z"},
    {"validated_on is_null": true}. `q` is a substring search across the view's
    text columns. Secrets are masked unless reveal=true. Every row carries an id.

    Paging is explicit: raise `offset` by the shown count to get the next page —
    the footer (or the JSON `next`) prints the exact follow-up call. `fmt='json'`
    returns a structured envelope {view,total,offset,limit,count,rows,next};
    `max_chars` caps the output, dropping trailing rows and resuming after them.
    """
    from yhwach import views as yhviews

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        cols, rows, total = yhviews.query(
            conn, eid, view, where=where, q=q, fields=fields, order=order,
            limit=limit, offset=offset, reveal=reveal)
        return yhviews.format_result(cols, rows, total, view, limit, offset,
                                     fmt=fmt, max_chars=max_chars)


def tool_attempt(db_path: Path | str, lab: str, rule: str, result: str,
                 reason: str = "", host: str | None = None,
                 evidence: str | None = None, technique: str | None = None) -> str:
    """Record that a move was tried, so recall stops re-proposing it.

    `rule` is a playbook technique id (validated against the catalog). `result`
    is success | fail | blocked | partial. A fail/blocked retires that (rule,
    host) pair from `yhwach_next` until you explicitly retry; a success marks it
    done. For an off-catalog move (a custom web auth bypass, a client-specific
    app), pass a free-text `technique` instead of `rule`.
    """
    from yhwach import knowledge as kn

    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        rule_id: str | None = rule
        tech = technique
        if rule:
            ids = {t.id: t.technique for t in kn.load_techniques()}
            if rule in ids:
                tech = tech or ids[rule]
            elif technique is None:
                import difflib

                near = difflib.get_close_matches(rule, list(ids), n=3)
                hint = f" (did you mean: {', '.join(near)}?)" if near else ""
                raise ValueError(
                    f"unknown technique id '{rule}'{hint}. Pass technique=<free text> "
                    "to record an off-catalog move.")
        else:
            rule_id = None
        host_id: int | None = None
        if host:
            host_id = yhdisc.observe_ip(conn, eid, host, source="attempt")
            if host_id is None:
                hrow = conn.execute(
                    "SELECT id FROM host WHERE engagement_id=? AND ip=?", (eid, host)
                ).fetchone()
                host_id = int(hrow["id"]) if hrow else None
        yhdb.add_attempt(conn, eid, result=result, host_id=host_id,
                         playbook_rule_id=rule_id, technique_id=tech,
                         reason=reason or None, evidence=evidence)
        yhdb.log_event(conn, eid, "attempt",
                       {"rule": rule_id or tech, "host": host, "result": result,
                        "reason": reason})
    where = f" @ {host}" if host else ""
    return f"attempt recorded: {rule_id or tech}{where} -> {result}"


TOOL_SPECS = [
    ("yhwach_engage", tool_engage,
     "Initialise/resume a lab: create the DB and upsert the engagement (lab + scope "
     "[+ domain/dc]). Call this first; scope is validated as IPs/CIDRs."),
    ("yhwach_status", tool_status, "Engagement scoreboard: hosts by stage, services, tasks, vault."),
    ("yhwach_dossier", tool_dossier,
     "The per-host briefing the operator sees: what the box is, what each surface kind is, "
     "and what is still dark. Composed offline from the world model and the knowledge packs."),
    ("yhwach_annotate", tool_annotate,
     "Attach a short written note about a host. Description, not direction: say what something "
     "IS or what raw output MEANS, never what to run next."),
    ("yhwach_brief", tool_brief,
     "The AI-legible engagement map: REACH / HOLD / SURFACES / UNLOCKS / UNEXPLORED / OBJECTIVES. "
     "Read this to reason over the memory and find the path; yhwach decides nothing."),
    ("yhwach_next", tool_next,
     "The recall menu + what you're about to miss: every technique that applies now "
     "(grouped by host, read-only vs gated), fused with under-enumeration gaps, untried "
     "vault creds and uncaptured objectives. The deterministic menu the brain reasons "
     "FROM — call it to answer 'what do I do next?'. Optional host scopes to one IP."),
    ("yhwach_findings", tool_findings, "Recorded findings, most severe first."),
    ("yhwach_finding_set", tool_finding_set,
     "Correct a finding: status (open|confirmed|exploited|false_positive|duplicate|"
     "remediated|dead), severity, or evidence. Closed findings leave recall but stay "
     "queryable; the finding is frozen against parser re-ingest. Never deletes."),
    ("yhwach_add_evidence", tool_add_evidence,
     "Bind a proof artefact (screenshot|request|response|output|file|log) to a finding "
     "or PoC objective — by file path (hashed, refused if missing) or pasted text. "
     "The DB keeps a sha256 + link so 'does finding #N have proof?' is answerable."),
    ("yhwach_add_finding", tool_add_finding,
     "Record an operator-confirmed finding/lead (doc disclosure, config leak, auth-bypass "
     "lead, enumerated users) into the world model so it shows on the board/report. "
     "Args: title, severity (critical|high|medium|low|info), evidence, cls, host?, tag?."),
    ("yhwach_poc_step", tool_poc_step,
     "Append one reproducible step to a PoC kill-chain (objective + title + verbatim command "
     "+ output; optional script_content/script_name saved verbatim, cve, source, host). "
     "Call for every step so the PoC can be recreated end-to-end."),
    ("yhwach_poc", tool_poc,
     "Render a reproducible PoC chain to chains/<objective>.md (every command/output/script/CVE), "
     "or list recorded objectives when objective is omitted."),
    ("yhwach_report", tool_report, "Full Markdown engagement report."),
    ("yhwach_report_check", tool_report_check,
     "Readiness gate: is the memory reproducible enough to write up? Flags proven "
     "findings with no evidence, PoC placeholders ($VAR/TODO), inline secrets in "
     "evidence, uncommunicated criticals, and outstanding cleanup artefacts."),
    ("yhwach_add_cred", tool_add_cred,
     "Add a credential to the vault (username/label + secret + kind + source; "
     "source is appended on update, never clobbered)."),
    ("yhwach_add_loot", tool_add_loot,
     "Record a recovered file/key/dump (config|key|db|source|dump|hash|note|binary) in the "
     "model: summary + host? + remote path? + local_path? + contains_secret?. Use for any "
     "artifact looted by hand so it lands on the board/report, not just the operator's head."),
    ("yhwach_creds", tool_creds,
     "List the credential vault in full (identifier, secret, kind, source, source_host). "
     "Every access-granting artifact — passwords, hashes, SSH keys, API tokens — lives here. "
     "Query before attacking anything new."),
    ("yhwach_advance", tool_advance, "Advance a host's FSM stage (foothold/looted/pivoted/...)."),
    ("yhwach_set_host", tool_set_host,
     "Name/classify a host: hostname (DC01), os, and role (what it mainly hosts — "
     "Domain Controller | Jenkins CI | AI - IT Service Desk | File server | Workstation)."),
    ("yhwach_add_interface", tool_add_interface,
     "Record an extra interface/IP on a host — how yhwach learns a box is dual-homed "
     "(DMZ host with a NIC into an internal subnet); the basis of the pivot tree."),
    ("yhwach_tag", tool_tag,
     "Tag a host with a free-form label (dc | ai-target | domain-admin | dual-homed | "
     "tier0 | dead-end | loot-here | ...), orthogonal to its FSM stage. NOTE: a tag is "
     "an operator label for filtering/notes — it does NOT unlock recall rules. Only typed "
     "facts (findings, surfaces, creds) light up yhwach_next; tagging 'dc' changes nothing."),
    ("yhwach_untag", tool_untag, "Remove a free-form tag from a host."),
    ("yhwach_scope", tool_scope,
     "Manage the typed engagement scope: list|add|exclude|remove|check (no traffic). "
     "Tokens are ip/cidr/hostname/*.wildcard; exclude wins; empty scope refuses traffic."),
    ("yhwach_spray", tool_spray,
     "Spray the credential vault against reachable services (ssh|smb|winrm|ldap|mssql|"
     "rdp|ftp|http-basic). Also auto-runs on every add_cred and every new service "
     "from an nmap ingest, so most turns don't need this called explicitly. "
     "Filters: host?, protocol?, cred?, force?, dry_run?. Results (success & fail) "
     "are cached in credential_access; force=True re-attempts. Uses nxc / curl; "
     "domain and local-auth are tried automatically on SMB/WinRM/MSSQL."),
    ("yhwach_interpret", tool_interpret,
     "Turn pasted tool output into typed rows (auto-sniffs nmap/netexec/secretsdump/potfile/nessus/openvas/nuclei/bloodhound/"
     "certipy/linpeas/winpeas/web; kind='x:<action_id>' runs an extractor; else loot+INFO). "
     "Names which recall rules the new facts unlocked. dry_run classifies without writing."),
    ("yhwach_query", tool_query,
     "Query a named read view (hosts|services|surfaces|findings|creds|principals|"
     "shares|loot|objectives|attempts|events|software|vulns|web_paths|scan_coverage|"
     "probe_runs) with where/q/fields/order/limit. Read-only; secrets masked unless reveal."),
    ("yhwach_action", tool_action,
     "Render one recall action id as a runnable command for host/port (secrets stay "
     "$YH_SECRET env refs), with the fold-back yhwach_interpret call and a ref. "
     "Manual actions (no template) say so."),
    ("yhwach_attempt", tool_attempt,
     "Record a tried move (result: success|fail|blocked|partial). fail/blocked "
     "retire that (rule,host) from yhwach_next; success marks it done. Pass a "
     "free-text technique= for off-catalog moves."),
    ("yhwach_scan", tool_scan,
     "Run nmap against hosts and ingest results — the 'always full-scan early' fix. "
     "mode=quick|full|udp (full = -p- -sV -sC; the 'no missed ports' guarantee). "
     "Omit host to drain the scan_needed=1 queue (max_hosts caps the batch, default "
     "8). Ingests through the same path as yhwach_ingest so the sprayer's "
     "new-service hook fires for every service discovered."),
    ("yhwach_derive", tool_derive,
     "Derive credential candidates from vault patterns (year tokens, role tokens, "
     "prefix leetspeak, suffix tails like '#Acme2025'). Prints suggestions by "
     "default; spray=True inserts them as vault creds (which then fire the "
     "add_cred autospray). ~5 candidates per known pattern, not a wordlist. "
     "targets? = comma-separated usernames to generate FOR (default: common svc accounts)."),
    ("yhwach_ingest", tool_ingest,
     "Ingest a tool-output file into the world model (kind=nmap|secretsdump|potfile|nessus|openvas|nuclei|httpx|subfinder|bbot|burp|har|kubectl|aws|trivy|prowler|sarif|poutine|mcp|linpeas|winpeas|"
     "bloodhound|certipy|netexec|web). nmap adds software+CPE; bloodhound builds the "
     "principal/privilege/edge graph; netexec adds SMB shares/users/admin/policy; web "
     "adds web_app+paths (needs url). Host-scoped kinds need a host and set chaining tags."),
    ("yhwach_enum", tool_enum,
     "Run nmap through HexStrike against a target and ingest the result (delegated enumeration)."),
    ("yhwach_probe", tool_probe,
     "Probe scanned hosts for AI + traditional attack surfaces and record them."),
    ("yhwach_pivot", tool_pivot,
     "Record a pivot (subnet reachable via a host), render the Ligolo deploy, and advance "
     "the host looted -> pivoted."),
    ("yhwach_gaps", tool_gaps,
     "Under-enumerated hosts and the exact nmap that closes each gap (full-port / -sV / "
     "UDP top-100), from recorded scan coverage."),
    ("yhwach_coverage", tool_coverage,
     "World-model honesty score: of the hosts you've reached (scanned+), how many are "
     "fully enumerated — plus each one's remaining gaps with the exact fix. The "
     "completeness half of 'check every path'; scopes to a host with the optional arg."),
    ("yhwach_audit", tool_audit,
     "Methodology audit: coverage by standard (ATT&CK / ATLAS / OWASP-LLM / CWE / CVE) "
     "from classified findings + the paths not yet checked (service_enum / scan gaps). "
     "The 'what did we exercise, what did we skip?' self-assessment for the write-up."),
    ("yhwach_objective", tool_objective,
     "The scored/timed engagement cockpit: record flags/objectives (add=<label>, +host/points/kind), "
     "mark one captured (capture=<label>), or read the scoreboard (points scored vs target, "
     "flags captured vs found, hours elapsed vs budget). Engagements can be scored — track it here."),
    ("yhwach_vulns", tool_vulns,
     "Match recorded software versions against the offline CVE knowledge base; record "
     "vulnerabilities + exploitable_cve findings. Run after ingesting versions."),
    ("yhwach_ref", tool_ref,
     "Query a bundled reference pack (offline): default-creds | esc | gtfobins | lessons | "
     "services | tags | lolbas | wadcoms | arsenal | ai-attacks, with an optional query "
     "filter. Creds, AD CS ESC, GTFObins/LOLBAS privesc, service matrix, the vendored "
     "arsenal index, and the AI/LLM attack chains (RAG/MCP/A2A/vector-db/cloud)."),
    ("yhwach_recon", tool_recon,
     "Full recon picture for one host (services, software, vulns, web, shares, "
     "on-host privileges, loot, interfaces, findings) — read before attacking it."),
    ("yhwach_path", tool_path,
     "Shortest attack-graph path between two nodes (owned -> Domain Admins / objective). "
     "Names or 'principal:<id>'/'host:<id>'."),
    ("yhwach_paths", tool_paths,
     "Shortest path from what you OWN to EVERY objective + Domain/Enterprise Admins, in "
     "one call (owned = principals you hold creds for + owned hosts). Unreachable targets "
     "are flagged so you know where to enumerate more edges. 'Where do I stand vs the crown?'"),
    ("yhwach_export_notes", tool_export_notes,
     "Auto-scaffold the Obsidian notebook (standing notes + per-host) from the world "
     "model; operator syncs the tree into the vault via the Obsidian MCP."),
    ("yhwach_schema", tool_schema,
     "Discover the tool surface: no arg lists every tool, the yhwach_query views and "
     "operators, and what each argument means; tool='yhwach_<name>' returns that tool's "
     "args + a runnable example. Pure discovery — call it when unsure of an arg or a view."),
    ("yhwach_notice", tool_notice,
     "Client communications log (what was told, when). With body=, record a notice "
     "(kind: critical_notification|status_update|stop|pause|resume|detection|scope_change; "
     "link a critical to its finding); without, list. Flags live criticals not yet notified."),
    ("yhwach_log", tool_log,
     "Record a command YOU ran by hand into the activity ledger (secrets redacted) so the "
     "originated-traffic log is complete. yhwach's own spray/scan already log here. The "
     "ledger is PARTIAL — only traffic yhwach or you report."),
    ("yhwach_artifact", tool_artifact,
     "Cleanup ledger: what you LEFT on client systems. location= records one "
     "(kind: tunnel_agent|implant|webshell|file|account|service), remove=<id> confirms "
     "removal, neither lists. Outstanding artefacts block a clean close."),
    ("yhwach_submission", tool_submission,
     "Bounty submission memory. endpoint/finding/program records a submission and returns a "
     "duplicate-risk advisory (same endpoint+param, or same class program-wide); otherwise "
     "lists. Advisory only — never changes a finding's status or recall order."),
    ("yhwach_methodology", tool_methodology,
     "Per-host methodology matrix (I35): each AD checklist item is PRESENT / "
     "CHECKED / UNKNOWN, derived from host_fact + domain_fact (never typed). "
     "UNKNOWN means not yet enumerated — the gaps to close."),
    ("yhwach_plant", tool_plant,
     "Indirect-injection plant tracker. location+payload records a plant and "
     "returns a NEUTRAL canary to embed; sight=<id> records the canary firing; "
     "remove=<id> marks cleanup. No arg lists + the cleanup checklist. A live "
     "plant in client data blocks a clean close."),
    ("yhwach_ai_tool", tool_ai_tool,
     "Record an agent tool exposed by an AI surface. Its sink (shell/code/sql/"
     "email/http/file) is classified from name/description; a dangerous sink "
     "raises an excessive-agency finding and a changed description a rug-pull "
     "finding. No name lists them."),
    ("yhwach_ai_source", tool_ai_source,
     "Record a data source an AI agent reads (rag/vector_db/file/db/web). "
     "writable=true marks an attacker-controllable source (indirect-injection "
     "vector) and raises a finding. No name lists them."),
    ("yhwach_payload", tool_payload,
     "Injection payload/response/verdict ledger. payload= records a test (a "
     "heuristic suggests success|refused|unclear, advisory only — verdict stays "
     "'unclear' until you confirm via set_id+verdict). canary=true returns the "
     "engagement's neutral canary for indirect-injection payloads. No arg lists."),
    ("yhwach_reuse", tool_reuse,
     "Derive credential-reuse attack-graph edges from dumped hashes + validated access "
     "(CredValidOn, LocalAdminReuse as a star, SameHash). Idempotent; run after spraying "
     "provided creds or ingesting a secretsdump, then yhwach_paths. The fleet-lateral path."),
    ("yhwach_add_findings", tool_add_findings,
     "Record MANY findings in one call: findings=[{title, severity, cls?, host?, "
     "tag?, evidence?, location?}, ...]. One transaction, same dedupe as "
     "yhwach_add_finding. Use for a batch instead of N calls."),
    ("yhwach_add_creds", tool_add_creds,
     "Record MANY credentials in one call: creds=[{identifier, secret, kind?, "
     "source?, provided?, spray_policy?}, ...]. One transaction, then ONE "
     "autospray pass only if the engagement is armed."),
    ("yhwach_own", tool_own,
     "Assert ownership of a host or principal won OUT-OF-BAND (a shell/console yhwach "
     "didn't originate), so pathfind starts from it. host= advances to foothold; "
     "principal= flags it owned. Ownership otherwise comes only from validated access."),
]
