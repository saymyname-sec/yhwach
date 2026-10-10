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
    return f"engagement '{lab}' ready (id={eid}); scope {scope}{dom}{hosts_note}"


def tool_status(db_path: Path | str, lab: str) -> str:
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        stages = conn.execute(
            "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage ORDER BY stage",
            (eid,)).fetchall()
        svc = conn.execute(
            "SELECT COUNT(*) n FROM service s JOIN host h ON h.id=s.host_id WHERE h.engagement_id=?",
            (eid,)).fetchone()["n"]
        vault_rows = yhdb.list_credentials(conn, eid)
    lines = [f"Engagement '{lab}':"]
    lines += [f"  {r['stage']}: {r['n']}" for r in stages] or ["  (no hosts)"]
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


def tool_brief(db_path: Path | str, lab: str, section: str | None = None) -> str:
    """The AI-legible engagement map (REACH/HOLD/SURFACES/UNLOCKS/UNEXPLORED/OBJECTIVES).
    Read this to reason over the memory; yhwach decides nothing."""
    from yhwach.brief import build_brief
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        return build_brief(conn, eid, section=section)


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
                  validated_on: str | None = None, admin: bool = False) -> str:
    """Store a credential in the vault.

    `user` is the login/identifier (username, key label, token id).
    `secret` is the plaintext, hash, or key material (raw SSH private key blob
    is fine — newlines are preserved by SQLite). `kind` picks the credential
    class (`password` | `ntlm` | `kerberos` | `ssh_key` | `api_key` | `token`
    | `dpapi`). `source_host`, if given, is the host IP where the cred was
    dumped and gets joined back on read. On update the `source` string is
    appended (not clobbered), so provenance survives re-discovery.

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
            conn, eid, user, secret, kind, source, source_host_id=source_host_id
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
            yhdb.log_event(conn, eid, "ingest", {"kind": "nmap", "hosts": h, "services": s})
            cov = "; ".join(f"{c.proto} {c.ports}" for c in meta.coverage) or "unknown"
            gaps = enum_gaps(conn, eid)
            tail = f"; {len(gaps)} host(s) under-enumerated (yhwach_gaps)" if gaps else ""
            # Auto-spray hook: for each host that just got new services, try
            # every vault cred against them. This is the "when a protocol
            # lets you connect, try every cred we know" behaviour the user
            # explicitly asked for. Restricted to the ingest's IPs to keep
            # each ingest bounded.
            spray_note = ""
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
            return (f"netexec on {host}: {summ['shares']} share(s), {summ['principals']} user(s), "
                    f"{summ['admin']} admin, {summ['findings']} finding(s)")
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
            note = (f"; graph: {g['principals']} principals, {g['privileges']} privs, "
                    f"{g['edges']} edges")
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
        services = yhdb.all_services_for_scanned_hosts(conn, eid)
        if host:
            services = [s for s in services if s["ip"] == host]
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
            trad = detect_traditional(session, s["ip"], s["port"], s["product"], timeout=timeout)
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
                     tag: str | None = None) -> str:
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
            tag=tag, engagement_id=eid)
        yhdb.log_event(conn, eid, "finding",
                       {"id": fid, "title": title, "severity": sev, "host": host, "tag": tag})
    where = f" on {host}" if host else ""
    chain = f" [tag: {tag}]" if tag else ""
    return f"finding #{fid} {'recorded' if created else 'updated'}{where}: [{sev}] {title}{chain}"


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
                  source: str | None = None, host: str | None = None) -> str:
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
                              source=source, host=host)
    tail = f" [script: {script_path}]" if script_path else ""
    return f"PoC '{pocmod.slug(objective)}' step #{seq} recorded: {title}{tail}"


def tool_poc(db_path: Path | str, lab: str, objective: str | None = None) -> str:
    """Render a reproducible PoC chain (chains/<objective>.md), or list objectives.

    With `objective`, returns the full copy-paste kill-chain (every command,
    output, script, CVE/source) and writes it to chains/<objective>.md. Without
    it, lists the recorded objectives and their step counts.
    """
    from yhwach import poc as pocmod
    with yhdb.transaction(db_path) as conn:
        eid = _eng(conn, lab)
        if objective is None:
            objs = pocmod.list_objectives(conn, eid)
            if not objs:
                return "No PoC steps recorded yet. Use yhwach_poc_step."
            return "PoC objectives:\n" + "\n".join(f"  {lbl} ({n} step(s))" for lbl, n in objs)
        return pocmod.render_poc(conn, eid, objective, lab=lab, write=True, db_path=db_path)


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
        if host:
            # Explicit target: run even if scan_needed=0 (the operator asked).
            # Auto-materialise the host if we've never heard of it — same
            # policy as add_finding.
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
     "tier0 | dead-end | loot-here | ...), orthogonal to its FSM stage."),
    ("yhwach_untag", tool_untag, "Remove a free-form tag from a host."),
    ("yhwach_spray", tool_spray,
     "Spray the credential vault against reachable services (ssh|smb|winrm|ldap|mssql|"
     "rdp|ftp|http-basic). Also auto-runs on every add_cred and every new service "
     "from an nmap ingest, so most turns don't need this called explicitly. "
     "Filters: host?, protocol?, cred?, force?, dry_run?. Results (success & fail) "
     "are cached in credential_access; force=True re-attempts. Uses nxc / curl; "
     "domain and local-auth are tried automatically on SMB/WinRM/MSSQL."),
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
     "Ingest a tool-output file into the world model (kind=nmap|linpeas|winpeas|"
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
]
