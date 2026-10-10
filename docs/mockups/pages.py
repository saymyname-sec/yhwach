"""The eight pages. Signature panels hand-rendered; the rest generic."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from render import (  # noqa: E402
    OUT,
    bar,
    card,
    chip,
    e,
    generic,
    hl,
    job,
    mono,
    panel,
    rows_of,
    sec,
    shell,
    spec,
    stage_badge,
    tbl,
)

OUT.mkdir(parents=True, exist_ok=True)


def mark(ok, partial=False, zero=False, text=None):
    if zero:
        return f"<span class='mk z'>{text or '·'}</span>"
    if ok:
        return f"<span class='mk y'>{text or '✔'}</span>"
    if partial:
        return f"<span class='mk p'>{text or '~'}</span>"
    return f"<span class='mk n'>{text or '✘'}</span>"


def num(n, good_at=1):
    n = int(n or 0)
    if n == 0:
        return "<span class='mk n'>0</span>"
    return f"<span class='mk y'>{n}</span>" if n >= good_at else f"<span class='mk p'>{n}</span>"


# ============================= RECON ======================================
def page_recon():
    b = [bar("Recon", "The enumeration matrix is the point of this tab: hosts down the side, "
             "enumeration dimensions across the top, every cell a fact about what was actually done."),
         job(spec["recon"]["job"])]

    rs = rows_of("recon", "_recon_enum_matrix")
    hdr = ["host", "stage", "-p-", "-sV", "UDP", "services", "surfaces", "web app",
           "web paths", "shares", "principals", "cred tries", "last scan"]
    body = []
    for r in rs:
        body.append([
            f"{hl(r['ip'])}<div class='dim' style='font-size:.7rem'>{e(r['hostname'] or '')}</div>",
            stage_badge(r["stage"]),
            mark(int(r["tcp_full"] or 0) == 1),
            mark(int(r["tcp_sv"] or 0) == 1),
            mark(int(r["udp_rows"] or 0) > 0),
            num(r["n_svc"]), num(r["n_surf"]), num(r["n_app"]), num(r["n_path"]),
            num(r["n_share"]), num(r["n_princ"]),
            (f"<span class='mk y'>{r['n_cred_ok']}/{r['n_cred']}</span>"
             if int(r["n_cred_ok"] or 0) else
             (f"<span class='mk p'>0/{r['n_cred']}</span>" if int(r["n_cred"] or 0)
              else "<span class='mk n'>0</span>")),
            f"<span class='dim mono' style='font-size:.68rem'>{e((r['last_scan'] or '—')[:16])}</span>",
        ])
    b += [sec("Enumeration matrix — what has actually been looked at, per host"),
          card(tbl(hdr, body, "no hosts materialised yet"),
               "✔ done · ✘ not done · a number is a row count. Sorted by how few of the three "
               "scans exist, so the thinnest hosts surface first — a count, not a priority. "
               "Columns are fixed at 11, so only rows grow with the estate.")]

    b.append(generic("recon", "_recon_scope_ledger", cap=10))
    b.append(generic("recon", "_recon_segments", cap=10))
    b.append(generic("recon", "_recon_provenance", cap=10))

    rs = rows_of("recon", "_recon_scan_ledger")
    if rs:
        hdr2 = ["host", "proto", "ports scanned", "full", "-sV", "source / argv", "when"]
        body2 = [[hl(r["ip"]), e(r["proto"]), mono(r["ports"]),
                  mark(int(r["full_range"] or 0) == 1), mark(int(r["version_scan"] or 0) == 1),
                  (mono(r["source"]) if r["source"] else "<span class='dim'>(argv not recorded)</span>"),
                  f"<span class='dim mono' style='font-size:.68rem'>{e((r['scanned_at'] or '')[:19])}</span>"]
                 for r in rs[:20]]
        b += [sec("Scan coverage ledger — the raw record, not a verdict"),
              card(tbl(hdr2, body2),
                   "The port range verbatim as nmap reported it. `source` carries the real argv "
                   "after a normal ingest; the demo DB only seeded the bare tool name.")]
    return shell("recon", "\n".join(x for x in b if x))


# ============================ SURFACES =====================================
def page_surfaces():
    b = [bar("Surfaces", "<b>surface.meta_json has zero production readers today.</b> Everything "
             "in the first two panels is decoded from it — no new writer, one json.loads."),
         job(spec["surfaces"]["job"])]

    rs = rows_of("surfaces", "_surfaces_ai_band")
    hdr = ["host", "stage", "port", "kind", "auth", "product", "decoded from meta_json"]
    body = []
    for r in rs:
        try:
            meta = json.loads(r["meta_json"] or "{}")
        except Exception:  # noqa: BLE001
            meta = {}
        kv = "".join(f"<dt>{e(k)}</dt><dd>{e(json.dumps(v) if isinstance(v, (list, dict)) else v)}</dd>"
                     for k, v in meta.items()) or "<dt class='dim'>—</dt><dd class='dim'>empty</dd>"
        body.append([hl(r["ip"]) + f"<div class='dim' style='font-size:.7rem'>{e(r['hostname'] or '')}</div>",
                     stage_badge(r["stage"]), mono(f"{r['port']}/{r['proto']}"),
                     chip(r["kind"], "#e83bb0"), e(r["auth"]), e(r["product"] or "—"),
                     f"<dl class='kv' style='padding:0'>{kv}</dl>"])
    b += [sec("AI surfaces — every probe hit, decoded"),
          card(tbl(hdr, body, "no AI surfaces detected yet"),
               "Unknown keys render verbatim, so a new probe needs no UI change. The probes "
               "currently discard MCP tool descriptions, A2A skills and Qdrant collection names "
               "(see §7.3 of the design) — those columns appear here the day the probe keeps them.")]

    rs = rows_of("surfaces", "_surfaces_asset_rollup")
    if rs:
        body2 = [[chip(r["asset_class"], "#c05bd8"), mono(r["asset"]),
                  mono(r["seen_on"]), e(r["kinds"])] for r in rs]
        b += [sec("Estate asset rollup — every model, tool, endpoint and API path"),
              card(tbl(["class", "asset", "seen on", "surface kinds"], body2),
                   "One row per distinct thing the probes named anywhere in the estate.")]

    for fn in ("_surfaces_service_inventory", "_surfaces_http_endpoints", "_surfaces_cve_match",
               "_surfaces_software", "_surfaces_webpaths", "_surfaces_kind_brief"):
        b.append(generic("surfaces", fn, cap=14))
    return shell("surfaces", "\n".join(x for x in b if x))


# ============================ IDENTITY =====================================
def page_identity():
    b = [bar("Identity", "The lockout threshold is a <b>pre-flight safety fact</b> and today it is "
             "readable only by sprayer.py. It renders in three never-collapsed states."),
         job(spec["identity"]["job"])]

    rs = rows_of("identity", "_identity_spray_safety") or rows_of("identity", "_identity_domain_header")
    cells = []
    for r in rs:
        k = r.keys()
        thr = r["lockout_threshold"] if "lockout_threshold" in k else None
        if thr is None:
            badge = "<span class='lk unk'>UNKNOWN — guard NOT engaged</span>"
        elif int(thr) == 0:
            badge = "<span class='lk none'>NO LOCKOUT (0)</span>"
        else:
            badge = f"<span class='lk set'>LOCKOUT AT {e(thr)}</span>"
        cells.append([
            e(r["domain"] if "domain" in k else "—"), badge,
            e(r["min_length"] if "min_length" in k else "—"),
            e(r["lockout_window_min"] if "lockout_window_min" in k else "—"),
            e(r["complexity"] if "complexity" in k else "—"),
            mono(r["source"] if "source" in k else "—"),
        ])
    if not cells:
        cells = [["—", "<span class='lk unk'>UNKNOWN — guard NOT engaged</span>", "—", "—", "—",
                  "<span class='dim'>no password_policy row</span>"]]
    b += [sec("Spray safety — observed password policy"),
          card(tbl(["domain", "lockout", "min len", "window (min)", "complexity", "source"], cells),
               "No row at all is rendered as UNKNOWN, never as safe. This band is mirrored onto "
               "/vault, because that is the page you open immediately before spraying.")]

    rs = rows_of("identity", "_identity_roster")
    if rs:
        hdr = ["principal", "type", "rid", "spn", "description", "source"]
        body = []
        for r in rs:
            desc = r["description"] or ""
            low = desc.lower()
            if any(w in low for w in ("pass", "pwd", "temp", "welcome", "secret", "cred")):
                desc = f"<span class='leak'>{e(desc)}</span>"
            else:
                desc = e(desc) or "<span class='dim'>—</span>"
            body.append([f"<b class='mono'>{e(r['name'])}</b>", chip(r["type"]),
                         mono(r["rid"] or "—"),
                         (mono(r["spn"]) if r["spn"] else "<span class='dim'>—</span>"),
                         desc, e(r["source"] or "")])
        b += [sec("Principal roster"),
              card(tbl(hdr, body),
                   "The description column is the point: ldap_user_descriptions is a real playbook "
                   "rule (T1552.001), yhwach stores what it finds, and no renderer anywhere shows "
                   "it today. Highlighting is a plain keyword hint, not a verdict.")]

    for fn in ("_identity_privileges", "_identity_shares", "_identity_edges",
               "_identity_inventory", "_identity_lockout_proxy"):
        b.append(generic("identity", fn, cap=14))
    return shell("identity", "\n".join(x for x in b if x))


# ============================== VAULT ======================================
def page_vault():
    b = [bar("Vault", "Today a <b>proven failure renders in the same green cell as a success</b>. "
             "The access column is split, and the matrix and spray feed move here off the Board."),
         job(spec["vault"]["job"])]

    rs = rows_of("vault", "_vault_table")
    hdr = ["user", "secret", "kind", "access (proven / failed)", "validated on", "source"]
    body = []
    for r in rs:
        k = r.keys()
        prov = int(r["n_proven"] or 0) if "n_proven" in k else 0
        adm = int(r["n_admin"] or 0) if "n_admin" in k else 0
        fail = int(r["n_failed"] or 0) if "n_failed" in k else 0
        acc = []
        if prov:
            acc.append(f"<span class='mk y'>{prov} proven{' ★' if adm else ''}</span>")
        if fail:
            acc.append(f"<span class='mk n'>{fail} failed</span>")
        if not acc:
            acc = ["<span class='mk z'>untried</span>"]
        body.append([f"<b class='mono'>{e(r['identifier'])}</b>",
                     f"<code class='mono'>{e(r['secret'])}</code>",
                     chip(r["kind"]), " ".join(acc),
                     (mono(r["validated_on_host_ip"]) if r["validated_on_host_ip"]
                      else "<span class='dim'>—</span>"),
                     f"<span class='dim' style='font-size:.72rem'>{e(r['source'])}</span>"])
    b += [sec("Credential vault"),
          card(tbl(hdr, body, "no credentials captured yet"),
               "★ marks an admin-level proof. A failed logon is a fact worth as much as a "
               "successful one — it tells you the account is wrong, not the password.")]

    for fn in ("_spray_safety_band", "_cred_service_matrix", "_spray_feed", "_vault_access_ledger"):
        b.append(generic("vault", fn, cap=14))
    return shell("vault", "\n".join(x for x in b if x))


# =============================== MAP =======================================
def page_map():
    b = [bar("Map", "The demo holds a tunnel to <code class='mono'>10.30.0.0/24</code> via "
             "dbhost01 and that string appears <b>nowhere</b> on /map today. A tunnelled subnet "
             "with zero discovered hosts is exactly the segment you have not touched."),
         job(spec["map"]["job"])]
    for fn in ("_reach_table", "_segment_inventory", "_reach_tree", "_host_cards", "_interfaces"):
        b.append(generic("map", fn, cap=14))
    return shell("map", "\n".join(x for x in b if x))


# =============================== POC =======================================
def page_poc():
    b = [bar("PoC", "With <b>three captured objectives</b> in this DB the current tab renders "
             "“no PoC steps recorded yet” and lists nothing — it derives its list from poc_step "
             "events, so a flag you cannot prove is invisible. Here every objective appears."),
         job(spec["poc"]["job"])]
    for fn in ("_poc_chain_inventory", "_poc_chain_steps", "_poc_proof_integrity",
               "_poc_unchained_wins", "_poc_bundle"):
        b.append(generic("poc", fn, cap=14))
    return shell("poc", "\n".join(x for x in b if x))


# ============================== REPORT =====================================
def page_report():
    b = [bar("Report", "“Recommended next steps” is suppressed. What replaces it is an "
             "<b>evidence gap inventory</b> — what lacks proof, stated as a fact, not a task list."),
         job(spec["report"]["job"])]
    for fn in ("_report_gaps", "_report_state", "_report_full"):
        b.append(generic("report", fn, cap=16))
    return shell("report", "\n".join(x for x in b if x))


# =============================== BOARD =====================================
def page_board():
    b = [bar("Board", "Composition only — no new data. The network map moves to /map and the "
             "three vault panels to /vault (each was rendered twice), the uncapped tables get a "
             "25-row cap, and “Next moves — the recall menu” is renamed to what it is."),
         job(spec["board"]["job"])]
    for fn in ("_applicability_panel", "_topology_strip", "_vault_strip", "_standards_inventory",
               "_coverage_panel", "_hosts", "_findings"):
        p = panel("board", fn)
        if not p:
            continue
        if fn == "_applicability_panel":
            b += [sec("Applicability inventory — techniques possible per surface, by risk tier"),
                  card("<p class='empty' style='padding:.9rem'>Renamed from “Next moves — the "
                       "recall menu”. Same deterministic, unranked content from "
                       "<code class='mono'>nextmoves.next_moves()</code>; the heading now "
                       "describes what it is rather than implying an order.</p>",
                       "No query change. The panel also moves below the factual inventories.")]
            continue
        b.append(generic("board", fn, cap=12))
    return shell("board", "\n".join(x for x in b if x), page_title="Yhwach Tab Mockups")


PAGES = [("index.html", page_board), ("recon.html", page_recon),
         ("surfaces.html", page_surfaces), ("identity.html", page_identity),
         ("map.html", page_map), ("vault.html", page_vault),
         ("poc.html", page_poc), ("report.html", page_report)]

if __name__ == "__main__":
    for name, fn in PAGES:
        try:
            (OUT / name).write_text(fn(), encoding="utf-8")
            print(f"  wrote {name:16s} {(OUT / name).stat().st_size:>7,} bytes")
        except Exception as exc:  # noqa: BLE001
            print(f"  FAILED {name}: {type(exc).__name__}: {exc}")
