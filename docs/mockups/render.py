"""Render the 8 proposed yhwach tabs as static mockups.

Real data from the seeded demo DB, real markup idioms, yhwach's own ui._CSS plus
the proposed figure/ground patch. The signature panels (where the encoding IS the
design) are hand-rendered; the rest render generically from their verified query
so every panel on every page shows true rows.
"""
from __future__ import annotations

import html
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from yhwach import ui as yui  # noqa: E402

SPEC = Path(sys.argv[1])
DB = Path(sys.argv[2])
OUT = Path(sys.argv[3])
LAB = "demo_lab"
EID = 1

_CSS_PATCH = """
/* ---- PROPOSED (review 1): figure/ground + type scale ---- */
:root{ --surface:#241d24; --surface2:#2f2630; --line:#5a3a53; --line-strong:#7a4a6d; }
.card,.path,.gazewrap,.netwrap,.hostwrap{border-color:var(--line-strong);
  box-shadow:0 1px 0 rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.03)}
h2.sec{font-size:.95rem;color:var(--ink);letter-spacing:.1em;margin:1.9rem 0 .8rem}
.card{overflow-x:auto;overflow-y:hidden}
/* ---- mockup chrome ---- */
.mockbar{background:rgba(232,59,176,.09);border:1px solid #8a1f68;border-radius:9px;
  padding:.65rem .9rem;margin:0 0 1.4rem;font-size:.78rem;color:var(--ink2);line-height:1.6}
.mockbar b{color:var(--accent)}
.pnote{color:var(--muted);font-size:.72rem;padding:.5rem .85rem;border-top:1px solid var(--line);
  font-style:italic}
.job{color:var(--ink2);font-size:.86rem;margin:.1rem 0 1.4rem;max-width:80ch}
.ok{color:#6bb36b}.bad{color:#e06767}.warn{color:#d9a441}.dim{color:var(--muted)}
.mk{font-family:ui-monospace,monospace;font-weight:700;text-align:center;font-size:.9rem}
.mk.y{color:#7be07b;background:rgba(12,163,12,.16)}
.mk.n{color:#e67878;background:rgba(208,59,59,.13)}
.mk.p{color:#d9a441;background:rgba(217,164,65,.13)}
.mk.z{color:var(--muted)}
.lk{display:inline-block;padding:.12rem .5rem;border-radius:5px;font-size:.7rem;font-weight:700;
  letter-spacing:.04em}
.lk.none{color:#7be07b;background:rgba(12,163,12,.18);border:1px solid #0ca30c}
.lk.set{color:#d9a441;background:rgba(217,164,65,.16);border:1px solid #d9a441}
.lk.unk{color:#e67878;background:rgba(208,59,59,.16);border:1px solid #d03b3b}
.kv{display:grid;grid-template-columns:minmax(110px,auto) 1fr;gap:.2rem .7rem;font-size:.76rem;
  padding:.5rem .85rem}
.kv dt{color:var(--accent);font-family:ui-monospace,monospace;font-size:.7rem}
.kv dd{margin:0;color:var(--ink2);font-family:ui-monospace,monospace;word-break:break-all}
.leak{color:#ffd166;background:rgba(250,178,25,.12);padding:.05rem .3rem;border-radius:3px}
"""

NAV = [("board", "index.html", "Board"), ("recon", "recon.html", "Recon"),
       ("surfaces", "surfaces.html", "Surfaces"), ("identity", "identity.html", "Identity"),
       ("map", "map.html", "Map"), ("vault", "vault.html", "Vault"),
       ("poc", "poc.html", "PoC"), ("report", "report.html", "Report")]


def e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row
with SPEC.open(encoding="utf-8") as _f:
    spec = {t["key"]: t for t in json.load(_f)}


def panel(key: str, fn: str):
    for p in spec[key]["panels"]:
        if p["fn"] == fn:
            return p
    return None


def rows_of(key: str, fn: str, i: int = 0):
    p = panel(key, fn)
    if not p or not p["queries"] or i >= len(p["queries"]):
        return []
    q = p["queries"][i]
    try:
        sql = q["sql"]
        if ":eid" in sql:
            return conn.execute(sql, {"eid": EID}).fetchall()
        for n in range(10):
            try:
                return conn.execute(sql, tuple([EID] * n)).fetchall()
            except sqlite3.ProgrammingError:
                continue
    except Exception:  # noqa: BLE001
        return []
    return []


# ---- markup ---------------------------------------------------------------

def sec(t): return f"<h2 class='sec'>{e(t)}</h2>"


def card(inner, note=None):
    n = f"<div class='pnote'>{note}</div>" if note else ""
    return f"<div class='card'>{inner}{n}</div>"


def tbl(headers, rows, empty="none"):
    if not rows:
        return f"<p class='empty' style='padding:.9rem'>{e(empty)}</p>"
    th = "".join(f"<th>{e(h)}</th>" for h in headers)
    tb = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{tb}</tbody></table>"


def chip(t, c=None):
    s = f" style='color:{c};background:{c}22'" if c else ""
    return f"<span class='chip'{s}>{e(t)}</span>"


def mono(v): return f"<code class='mono'>{e(v)}</code>"


def hl(ip): return f"<a href='#' class='mono' style='color:inherit;border-bottom:1px dotted #8a1f68'>{e(ip)}</a>"


def stage_badge(s):
    return chip(s, yui._STAGE.get(s, "#5b626d"))


def generic(key, fn, *, cap=14, cols=None):
    """Render a panel from every one of its verified queries that returned rows.

    Several panels are specified as a set of statements (an inventory plus its
    sub-counts); showing only the first would misrepresent the panel.
    """
    p = panel(key, fn)
    if not p:
        return ""
    blocks, shown = [], 0
    for i, _q in enumerate(p["queries"]):
        rs = rows_of(key, fn, i)
        if not rs:
            continue
        shown += 1
        keys = list(rs[0].keys()) if cols is None else cols
        body = [[mono(r[k]) if k in ("ip", "port", "path", "sid") else e(r[k]) for k in keys]
                for r in rs[:cap]]
        note = f"{len(rs)} row(s)" + (f" · showing {cap}" if len(rs) > cap else "")
        if len(p["queries"]) > 1:
            note = f"query {i + 1} of {len(p['queries'])} · {note}"
        blocks.append(card(tbl(keys, body), note))
    if not blocks:
        return sec(p["heading"]) + card(
            f"<p class='empty' style='padding:.9rem'>{e(p['empty_state'] or 'none')}</p>",
            "every query for this panel returned zero rows against the demo DB")
    return sec(p["heading"]) + "\n".join(blocks)


def shell(active, body, page_title=None):
    nav = "".join(f"<a href='{href}' class='{'on' if active == key else ''}'>{label}</a>"
                  for key, href, label in NAV)
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{e(page_title or f'yhwach — {LAB} — {active}')}</title>"
            f"<style>{yui._CSS}{_CSS_PATCH}</style></head><body><div class='wrap'>"
            f"<header class='top'>{yui._EYE}<div class='brand'><h1>Yhwach</h1>"
            f"<span class='sub'>engagement <b>{e(LAB)}</b></span></div>"
            f"<div class='spacer'></div><nav>{nav}</nav></header>{body}</div></body></html>")


def bar(tab, note):
    return (f"<div class='mockbar'><b>MOCKUP · {e(tab)}</b> — real rows from the seeded "
            f"<code class='mono'>demo_lab</code> DB, rendered with yhwach's own "
            f"<code class='mono'>ui._CSS</code> plus the proposed figure/ground patch. {note}</div>")


def job(t): return f"<p class='job'>{e(t)}</p>"
