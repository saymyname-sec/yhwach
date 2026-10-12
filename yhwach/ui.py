"""UI: the yhwach live board — a pure read view over the memory DB.

A dashboard over the engagement memory: the pivot tree, the credential vault,
hosts/tags/findings and the attack path. It talks to the world model
**read-only** — no control surface, so a crashed or hostile UI can't corrupt the
memory (drive the engagement from the CLI/MCP). The kill-switch/approval-inbox
were removed along with the self-driving runtime.

Design: a self-contained dark console styled after Yhwach's "The Almighty" — a
black, many-eyed oracle in a magenta reishi storm (void black + Almighty magenta
+ imperial purple; the eye mark sees every path). No build step and **no external
CDN**: the page polls a server-rendered fragment with a few lines of inline JS,
so it works offline on an engagement host. Severity uses the validated
dark-surface status palette (dataviz); the magenta is chrome only and is
hue-separated from the status ramp, so identity is never colour-alone.

Optional dependency: `pip install 'yhwach[ui]'` (FastAPI + uvicorn).
"""

from __future__ import annotations

import html
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse

from yhwach import db as yhdb

AI_KINDS = {
    "ollama",
    "gradio",
    "openwebui",
    "chatbot",
    "rag",
    "mcp",
    "a2a",
    "vectordb",
    "openai_compat",
}

# A worker heartbeat older than this (seconds) is treated as stale — the worker
# went away or the run stopped. The board polls every 3s, so ~25s = missed
# several beats.
_WORKER_STALE_SECS = 25

# Worker heartbeat status -> board colour (magenta = live, green done, red fail).
_HB_COL = {"watching": "#e83bb0", "running": "#e83bb0", "done": "#0ca30c",
           "fail": "#d03b3b", "idle": "#7f8792"}

# A few tags carry meaning worth colouring; everything else gets the neutral chip.
_TAG_COL = {
    "dead-end": "#856176", "decoy": "#856176", "blocked": "#d03b3b", "gated": "#fab219",
    "ai-target": "#e83bb0", "ai-exploited": "#e83bb0", "objective": "#e83bb0",
    "domain-admin": "#0ca30c", "tier0": "#ec835a", "dual-homed": "#c05bd8",
    "flag-captured": "#0ca30c",
}


def _derive_role(products: list[str], surface_kinds: set[str]) -> str:
    """A best-effort 'what does this box mainly host' label from its services +
    surfaces, used only when the operator hasn't set an explicit role."""
    p = " ".join(products).lower()
    if surface_kinds & AI_KINDS:
        return "AI surface"
    if "kerberos" in p or ("ldap" in p and "microsoft" in p):
        return "Domain Controller"
    if "jenkins" in p:
        return "Jenkins CI"
    if "activemq" in p or "amqp" in p or "mqtt" in p:
        return "Message broker"
    if "microsoft-ds" in p or "netbios" in p:
        return "Windows host"
    for kw, label in (("jetty", "Java web"), ("nginx", "Web"), ("apache", "Web"),
                      ("openssh", "Linux host"), ("mysql", "Database"),
                      ("mssql", "Database"), ("postgres", "Database")):
        if kw in p:
            return label
    return ""


def _tag_chips(tags: list[str]) -> str:
    """Render host tags as coloured chips."""
    out = ""
    for t in tags:
        c = _TAG_COL.get(t, "#856176")
        out += (f"<span class='chip' style='color:{c};background:{c}22;margin:1px 2px'>"
                f"{_esc(t)}</span>")
    return out

# Severity -> validated dark-surface status colour (dataviz status palette).
_SEV = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#7f8792",
}
# Host FSM stage -> colour + rank (rank orders the attack-path flow, left->right).
_STAGE = {
    "undiscovered": "#5b626d",
    "scanned": "#3987e5",
    "enumerated": "#199e70",
    "foothold": "#fab219",
    "looted": "#ec835a",
    "pivoted": "#c05bd8",
    "done": "#0ca30c",
    "blocked": "#d03b3b",
}
_RANK = {
    "undiscovered": 0,
    "scanned": 1,
    "blocked": 1,
    "enumerated": 2,
    "foothold": 3,
    "looted": 4,
    "pivoted": 5,
    "done": 6,
}
_OWNED = ("foothold", "looted", "pivoted", "done")

# The Almighty palette, read off the character: void black, Almighty magenta,
# imperial purple, pale reishi highlight.
_CSS = """
:root{
  /* Figure/ground: --surface used to sit at 1.04:1 against --bg and --line at
     1.21:1 against the card, so panels had neither a visible fill nor a visible
     border and every table rule drew nothing. These are 1.23:1 and 1.70:1 —
     1.7:1 is where a 1px hairline becomes readable on a dark ground. --muted
     still clears 4.5:1 on the new surface, so AA holds. */
  --bg:#0a0509; --surface:#241d24; --surface2:#2f2630; --line:#5a3a53;
  --line-strong:#7a4a6d;
  --ink:#f4e9f1; --ink2:#c9adc2; --muted:#a3839a;
  --accent:#e83bb0; --accent2:#8a1f68; --glow:rgba(232,59,176,.55);
  --ok:#0ca30c; --danger:#d03b3b;
}
*{box-sizing:border-box}
body{margin:0;background:
  radial-gradient(1100px 520px at 50% -260px, rgba(232,59,176,.20), transparent 62%),
  radial-gradient(760px 420px at 88% -60px, rgba(138,31,104,.22), transparent 66%),
  radial-gradient(680px 380px at 6% 8%, rgba(120,40,110,.12), transparent 60%),
  var(--bg);
  color:var(--ink);font:14px/1.55 ui-monospace,"SF Mono",Menlo,Consolas,monospace}
a{color:var(--accent);text-decoration:none}
a:focus-visible,button:focus-visible,details:focus-visible summary{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.wrap{max-width:1120px;margin:0 auto;padding:1.4rem 1.4rem 3rem}
header.top{display:flex;align-items:center;gap:.95rem;padding:.2rem 0 1.15rem;
  border-bottom:1px solid var(--line);margin-bottom:1.3rem}
.eye{flex:0 0 auto;filter:drop-shadow(0 0 7px var(--glow))}
.brand{display:flex;flex-direction:column;gap:.12rem}
.brand h1{margin:0;font-size:1.2rem;letter-spacing:.32em;font-weight:700;
  text-transform:uppercase;
  background:linear-gradient(92deg,#f7d7ee,#e83bb0 55%,#8a1f68);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.brand .sub{color:var(--ink2);font-size:.76rem;letter-spacing:.16em;text-transform:uppercase}
.brand .sub b{color:var(--accent);font-weight:600}
.spacer{flex:1}
nav a{color:var(--ink2);padding:.35rem .8rem;border-radius:8px;font-size:.82rem}
nav a:hover{color:var(--ink)}
nav a.on{color:var(--ink);background:var(--surface2);border:1px solid var(--line)}
.runbadge{display:inline-flex;align-items:center;gap:.45rem;padding:.3rem .7rem;border-radius:999px;
  font-size:.78rem;border:1px solid var(--line);background:var(--surface)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.dot.live{background:var(--accent);box-shadow:0 0 0 3px rgba(232,59,176,.20);animation:p 1.6s infinite}
@keyframes p{50%{opacity:.4}}
.kill{background:var(--danger);color:#fff;border:0;padding:.4rem .9rem;border-radius:8px;cursor:pointer;font:inherit;font-weight:600}
.kill:hover{filter:brightness(1.12)}
/* A section heading used to render at .74rem against .86rem table rows — smaller
   than the content it labels. It now outranks the rows. */
h2.sec{font-size:.95rem;text-transform:uppercase;letter-spacing:.1em;color:var(--ink);margin:1.9rem 0 .8rem;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.8rem}
.tile{background:linear-gradient(180deg,var(--surface2),var(--surface));
  border:1px solid var(--line);border-radius:12px;padding:.9rem 1rem}
.tile .k{color:var(--ink2);font-size:.72rem;text-transform:uppercase;letter-spacing:.1em}
.tile .v{font-size:1.7rem;font-weight:600;margin-top:.25rem;font-variant-numeric:tabular-nums}
.tile .v small{font-size:.9rem;color:var(--ink2);font-weight:400}
.sevbar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin-top:.6rem;background:var(--surface2);gap:2px}
.sevbar span{display:block}
.sevleg{display:flex;gap:.7rem;margin-top:.5rem;flex-wrap:wrap;font-size:.72rem;color:var(--ink2)}
.sevleg i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:.3rem;vertical-align:middle}
/* overflow-x:auto, not hidden: a wide table used to be clipped dead at any
   window under ~1340px with no scrollbar (the vault lost its whole `source`
   column). overflow-y stays hidden so the rounded corners still clip. */
.card{background:var(--surface);border:1px solid var(--line-strong);border-radius:12px;
  overflow-x:auto;overflow-y:hidden;box-shadow:0 1px 0 rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.03)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.55rem .85rem;border-bottom:1px solid var(--line);font-size:.86rem}
th{color:var(--ink2);font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--surface2)}
.badge{display:inline-block;padding:.12rem .55rem;border-radius:999px;font-size:.74rem;font-weight:600;
  border:1px solid transparent}
.chip{display:inline-block;padding:.05rem .5rem;border-radius:6px;font-size:.72rem;font-weight:600;
  white-space:nowrap}
/* A host IP that links to its own page, without turning a table into a wall of
   magenta: keeps the row's colour, marks itself with a dotted underline. */
.hl{color:inherit;border-bottom:1px dotted var(--accent2);text-decoration:none}
.hl:hover{color:var(--accent);border-bottom-color:var(--accent)}
/* /recon marks: done / not-done / partial, as a glyph AND a colour so the cell
   never depends on hue alone. */
.mk{font-family:ui-monospace,monospace;font-weight:700;font-size:.82rem;
  display:inline-block;min-width:1.9em;text-align:center;padding:.05rem .3rem;border-radius:4px}
.mk.y{color:#7be07b;background:rgba(12,163,12,.16)}
.mk.n{color:#e67878;background:rgba(208,59,59,.13)}
.mk.p{color:#e0b64a;background:rgba(217,164,65,.14)}
.sub2{color:var(--muted);font-size:.7rem;line-height:1.3}
.muted{color:var(--muted)}
/* /identity: the lockout badge has three states and NO ROW AT ALL is one of
   them — an unobserved policy is the dangerous case, not an absent one. */
.lk{display:inline-block;padding:.12rem .5rem;border-radius:5px;font-size:.7rem;
  font-weight:700;letter-spacing:.04em;white-space:nowrap}
.lk.none{color:#7be07b;background:rgba(12,163,12,.18);border:1px solid #0ca30c}
.lk.set{color:#e0b64a;background:rgba(217,164,65,.16);border:1px solid #d9a441}
.lk.unk{color:#e67878;background:rgba(208,59,59,.16);border:1px solid #d03b3b}
/* A description that looks like it carries a secret. A hint for the eye, never
   a verdict — ldap_user_descriptions (T1552.001) is why this column exists. */
.leak{color:#ffd166;background:rgba(250,178,25,.12);padding:.05rem .3rem;border-radius:3px}
.kv{display:grid;grid-template-columns:minmax(70px,auto) 1fr;gap:.1rem .6rem;margin:0;
  font-size:.72rem}
.kv dt{color:var(--accent);font-family:ui-monospace,monospace;font-size:.68rem}
.kv dd{margin:0;color:var(--ink2);font-family:ui-monospace,monospace;word-break:break-all}
.star{color:var(--accent);font-size:.72rem;margin-left:.3rem}
.approve{background:var(--ok);color:#fff;border:0;padding:.28rem .8rem;border-radius:7px;cursor:pointer;font:inherit;font-size:.8rem}
.approve:hover{filter:brightness(1.12)}
.empty{color:var(--muted);padding:.6rem .2rem;font-style:italic}
.mono{color:var(--ink2)}
.tl{list-style:none;margin:0;padding:0}
.tl li{display:flex;gap:.8rem;padding:.4rem .2rem;border-bottom:1px solid var(--line);font-size:.84rem}
.tl li:last-child{border-bottom:0}
.tl .t{color:var(--muted);white-space:nowrap;font-size:.78rem}
.tl .e{font-weight:600}
/* attack path */
.path{background:
  radial-gradient(600px 200px at 12% -40px, rgba(232,59,176,.10), transparent 70%),
  var(--surface);
  border:1px solid var(--line);border-radius:12px;padding:1rem 1.1rem}
.flow{display:flex;align-items:stretch;gap:.2rem;flex-wrap:wrap}
.node{position:relative;min-width:132px;background:var(--surface2);border:1px solid var(--line);
  border-left:3px solid var(--muted);border-radius:10px;padding:.55rem .7rem;margin:.25rem 0}
.node .ip{font-weight:700;font-size:.9rem}
.node .st{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em}
.node .meta{color:var(--ink2);font-size:.74rem;margin-top:.15rem}
.node.crown{border-left-color:var(--accent);border-color:var(--accent2);
  background:linear-gradient(180deg,rgba(232,59,176,.12),var(--surface2))}
.node.crown.won{border-left-color:var(--ok)}
.arrow{align-self:center;color:var(--accent);font-size:1.15rem;padding:0 .15rem;opacity:.8}
.edges{margin-top:.85rem;display:flex;flex-direction:column;gap:.3rem}
.edge{display:flex;align-items:center;gap:.5rem;font-size:.82rem;flex-wrap:wrap}
.edge code{color:var(--ink)}
.edge .k{color:var(--accent);font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;
  border:1px solid var(--accent2);border-radius:5px;padding:.02rem .4rem}
.edge.hot .k{background:rgba(232,59,176,.16)}
.pathnote{color:var(--ink2);font-size:.78rem;margin-top:.75rem}
.pathnote b{color:var(--accent)}
/* the gaze — orchestrator + workers */
.gazewrap{background:
  radial-gradient(720px 260px at 50% 118%, rgba(232,59,176,.16), transparent 62%),
  var(--surface);border:1px solid var(--line);border-radius:12px;padding:1rem 1.1rem}
.gazehead{display:flex;align-items:center;gap:.8rem;margin-bottom:.3rem;flex-wrap:wrap}
.gazehead .lbl{font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:.78rem}
.gazehead .meta{color:var(--ink2);font-size:.78rem}
.gaze{display:block;margin:.1rem auto .3rem;max-width:100%}
.gz-halo{transform-box:fill-box;transform-origin:center;animation:gzp 1.7s ease-in-out infinite}
@keyframes gzp{0%,100%{opacity:.15}50%{opacity:.5}}
.gz-line{stroke:#8a1f68;stroke-opacity:.5}
.gz-line.on{stroke:#e83bb0;stroke-opacity:.85;animation:gzl 1.7s ease-in-out infinite}
@keyframes gzl{50%{stroke-opacity:.35}}
.wke{filter:drop-shadow(0 0 4px rgba(232,59,176,.4))}
.wkgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(244px,1fr));gap:.7rem;margin-top:.5rem}
.wk{display:flex;align-items:center;gap:.65rem;background:var(--surface2);border:1px solid var(--line);
  border-left:3px solid var(--muted);border-radius:10px;padding:.6rem .7rem}
.wk.on{border-left-color:var(--accent);box-shadow:inset 0 0 0 1px rgba(232,59,176,.25)}
.wk-b{flex:1;min-width:0}
.wk-ip{font-weight:700;font-size:.86rem}
.wk-focus{font-size:.78rem;margin-top:.12rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.wk-focus .rid{color:var(--accent);font-weight:600}
.wk-meta{color:var(--ink2);font-size:.72rem;margin-top:.1rem}
.wk-st{flex:0 0 auto}
.report{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:1.2rem 1.4rem;
  white-space:pre-wrap;word-wrap:break-word;font-size:.86rem;line-height:1.7}
.report .r-h1{font-size:1.15rem;font-weight:700;color:var(--ink);margin:.2rem 0 .6rem}
.report .r-h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.1em;color:var(--accent);margin:1.1rem 0 .4rem;font-weight:700}
.report.annot{border-left:3px solid var(--accent2)}
.report.annot.stale{opacity:.6}
.annot-by{color:var(--muted);font-size:.7rem;margin-bottom:.4rem}
.report .r-h3{font-size:.84rem;font-weight:700;color:var(--ink2);margin:.7rem 0 .25rem}
.report .r-li{padding-left:1.1rem}
/* report.py emits pipe tables throughout; they used to render as literal text. */
.report .r-t{width:100%;border-collapse:collapse;margin:.4rem 0 .8rem;font-size:.78rem}
.report .r-t th,.report .r-t td{text-align:left;padding:.3rem .55rem;
  border-bottom:1px solid var(--line);vertical-align:top}
.report .r-t th{color:var(--ink2);font-size:.7rem;text-transform:uppercase;letter-spacing:.06em}
.dlrow{display:flex;gap:.7rem;margin:.2rem 0 1.1rem;flex-wrap:wrap}
.dl{background:var(--surface2);border:1px solid var(--line);color:var(--ink);padding:.45rem .9rem;border-radius:8px;font-size:.82rem}
.dl:hover{border-color:var(--accent)}
/* living eyes — every pupil follows the cursor (JS-driven), eased so it feels alive */
.pupil{transform-box:fill-box;transform-origin:center}
.eye-pupil{transform-box:fill-box;transform-origin:center;transition:transform .12s ease-out;will-change:transform}
/* the header crest: a touch bigger, lifts + brightens on hover */
.eye{transition:transform .2s ease,filter .2s ease;cursor:pointer}
.eye:hover{transform:scale(1.06);filter:drop-shadow(0 0 11px var(--glow))}
/* blink: hold open, snap shut for a beat, reopen */
.crest-blink{animation:blink 6.5s ease-in-out infinite}
@keyframes blink{0%,93%,100%{transform:scaleY(1)}96%{transform:scaleY(.12)}}
@media (prefers-reduced-motion: reduce){.crest-blink{animation:none}}
/* gentle life on hover for cards/tiles/nodes */
.tile,.wk,.nethost{transition:transform .15s ease,border-color .15s ease,box-shadow .15s ease}
.tile:hover,.wk:hover,.nethost:hover{transform:translateY(-2px);border-color:var(--accent2)}
.sevbar span{animation:grow .7s ease-out both}
@keyframes grow{from{transform:scaleX(0);transform-origin:left}to{transform:scaleX(1)}}
/* network map */
.netwrap{background:
  radial-gradient(680px 320px at 50% 42%, rgba(232,59,176,.12), transparent 66%),
  var(--surface);border:1px solid var(--line);border-radius:12px;padding:1rem 1.1rem}
.nethead{display:flex;align-items:center;gap:.8rem;margin-bottom:.2rem;flex-wrap:wrap}
.nethead .lbl{font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:.78rem}
.nethead .meta{color:var(--ink2);font-size:.78rem}
.netmap{display:block;margin:.1rem auto .4rem;max-width:100%}
.nn-edge{stroke:#8a1f68;stroke-opacity:.5;transition:stroke .12s,stroke-opacity .12s,stroke-width .12s}
.nn-edge.owned{stroke:#e83bb0;stroke-opacity:.8}
/* hover a host → its whole route back to the operator lights up */
.nn-edge.hot{stroke:#f7d7ee;stroke-opacity:1;stroke-width:3}
.nn-ring{fill:none;stroke-opacity:.9}
.nn-pulse{transform-box:fill-box;transform-origin:center;animation:nnp 2s ease-in-out infinite}
@keyframes nnp{0%,100%{opacity:.25}50%{opacity:.6}}
.netgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:.7rem;margin-top:.55rem}
.nethost{background:var(--surface2);border:1px solid var(--line);border-left:3px solid var(--muted);
  border-radius:10px;padding:.6rem .75rem}
.nethost .hh{display:flex;align-items:baseline;gap:.5rem;flex-wrap:wrap}
.nethost .hip{font-weight:700;font-size:.9rem}
.nethost .hn{color:var(--ink2);font-size:.74rem}
.nethost .hmeta{color:var(--ink2);font-size:.72rem;margin:.15rem 0 .4rem}
.ports{display:flex;flex-direction:column;gap:.2rem}
.port{display:flex;align-items:baseline;gap:.5rem;font-size:.78rem;white-space:nowrap;overflow:hidden}
.port.port-dim{opacity:.5}
.port .pn{color:var(--accent);font-weight:600;font-variant-numeric:tabular-nums;min-width:64px;flex:none}
.port .ps{color:var(--ink);flex:none}
.port .pv{color:var(--muted);font-size:.72rem;flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis}
.details-fails summary,details.fails summary{list-style:revert}
/* refresh toolbar + critical toast */
.rtoolbar{display:flex;align-items:center;gap:.5rem;margin-right:.6rem}
.upd{color:var(--ink2);font-size:.72rem;white-space:nowrap}
.mini{background:var(--surface2);border:1px solid var(--line);color:var(--ink);
  border-radius:8px;padding:.25rem .5rem;cursor:pointer;font:inherit;font-size:.8rem}
.mini:hover{border-color:var(--accent)}
.toast{position:fixed;right:1rem;bottom:1rem;z-index:50;background:#2a0d12;
  border:1px solid var(--danger);color:#ffd9d9;padding:.7rem 1rem;border-radius:10px;
  font-size:.86rem;font-weight:600;box-shadow:0 8px 28px rgba(208,59,59,.35);
  animation:tin .25s ease-out}
@keyframes tin{from{transform:translateY(10px);opacity:0}to{transform:translateY(0);opacity:1}}
/* live command ticker on worker cards */
.wk-cmd{color:var(--ink2);font-size:.72rem;margin-top:.12rem;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,monospace}
.wk-cmd b{color:var(--ok);font-weight:600}
/* host focus page */
.hostwrap{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.3rem}
.back{display:inline-block;margin-bottom:.8rem;font-size:.82rem}
.nn-node{cursor:pointer}
.nn-node:hover .nn-ring{stroke-width:3.4}
.subhdr{color:var(--accent);font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;
  font-weight:700;margin:.9rem 0 .3rem;grid-column:1/-1}
/* PR-4: host stage board */
.stageboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:.75rem;margin-bottom:.6rem}
.stagecol{background:var(--surface2);border:1px solid var(--line);border-radius:8px;
  padding:.5rem .55rem}
.stagehdr{display:flex;justify-content:space-between;align-items:center;
  padding-bottom:.35rem;border-bottom:1px solid;margin-bottom:.4rem;
  font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
.stagehdr .n{font-size:.85rem;color:var(--ink2);font-weight:700}
.stagecol .chips{display:flex;flex-wrap:wrap;gap:.22rem}
.hostchip{display:inline-block;border:1px solid;border-radius:5px;padding:.08rem .38rem;
  font-size:.72rem;font-family:ui-monospace,monospace;line-height:1.35;cursor:default}
.hostchip.more{color:var(--muted);border-color:var(--line);background:transparent;font-style:italic}
.stageleg{color:var(--muted);font-size:.7rem;margin-top:.55rem;padding-top:.4rem;
  border-top:1px solid var(--line)}
/* Undiscovered rollup: subnet lines are native <details> so no JS needed. */
.subnet-fold{margin:.15rem 0;padding:.05rem 0}
.subnet-fold > summary{list-style:none;cursor:pointer;padding:.22rem .4rem;
  border:1px solid var(--line);border-radius:5px;
  background:var(--surface);
  display:flex;justify-content:space-between;align-items:center;
  font-size:.74rem;font-family:ui-monospace,monospace;user-select:none}
.subnet-fold > summary::-webkit-details-marker{display:none}
.subnet-fold > summary::before{content:'▸';margin-right:.4rem;color:var(--muted);
  transition:transform .12s ease;display:inline-block}
.subnet-fold[open] > summary::before{transform:rotate(90deg);color:inherit}
.subnet-fold > summary:hover{background:var(--surface2)}
.subnet-fold .sn-n{color:var(--muted);font-size:.7rem}
.subnet-chips{padding:.35rem 0 .1rem .5rem}
/* "N hidden" footer under panels that dropped undiscovered rows. */
.hidden-note{color:var(--muted);font-size:.72rem;padding:.5rem .85rem;
  border-top:1px solid var(--line);margin-top:.1rem}
.hidden-note em{color:var(--ink2);font-style:normal}
/* PR-4: credential × service matrix */
.matrix{border-collapse:separate;border-spacing:0;font-size:.72rem;margin-top:.2rem}
.matrix th, .matrix td{border-right:1px solid var(--line);border-bottom:1px solid var(--line);
  text-align:center;padding:.2rem .35rem;vertical-align:middle}
.matrix thead th{position:sticky;top:0;background:var(--surface);z-index:1}
.matrix .mxh{padding:.2rem .3rem;color:var(--ink2);font-weight:500;
  min-width:66px;white-space:nowrap}
.matrix .mxh > div:first-child{color:var(--accent);text-transform:uppercase;font-size:.68rem}
.matrix .mxh .mono{font-size:.66rem;color:var(--muted)}
.matrix .mxr{text-align:left;padding:.28rem .5rem;background:var(--surface2);
  position:sticky;left:0;z-index:1;min-width:150px;font-weight:400}
.matrix .mxr b{display:block;color:var(--ink);font-weight:600}
.matrix .mxr .mono{color:var(--muted);font-size:.66rem}
.matrix .mx{font-family:ui-monospace,monospace;font-size:.95rem;font-weight:700}
.matrix .mx.admin{color:#7be07b;background:rgba(12,163,12,.28)}
.matrix .mx.ok{color:#7be07b;background:rgba(12,163,12,.14)}
.matrix .mx.bad{color:#e67878;background:rgba(208,59,59,.16)}
.matrix .mx.none{color:var(--muted)}
.matrix-legend{color:var(--ink2);font-size:.72rem;margin:.1rem .3rem .55rem;
  display:flex;gap:.75rem;align-items:center}
.matrix-legend .mx{display:inline-block;min-width:1.2em;text-align:center;
  padding:0 .3rem;border-radius:3px;margin-right:.15rem;font-weight:700}
.matrix-note{color:var(--muted);font-size:.7rem;margin-top:.4rem;font-style:italic}
/* PR-4: spray activity feed */
.sprayfeed{list-style:none;margin:0;padding:.35rem 0;display:flex;flex-direction:column;gap:.3rem}
.sprayfeed li{display:grid;grid-template-columns:64px 180px auto 1fr 170px;
  align-items:center;gap:.5rem;padding:.28rem .4rem;
  background:var(--surface2);border:1px solid var(--line);border-radius:6px;font-size:.78rem}
.sprayfeed .sp{display:inline-block;padding:.05rem .45rem;border-radius:4px;
  font-size:.66rem;text-align:center;font-weight:700;letter-spacing:.04em}
.sprayfeed .sp.admin{color:#0a0509;background:#7be07b}
.sprayfeed .sp.ok{color:#7be07b;background:rgba(12,163,12,.24);border:1px solid #0ca30c}
.sprayfeed .sp.bad{color:#e67878;background:rgba(208,59,59,.12);border:1px solid #d03b3b55}
.sprayfeed .arrow{color:var(--muted)}
.sprayfeed .t{color:var(--muted);font-size:.7rem;text-align:right;font-family:ui-monospace,monospace}
"""


# The Almighty's crest: not a tidy row of eyes but a mangled cluster of them —
# almond lenses overlapping and fusing, pupils wandering off-axis, threaded by
# sinewy tendrils, the way the many eyes bleed out of Yhwach's hair like a
# hallucination. One dominant central eye anchors it so it still reads as a mark.
# Translucent magenta fills deepen where the lenses overlap; reishi-pale pupils.
def _lens(
    cx: float,
    cy: float,
    a: float,
    b: float,
    tilt: float,
    px: float,
    py: float,
    *,
    track: bool = False,
) -> str:
    """One eye: an almond lens (built at the origin, then translated/rotated into
    the tangle) with an off-centre pupil and a specular glint.

    `track=True` makes the pupil follow the cursor: the JS in `_shell` drives
    every `.eye-pupil`, counter-rotating by `data-tilt` so tilted eyes look the
    right way. Otherwise the pupil is static."""
    d = f"M{-a} 0 Q0 {-b} {a} 0 Q0 {b} {-a} 0 Z"
    ir = b * 0.60
    iris = f"<circle cx='{px}' cy='{py}' r='{ir:.2f}' fill='#e83bb0' fill-opacity='.42'/>"
    pupil = f"<circle cx='{px}' cy='{py}' r='{max(ir * 0.42, 0.9):.2f}' fill='#f7d7ee'/>"
    glint = (f"<circle cx='{px - ir * 0.35:.2f}' cy='{py - ir * 0.35:.2f}' "
             f"r='{max(ir * 0.16, 0.4):.2f}' fill='#fff' fill-opacity='.9'/>")
    if track:
        travel = max(ir * 0.5, 1.2)
        pupils = (
            f"<g class='pupil eye-pupil' data-tilt='{tilt}' data-travel='{travel:.1f}'>"
            f"{iris}{pupil}{glint}</g>"
        )
    else:
        pupils = iris + pupil + glint
    path = f"<path d='{d}' fill='#e83bb0' fill-opacity='.12' stroke='#e83bb0' stroke-width='1.7'/>"
    return f"<g transform='translate({cx} {cy}) rotate({tilt})'>{path}{pupils}</g>"


# Sinewy tendrils weaving through the cluster — the hair the eyes grow out of.
_TENDRILS = (
    "<path d='M6 44 C18 22 27 48 33 30 C39 14 49 24 59 42' stroke='#e83bb0' "
    "stroke-opacity='.30' stroke-width='1.5' fill='none' stroke-linecap='round'/>"
    "<path d='M11 15 C25 31 41 9 55 21' stroke='#8a1f68' stroke-opacity='.55' "
    "stroke-width='1.3' fill='none' stroke-linecap='round'/>"
    "<path d='M18 48 C27 35 37 41 47 47' stroke='#e83bb0' stroke-opacity='.22' "
    "stroke-width='1.2' fill='none' stroke-linecap='round'/>"
    "<path d='M32 6 C28 18 40 22 34 34' stroke='#8a1f68' stroke-opacity='.4' "
    "stroke-width='1.1' fill='none' stroke-linecap='round'/>"
)

# The cluster of eyes (cx, cy, half-w, half-h, tilt, pupil-x, pupil-y), drawn
# outer-first so the big central eye sits on top; sizes/tilts irregular and
# overlapping on purpose. Pupils look every which way.
_CLUSTER = (
    (19, 23, 11, 6.5, 34, -1.5, 1.5),
    (45, 22, 10, 6, -32, 2, 0),
    (31, 12, 8, 4.5, 6, 0, 1),
    (11, 33, 7, 4.2, 64, 1, -0.5),
    (53, 31, 6.5, 4, -62, -1, 0.5),
    (25, 28, 5.5, 3.4, 46, 0.5, 0),
    (39, 30, 5, 3, -50, -1, 0.5),
    (33, 37, 15, 9, -5, 2.5, -1.5),  # dominant central eye, last = on top
)


def _crest_inner(track: bool = False) -> str:
    eyes = "".join(_lens(*p, track=track) for p in _CLUSTER)
    glint = "<circle cx='36' cy='34' r='.9' fill='#ffffff' fill-opacity='.85'/>"
    # Wrap in a group that periodically squashes vertically — a blink (pure CSS,
    # separate from the .eye hover transform so they never conflict).
    return (f"{_TENDRILS}<g class='crest-blink' style='transform-box:fill-box;"
            f"transform-origin:center'>{eyes}{glint}</g>")


def _crest(cls: str = "eye", w: int = 48, h: int = 45, *, track: bool = False) -> str:
    return (f"<svg class='{cls}' width='{w}' height='{h}' viewBox='0 0 64 60' "
            f"fill='none' aria-hidden='true'>{_crest_inner(track=track)}</svg>")


# The header logo: bigger than the favicon crest, and its pupils track the cursor.
_EYE = _crest(w=60, h=56, track=True)

# The same crest as a browser-tab favicon (standalone SVG data URI, over a dark
# rounded disc so it reads on light and dark tab bars).
_FAVICON = "data:image/svg+xml," + quote(
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 60'>"
    "<rect width='64' height='60' rx='13' fill='#140a12'/>" + _crest_inner() + "</svg>"
)


def _eye_icon(active: bool = False) -> str:
    """One worker eye for the cards — its pupil follows the cursor like the rest."""
    return (
        f"<svg class='wke{' on' if active else ''}' width='38' height='23' "
        f"viewBox='0 0 40 24' fill='none' aria-hidden='true'>"
        f"{_lens(20, 12, 17, 10, 0, 0, 0, track=True)}</svg>"
    )


def _gaze_svg(workers: list[dict], active_ip: str | None) -> str:
    """The metaphor made literal: the orchestrator as the great eye at the base,
    gaze-lines rising to the little worker-eyes fanned above it. The active
    worker's eye pulses and its gaze-line brightens."""
    shown = workers[:7]
    n = len(shown)
    w, h = 560, 200
    bx, by = w / 2, h - 26
    pupil_y = by - 18
    pos = []
    for i in range(n):
        t = (i + 0.5) / n if n else 0.5
        x = 46 + t * (w - 92)
        y = 58 - 30 * math.sin(math.pi * t)
        pos.append((x, y))
    parts = [
        f"<svg class='gaze' viewBox='0 0 {w} {h}' width='100%' height='{h}' "
        "preserveAspectRatio='xMidYMid meet' fill='none' aria-hidden='true'>"
    ]
    # gaze lines (behind the eyes)
    for (x, y), wk in zip(pos, shown, strict=True):
        on = wk["ip"] == active_ip
        parts.append(
            f"<line class='gz-line{' on' if on else ''}' x1='{bx:.0f}' y1='{pupil_y:.0f}' "
            f"x2='{x:.0f}' y2='{y + 8:.0f}' stroke-width='{1.6 if on else 1}'/>"
        )
    # the little worker eyes — each pupil glances down toward the Almighty (and,
    # since they all lean the same way, toward one another), then drifts back.
    for i, ((x, y), wk) in enumerate(zip(pos, shown, strict=True)):
        on = wk["ip"] == active_ip
        if on:
            parts.append(
                f"<circle class='gz-halo' cx='{x:.0f}' cy='{y:.0f}' r='15' fill='#e83bb0'/>"
            )
        parts.append(_lens(x, y, 13, 8, (7 if i % 2 else -7), 0, 0, track=True))
        parts.append(
            f"<text x='{x:.0f}' y='{y + 26:.0f}' fill='#c1a3ba' font-size='8' "
            f"font-family='monospace' text-anchor='middle'>{_esc(wk['ip'])}</text>"
        )
    # the great Almighty eye, scanning across its workers
    parts.append(
        f"<circle cx='{bx:.0f}' cy='{pupil_y:.0f}' r='34' fill='#e83bb0' fill-opacity='.10'/>"
    )
    parts.append(_lens(bx, pupil_y, 44, 26, 0, 0, 0, track=True))
    parts.append(
        f"<text x='{bx:.0f}' y='{by + 14:.0f}' fill='#e6c6dc' font-size='9' "
        "font-family='monospace' text-anchor='middle' letter-spacing='2'>THE ALMIGHTY</text>"
    )
    parts.append("</svg>")
    return "".join(parts)


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


# ─── markup helpers ────────────────────────────────────────────────────────
# The same four shapes were hand-written across 24 section headings, 19 cards
# and 23 empty states. Folding them here keeps a new panel to one call and makes
# the fallback colour and the empty-state markup single-sourced.


_STAGE_FALLBACK = "#5b626d"


def _stage_colour(stage: str | None) -> str:
    """Colour for a host stage. The fallback literal was repeated at eight call
    sites; a stage outside `db.STAGES` lands here rather than raising."""
    return _STAGE.get(stage or "", _STAGE_FALLBACK)


def _stage_badge(stage: str | None) -> str:
    """A host stage as the outlined badge four panels build by hand."""
    col = _stage_colour(stage)
    return (f"<span class='badge' style='color:{col};border-color:{col};"
            f"background:{col}22'>{_esc(stage or '?')}</span>")


def _hlink(ip: str | None, *, text: str | None = None) -> str:
    """An IP as a link to its host page. The host IP appears in eleven panels and
    was clickable in exactly one; `.hl` keeps it the row's own colour so a table
    does not become a wall of magenta."""
    if not ip:
        return "<span class='muted'>—</span>"
    return (f"<a class='hl' href='/host?ip={quote(str(ip))}'>"
            f"{_esc(text if text is not None else ip)}</a>")


def _empty(msg: str) -> str:
    return f"<p class='empty' style='padding:.9rem'>{_esc(msg)}</p>"


# The board re-serialises its whole fragment every 3s. A /20 scope legitimately
# materialises thousands of host rows, so an uncapped table pushes every panel
# below it many screens down and inflates the payload without adding a fact the
# operator can act on. 25 rows, then an exact count and where to see the rest —
# a truncation the page admits to, never a silent one.
_BOARD_ROW_CAP = 25


def _more_note(total: int, shown: int, where: str) -> str:
    """Footer for a capped table. Empty when nothing was dropped."""
    if total <= shown:
        return ""
    return (f"<div class='hidden-note'>+{total - shown} more of {total} not shown — "
            f"<em>{where}</em></div>")


def _panel(title: str, inner: str, *, note: str | None = None) -> str:
    """`h2.sec` + `.card`, with an optional muted footer line."""
    foot = f"<div class='hidden-note'>{note}</div>" if note else ""
    return f"<h2 class='sec'>{_esc(title)}</h2><div class='card'>{inner}{foot}</div>"


def _rows_table(headers: list[str], rows: list[list[str]], *, empty: str) -> str:
    """A `<table>` from pre-rendered cells. Cells are inserted verbatim, so the
    caller escapes — same contract as every existing panel."""
    if not rows:
        return _empty(empty)
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _age_secs(ts: str | None) -> float | None:
    """Age in seconds of a `%Y-%m-%dT%H:%M:%SZ` UTC timestamp, or None if unparseable."""
    if not ts:
        return None
    try:
        t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None
    return (datetime.now(UTC) - t).total_seconds()


def _shell(
    lab: str, active: str, body: str, *, poll_url: str | None = None, mount: str = "board"
) -> str:
    nav = "".join(
        f"<a href='{href}' class='{'on' if active == key else ''}'>{label}</a>"
        for key, href, label in (
            ("board", "/", "Board"),
            ("recon", "/recon", "Recon"),
            ("surfaces", "/surfaces", "Surfaces"),
            ("identity", "/identity", "Identity"),
            ("map", "/map", "Map"),
            ("vault", "/vault", "Vault"),
            ("poc", "/poc", "PoC"),
            ("report", "/report", "Report"),
        )
    )
    toolbar = ""
    # The cursor-tracking eyes + pivot-tree hover run on every page.
    script = "<script>" + _EYE_TRACK_JS + _TREE_HOVER_JS + "</script>"
    if poll_url:
        toolbar = (
            "<div class='rtoolbar'><span id='upd' class='upd'>connecting…</span>"
            "<button id='pausebtn' class='mini' title='pause / resume auto-refresh'>⏸</button></div>"
        )
        script += (
            "<script>"
            + _POLL_JS.replace("__URL__", poll_url).replace("__MOUNT__", mount)
            + "</script>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<link rel='icon' href='{_FAVICON}'>"
        f"<title>yhwach — {_esc(lab)}</title><style>{_CSS}</style></head><body><div class='wrap'>"
        f"<header class='top'>{_EYE}<div class='brand'><h1>Yhwach</h1>"
        f"<span class='sub'>engagement <b>{_esc(lab)}</b></span></div>"
        f"<div class='spacer'></div>{toolbar}<nav>{nav}</nav></header>"
        f"{body}</div>{script}</body></html>"
    )


# Cursor-tracking pupils: every frame, aim each `.eye-pupil` at the mouse. The
# pupil lives inside a rotated lens group, so the screen-space unit vector is
# counter-rotated by the eye's `data-tilt` before translating (by data-travel,
# in SVG user units). Measures the parent lens rect (not the pupil's own) so the
# translate doesn't chase itself. Honours prefers-reduced-motion. Re-queried each
# frame, so it keeps working after the board fragment re-renders.
_EYE_TRACK_JS = (
    "(function(){try{if(matchMedia&&matchMedia('(prefers-reduced-motion: reduce)')"
    ".matches)return;}catch(e){}"
    "var mx=innerWidth/2,my=innerHeight/2,last=-9999;"
    "addEventListener('mousemove',function(e){mx=e.clientX;my=e.clientY;"
    "last=performance.now();},{passive:true});"
    "function tick(now){var tx=mx,ty=my;"
    # Idle > 2.5s: the gaze wanders slowly around the screen centre so the eyes
    # never look frozen. A mouse move snaps them straight back to the cursor.
    "if(now-last>2500){var a=now*0.00042;"
    "tx=innerWidth/2+Math.cos(a)*Math.min(240,innerWidth*0.22);"
    "ty=innerHeight/2+Math.sin(a*1.3)*Math.min(150,innerHeight*0.2);}"
    "var eyes=document.getElementsByClassName('eye-pupil');"
    "for(var i=0;i<eyes.length;i++){var el=eyes[i],host=el.parentNode||el;"
    "var r=host.getBoundingClientRect();if(!r.width){el.style.transform='';continue;}"
    "var cx=r.left+r.width/2,cy=r.top+r.height/2,dx=tx-cx,dy=ty-cy,d=Math.hypot(dx,dy)||1;"
    "var t=(parseFloat(el.getAttribute('data-tilt'))||0)*Math.PI/180;"
    "var tv=parseFloat(el.getAttribute('data-travel'))||2;var ux=dx/d,uy=dy/d;"
    "var lx=ux*Math.cos(-t)-uy*Math.sin(-t),ly=ux*Math.sin(-t)+uy*Math.cos(-t);"
    "el.style.transform='translate('+(lx*tv).toFixed(2)+'px,'+(ly*tv).toFixed(2)+'px)';}"
    "requestAnimationFrame(tick);}requestAnimationFrame(tick);})();"
)

# Pivot-tree hover: light up a host's whole route back to the operator. Delegated
# on document (survives board fragment re-renders); matches edge data-edge against
# the hovered node's data-path chain.
_TREE_HOVER_JS = (
    "(function(){function edges(){return document.getElementsByClassName('nn-edge');}"
    "function clear(){var e=edges();for(var i=0;i<e.length;i++)e[i].classList.remove('hot');}"
    "document.addEventListener('mouseover',function(ev){"
    "var n=ev.target.closest&&ev.target.closest('.nn-node');if(!n){return;}"
    "var p=(n.getAttribute('data-path')||'').split('|'),set={};"
    "for(var i=0;i<p.length;i++){if(p[i])set[p[i]]=1;}"
    "var e=edges();for(var j=0;j<e.length;j++){var d=e[j].getAttribute('data-edge');"
    "if(d&&set[d]){e[j].classList.add('hot');}else{e[j].classList.remove('hot');}}});"
    "document.addEventListener('mouseout',function(ev){"
    "if(ev.target.closest&&ev.target.closest('.nn-node')){clear();}});})();"
)


# The live-board client: poll a fragment, stamp the refresh time, honour a pause
# toggle, and flash a toast + tab title when new critical findings appear. Kept
# out of f-strings (JS braces) and injected via .replace of __URL__/__MOUNT__.
_POLL_JS = (
    "(function(){var paused=false,lastCrit=null,url='__URL__',mount='__MOUNT__';"
    "var upd=document.getElementById('upd'),pb=document.getElementById('pausebtn');"
    "function stamp(){if(upd)upd.textContent='updated '+new Date().toLocaleTimeString();}"
    "function toast(n){var t=document.createElement('div');t.className='toast';"
    "t.textContent='\\u26A0 '+n+' new critical finding'+(n>1?'s':'');"
    "document.body.appendChild(t);setTimeout(function(){t.remove();},6000);"
    "document.title='(!) '+document.title.replace(/^\\(!\\) /,'');}"
    "async function poll(){if(paused)return;try{var r=await fetch(url);"
    "var el=document.getElementById(mount);el.innerHTML=await r.text();stamp();"
    "var c=el.querySelector('[data-crit]');if(c){var n=+c.getAttribute('data-crit');"
    "if(lastCrit!==null&&n>lastCrit)toast(n-lastCrit);lastCrit=n;}}catch(e){}}"
    "if(pb)pb.onclick=function(){paused=!paused;pb.textContent=paused?'\\u25B6':'\\u23F8';"
    "if(upd)upd.textContent=paused?'paused':'resuming…';if(!paused)poll();};"
    "poll();setInterval(poll,3000);})();"
)


def create_app(db_path: str | Path, lab: str, *, reveal_secrets: bool = True) -> FastAPI:
    app = FastAPI(title=f"yhwach — {lab}")
    db_path = str(db_path)

    def _eid(conn):
        return yhdb.engagement_id_for(conn, lab)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _shell(lab, "board", "<div id='board'>loading…</div>", poll_url="/panel")

    @app.get("/panel", response_class=HTMLResponse)
    def panel() -> str:
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            if eid is None:
                return f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            return _render_board(conn, eid, reveal=reveal_secrets)

    @app.get("/recon", response_class=HTMLResponse)
    def recon_page() -> str:
        # Static, like /vault and /poc: the matrix is wide enough that a 3s
        # innerHTML swap would fight its horizontal scroll position, and none of
        # these facts change between polls anyway.
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            body = (
                _recon_body(conn, eid)
                if eid is not None
                else f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            )
        return _shell(lab, "recon", body)

    @app.get("/surfaces", response_class=HTMLResponse)
    def surfaces_page() -> str:
        # Static, like /recon: an inventory, not a live feed.
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            body = (
                _surfaces_body(conn, eid, reveal=reveal_secrets)
                if eid is not None
                else f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            )
        return _shell(lab, "surfaces", body)

    @app.get("/identity", response_class=HTMLResponse)
    def identity_page() -> str:
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            body = (
                _identity_body(conn, eid, reveal=reveal_secrets)
                if eid is not None
                else f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            )
        return _shell(lab, "identity", body)

    @app.get("/map", response_class=HTMLResponse)
    def map_page() -> str:
        return _shell(lab, "map", "<div id='map'>loading…</div>", poll_url="/mappanel", mount="map")

    @app.get("/mappanel", response_class=HTMLResponse)
    def mappanel() -> str:
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            if eid is None:
                return f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            return _map_body(conn, eid)

    @app.get("/vault", response_class=HTMLResponse)
    def vault_page() -> str:
        # Static (no auto-refresh): the vault rarely changes, and polling would
        # clobber copy feedback / any in-page state each tick.
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            body = (
                # The matrix and spray feed moved here off the board, where they
                # were rendered a second time: this page owns credential reach.
                "\n".join((
                    _creds_vault(conn, eid, reveal=reveal_secrets, cap=None),
                    _cred_service_matrix(conn, eid),
                    _spray_feed(conn, eid),
                ))
                if eid is not None
                else f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            )
        return _shell(lab, "vault", body)

    @app.get("/map.svg")
    def map_svg():
        from fastapi.responses import Response

        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            svg = _map_svg_file(conn, eid) if eid else "<svg xmlns='http://www.w3.org/2000/svg'/>"
        return Response(
            svg,
            media_type="image/svg+xml",
            headers={"Content-Disposition": f'attachment; filename="{lab}-network.svg"'},
        )

    @app.get("/host", response_class=HTMLResponse)
    def host_page(ip: str = "") -> str:
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            body = (
                _host_detail(conn, eid, ip, reveal=reveal_secrets)
                if eid
                else f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            )
        return _shell(lab, "map", body)

    @app.get("/poc", response_class=HTMLResponse)
    def poc_page() -> str:
        # Static (no auto-refresh) so opened <details> chains stay open.
        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            body = (
                _poc_panel(conn, eid)
                if eid is not None
                else f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            )
        return _shell(lab, "poc", body)

    @app.get("/report", response_class=HTMLResponse)
    def report_page() -> str:
        from yhwach import synthesis

        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            if eid is None:
                body = f"<p class='empty'>no engagement '{_esc(lab)}' yet</p>"
            else:
                from yhwach.report import build_report

                # include_candidates=False, not candidates=[]: the latter prints
                # the heading plus a false "(no applicable techniques remain)".
                # The applicability inventory lives on the board; this page is
                # the write-up.
                md = synthesis.phase_report(
                    conn, eid, phase=_report_phase(conn, eid), include_candidates=False)
                body = (
                    "<h2 class='sec'>Reports</h2>"
                    "<div class='dlrow'>"
                    "<a class='dl' href='/report.md' download>⤓ State + Next Steps (.md)</a>"
                    "<a class='dl' href='/report/full.md' download>⤓ Full engagement report (.md)</a>"
                    "</div>"
                    + _report_gaps(conn, eid)
                    + f"<h2 class='sec'>Engagement state</h2><div class='report'>{_md_to_html(md)}</div>"
                    + "<h2 class='sec'>Full engagement report</h2>"
                    # build_report prints `- **Evidence:** ...`, and interpret
                    # writes mined secrets into that field. Under --redact it
                    # stays a download, as it was before this was rendered in-page.
                    + (f"<div class='report'>{_md_to_html(build_report(conn, eid))}</div>"
                       if reveal_secrets else
                       "<div class='card'>" + _empty(
                           "withheld under --redact — it prints finding evidence, which "
                           "can carry mined secrets; use the download above") + "</div>")
                )
        return _shell(lab, "report", body)

    @app.get("/report.md", response_class=PlainTextResponse)
    def report_md():
        from yhwach import synthesis

        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            text = synthesis.phase_report(conn, eid) if eid else "no engagement\n"
        return PlainTextResponse(
            text,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{lab}-next-steps.md"'},
        )

    @app.get("/report/full.md", response_class=PlainTextResponse)
    def report_full_md():
        from yhwach.report import build_report

        with yhdb.transaction(db_path) as conn:
            eid = _eid(conn)
            text = build_report(conn, eid) if eid else "no engagement\n"
        return PlainTextResponse(
            text,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{lab}-report.md"'},
        )

    return app


def _scalar(conn, sql, params=()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _render_board(conn, eid: int, *, reveal: bool = True) -> str:
    n_crit = _scalar(
        conn,
        "SELECT COUNT(*) FROM finding WHERE engagement_id=? AND status IN ('open','confirmed','exploited') AND severity='critical'",
        (eid,),
    )
    parts: list[str] = [f"<span data-crit='{n_crit}' hidden></span>"]
    parts += [_run_row(conn, eid), _tiles(conn, eid)]
    # The board shows what has been FOUND. "What's possible / what you still owe /
    # what to work next" is advisory — it lives at the wire (yhwach_next/gaps/
    # coverage/brief) for the model, not on the human board.
    # The by-stage host grid sits high (proof that the world model is honest about
    # the estate size); the cred×service matrix + spray feed sit near the vault.
    parts.append(_host_stage_board(conn, eid))
    # The full network map is the whole body of /map, and the three vault panels
    # are the whole body of /vault — each was being rendered twice per page view.
    # The board keeps the headline numbers and links out for the detail.
    parts.append(_topology_strip(conn, eid))
    parts.append(_attack_path(conn, eid))
    parts.append(_hosts(conn, eid))
    parts.append(_vault_strip(conn, eid, reveal=reveal))
    parts.append(_findings(conn, eid))
    parts.append(_activity(conn, eid))
    return "\n".join(parts)


def _run_status(conn, eid: int) -> str:
    # A fresh worker heartbeat means work is happening now, regardless of whether
    # the autonomous run_started/halt events were emitted (manual/parallel runs
    # don't emit them).
    hb = conn.execute(
        "SELECT MAX(updated_at) m FROM worker_state WHERE engagement_id=? "
        "AND status IN ('watching','running')",
        (eid,),
    ).fetchone()
    if hb and hb["m"]:
        age = _age_secs(hb["m"])
        if age is not None and age <= _WORKER_STALE_SECS:
            return "RUNNING"
    last_start = conn.execute(
        "SELECT ts FROM event WHERE engagement_id=? AND kind='run_started' ORDER BY id DESC LIMIT 1",
        (eid,),
    ).fetchone()
    last_halt = conn.execute(
        "SELECT ts FROM event WHERE engagement_id=? AND kind='orchestrator_halt' "
        "ORDER BY id DESC LIMIT 1",
        (eid,),
    ).fetchone()
    if last_start and (not last_halt or last_halt["ts"] < last_start["ts"]):
        return "RUNNING"
    return "idle"


def _run_row(conn, eid: int) -> str:
    status = _run_status(conn, eid)
    live = "live" if status == "RUNNING" else ""
    # Read-only status indicator. The UI is a pure view over the memory DB — no
    # kill/approve controls (drive the run from the CLI/MCP).
    return (
        "<div style='display:flex;align-items:center;gap:1rem'>"
        f"<span class='runbadge'><span class='dot {live}'></span> {status}</span>"
        "</div>"
    )


def _tiles(conn, eid: int) -> str:
    stage_rows = conn.execute(
        "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage", (eid,)
    ).fetchall()
    stages = {r["stage"]: r["n"] for r in stage_rows}
    total = sum(stages.values())
    owned = sum(v for k, v in stages.items() if k in _OWNED)
    n_surf = _scalar(
        conn,
        "SELECT COUNT(*) FROM surface s JOIN host h ON h.id=s.host_id " "WHERE h.engagement_id=?",
        (eid,),
    )
    n_cred = _scalar(conn, "SELECT COUNT(*) FROM credential WHERE engagement_id=?", (eid,))
    # Scan queue depth + spray matrix state — added in the world-model repair
    # (PR-1/PR-2/PR-3). Answers the operator's "how many hosts do I still
    # owe a full scan?" and "have my creds been tried yet?" at a glance,
    # without hunting through yhwach_gaps and yhwach_creds.
    n_pending = _scalar(
        conn, "SELECT COUNT(*) FROM host WHERE engagement_id=? AND scan_needed=1", (eid,),
    )
    n_hits = _scalar(
        conn,
        "SELECT COUNT(DISTINCT credential_id) FROM credential_access "
        "WHERE engagement_id=? AND result IN ('success','admin')",
        (eid,),
    )
    n_admin = _scalar(
        conn,
        "SELECT COUNT(DISTINCT credential_id) FROM credential_access "
        "WHERE engagement_id=? AND result='admin'",
        (eid,),
    )
    sev_rows = conn.execute(
        "SELECT severity, COUNT(*) n FROM finding WHERE engagement_id=? AND status IN ('open','confirmed','exploited') "
        "GROUP BY severity",
        (eid,),
    ).fetchall()
    sev = {r["severity"]: r["n"] for r in sev_rows}
    n_find = sum(sev.values())

    seg = ""
    leg = ""
    for name in ("critical", "high", "medium", "low"):
        c = sev.get(name, 0)
        if c and n_find:
            seg += f"<span style='width:{c / n_find * 100:.1f}%;background:{_SEV[name]}'></span>"
        leg += f"<span><i style='background:{_SEV[name]}'></i>{name} {c}</span>"
    if not n_find:
        seg = "<span style='width:100%;background:var(--surface2)'></span>"

    # Cred tile: <hits>/<total> validated, admins in bold if any.
    cred_val = f"{n_hits}<small> / {n_cred}</small>"
    cred_note = f" · <em>{n_admin} admin</em>" if n_admin else ""
    # Pending-scan tile: uses <total> so operator sees "X pending / Y hosts".
    pend_val = f"{n_pending}<small> / {total}</small>" if total else f"{n_pending}"

    # Enum-honesty tile: of the hosts we've reached (scanned+), how many are fully
    # enumerated. The "is my memory lying about completeness?" number — under-
    # enumeration is the #1 point loss in engagements, previously only a raw count.
    from yhwach.coverage import coverage_score

    cs = coverage_score(conn, eid)
    # pct is None until a host has actually been reached — render a dash, never a
    # score. A green 100% at hour zero is the exact lie this tile exists to catch.
    if cs.pct is None:
        hcol, honesty_val, honesty_note = "var(--muted)", "—", "nothing scanned yet"
    else:
        hcol = "#6bb36b" if cs.pct >= 80 else "#d9a441" if cs.pct >= 40 else "#e06767"
        honesty_val = f"{cs.pct}<small>%</small>"
        honesty_note = f"{cs.complete}/{cs.considered} fully enum'd"

    # Points scoreboard tile — the scoring metric. Only shown
    # once objectives exist, so engagements without objectives stay uncluttered.
    from yhwach.scoreboard import compute as _sb_compute

    sb = _sb_compute(conn, eid)
    points_tile = ""
    if sb.total:
        # points_target is optional (NULL = unscored engagement): colour + the
        # "/ target" denominator only render when a target was set at engage time;
        # otherwise show a neutral running points count.
        if sb.points_target:
            pcol = "#6bb36b" if sb.pct >= 100 else "#d9a441" if sb.pct >= 50 else "#e06767"
            val = f"{sb.points_scored}<small> / {sb.points_target}</small>"
        else:
            pcol = "#8a8a8a"
            val = f"{sb.points_scored}<small> pts</small>"
        # remaining_h is None unless engagement.time_budget_h was set — so the pace
        # half used to fall back to the flag count that is already printed before
        # the separator, rendering the literal "3/8 flags · 3/8 flags". Drop the
        # separator instead of repeating.
        sub = f"{sb.captured}/{sb.total} flags"
        if sb.remaining_h is not None:
            sub += f" · {sb.remaining_h}h left"
        elif sb.elapsed_h is not None:
            sub += f" · {sb.elapsed_h}h elapsed"
        points_tile = (
            "<div class='tile'><div class='k'>Points</div>"
            f"<div class='v' style='color:{pcol}'>{val}</div>"
            f"<div class='sevleg'><span>{_esc(sub)}</span></div></div>"
        )
    return (
        "<div class='tiles'>"
        + points_tile
        + f"<div class='tile'><div class='k'>Hosts owned</div>"
        f"<div class='v'>{owned}<small> / {total}</small></div></div>"
        f"<div class='tile'><div class='k'>Pending scan</div>"
        f"<div class='v'>{pend_val}</div></div>"
        f"<div class='tile'><div class='k'>Enum honesty</div>"
        f"<div class='v' style='color:{hcol}'>{honesty_val}</div>"
        f"<div class='sevleg'><span>{honesty_note}</span></div></div>"
        f"<div class='tile'><div class='k'>Open findings</div><div class='v'>{n_find}</div>"
        f"<div class='sevbar'>{seg}</div><div class='sevleg'>{leg}</div></div>"
        f"<div class='tile'><div class='k'>Cred hits</div>"
        f"<div class='v'>{cred_val}</div><div class='sevleg'>{cred_note}</div></div>"
        f"<div class='tile'><div class='k'>Surfaces</div><div class='v'>{n_surf}</div></div>"
        "</div>"
    )


_RISK_COL = {"read_only": "#6bb36b", "exploit": "#d9a441", "destructive": "#e06767"}


def _copy_cmd(cmd: str) -> str:
    """A monospace command + a one-click copy button (same idiom as the vault)."""
    s = _esc(cmd)
    return (
        f"<code class='mono' style='font-size:.7rem' data-s=\"{s}\">{s}</code> "
        "<button class='mini' title='copy' onclick=\"var s=this.previousElementSibling."
        "getAttribute('data-s');navigator.clipboard&&navigator.clipboard.writeText(s);"
        "var b=this;b.textContent='copied';setTimeout(function(){b.textContent='copy';},900);"
        "\">copy</button>"
    )


def _cov_bar(c) -> str:
    """A 4-segment completeness bar: full-TCP · -sV · UDP top-100 · every service triaged."""
    from yhwach.coverage import UDP_FLOOR

    dims = [
        ("TCP -p-", c.tcp_full),
        ("-sV", c.tcp_version),
        (f"UDP top-{UDP_FLOOR}", c.udp_ports >= UDP_FLOOR),
        ("services triaged", not any(g.kind == "service_enum" for g in c.gaps)),
    ]
    cells = "".join(
        f"<span title='{label}: {'covered' if ok else 'MISSING'}' "
        f"style='width:1.6rem;height:.5rem;border-radius:2px;"
        f"background:{'#2f8f4e' if ok else '#8f3030'}'></span>"
        for label, ok in dims
    )
    return f"<span style='display:inline-flex;gap:3px;vertical-align:middle'>{cells}</span>"


def _pivot_tree_svg(bands: list[tuple[str, list[dict]]], tunnels: list[dict],
                    *, standalone: bool = False, linkify: bool = True) -> str:
    """The pivot tree: the operator at the crown, subnets in depth-ordered
    bands beneath it, and a bright line down each pivot (tunnel via_host ->
    the subnet it opens, labelled with the tunnel tech). Dual-homed hosts are the
    bridges. Built from tunnel + host_interface, so it literally shows *how* each
    subnet was reached."""
    margin = 60
    w = 720
    band_h = 116
    top = 70
    h = top + max(1, len(bands)) * band_h + 24
    xmlns = " xmlns='http://www.w3.org/2000/svg'" if standalone else ""
    parts = [
        f"<svg class='netmap'{xmlns} viewBox='0 0 {w} {h}' width='100%' height='{h}' "
        "preserveAspectRatio='xMidYMid meet' fill='none'>",
        # arrowhead for pivot edges (fixed size, doesn't scale with stroke width)
        "<defs><marker id='pvarw' markerWidth='8' markerHeight='8' refX='6' refY='3' "
        "orient='auto' markerUnits='userSpaceOnUse'>"
        "<path d='M0 0 L6 3 L0 6 z' fill='#e83bb0'/></marker>"
        "<marker id='pvarwdim' markerWidth='8' markerHeight='8' refX='6' refY='3' "
        "orient='auto' markerUnits='userSpaceOnUse'>"
        "<path d='M0 0 L6 3 L0 6 z' fill='#8a1f68'/></marker></defs>",
    ]
    if standalone:
        parts.insert(1, f"<rect width='{w}' height='{h}' fill='#0a0509'/>")

    opx, opy = w / 2, 32
    pos: dict[str, tuple[float, float]] = {}
    band_cx: dict[str, float] = {}
    band_y: dict[str, float] = {}
    for i, (label, nodes) in enumerate(bands):
        by = top + i * band_h + 30
        band_y[label] = by
        n = max(len(nodes), 1)
        xs = []
        for j, nd in enumerate(nodes):
            x = margin + (j + 0.5) / n * (w - 2 * margin)
            pos[nd["ip"]] = (x, by)
            xs.append(x)
        band_cx[label] = sum(xs) / len(xs) if xs else w / 2

    # depth-0 bands (not the far side of any tunnel) hang straight off the operator
    targeted = {t["subnet"] for t in tunnels}
    # parent subnet of each subnet (via the tunnel that opens it) — drives the
    # hover path-highlight: a node lights every edge on its route to the operator.
    parent = {t["subnet"]: t["via_subnet"] for t in tunnels if t["subnet"] != t["via_subnet"]}

    def _chain(sn: str) -> list[str]:
        out, seen, cur = [], set(), sn
        while cur and cur not in seen:
            out.append(cur)
            seen.add(cur)
            cur = parent.get(cur)
        return out

    # -- edges (drawn first, behind nodes) --
    def _curve(x1: float, y1: float, x2: float, y2: float) -> str:
        """A vertical-ish cubic bezier (control points share the midline y)."""
        my = (y1 + y2) / 2
        return f"M{x1:.0f} {y1:.0f} C{x1:.0f} {my:.0f} {x2:.0f} {my:.0f} {x2:.0f} {y2:.0f}"

    for label, _nodes in bands:
        if label not in targeted:  # perimeter band → operator
            cx, by = band_cx[label], band_y[label]
            parts.append(
                f"<path class='nn-edge' data-edge=\"{_esc(label)}\" "
                f"d='{_curve(opx, opy + 16, cx, by - 18)}' "
                "stroke-width='1' marker-end='url(#pvarwdim)'/>"
            )
    for t in tunnels:  # pivot edges: via_host → target band (curved, arrowed, labelled)
        vp = pos.get(t["via_ip"])
        if vp is None or t["subnet"] not in band_y:
            continue
        tx, ty = band_cx[t["subnet"]], band_y[t["subnet"]]
        parts.append(
            f"<path class='nn-edge owned' data-edge=\"{_esc(t['subnet'])}\" "
            f"d='{_curve(vp[0], vp[1] + 14, tx, ty - 18)}' "
            "stroke-width='1.8' marker-end='url(#pvarw)'/>"
        )
        my = (vp[1] + ty) / 2
        parts.append(
            f"<text x='{(vp[0] + tx) / 2:.0f}' y='{my:.0f}' fill='#f2c6e4' font-size='7.5' "
            f"font-family='monospace' text-anchor='middle'>{_esc(t['kind'])}</text>"
        )

    # -- operator eye (the crown) --
    parts.append(f"<circle cx='{opx:.0f}' cy='{opy:.0f}' r='22' fill='#e83bb0' fill-opacity='.10'/>")
    parts.append(_lens(opx, opy, 20, 12, 0, 2, -2, track=True))
    parts.append(
        f"<text x='{opx:.0f}' y='{opy - 24:.0f}' fill='#e6c6dc' font-size='8.5' "
        "font-family='monospace' text-anchor='middle' letter-spacing='1'>OPERATOR</text>"
    )

    # -- band labels + nodes --
    for label, nodes in bands:
        by = band_y[label]
        parts.append(
            f"<text x='6' y='{by - 20:.0f}' fill='#8a6f82' font-size='8' "
            f"font-family='monospace'>{_esc(label)}</text>"
        )
        for nd in nodes:
            x, y = pos[nd["ip"]]
            col = _stage_colour(nd["stage"])
            dim = nd["stage"] in ("undiscovered", "scanned")
            # A summary node ("+N undiscovered") uses a smaller ring and a
            # dashed stroke to visually separate "we haven't looked here yet"
            # from real hosts — the operator sees the coverage gap without
            # confusing it with a lens they can click into.
            is_summary = nd.get("summary", False)
            rad = 11 if nd["stage"] in _OWNED else (6 if is_summary else 8)
            g = []
            if nd["stage"] in _OWNED:
                g.append(f"<circle class='nn-pulse' cx='{x:.0f}' cy='{y:.0f}' r='{rad + 7}' "
                         f"fill='{col}'/>")
            stroke_dash = " stroke-dasharray='3 2'" if is_summary else ""
            g.append(f"<circle class='nn-ring' cx='{x:.0f}' cy='{y:.0f}' r='{rad}' stroke='{col}' "
                     f"stroke-width='2.4' fill='{col}' fill-opacity='{0.08 if is_summary else (0.12 if dim else 0.3)}'"
                     f"{stroke_dash}/>")
            marks = ""
            if nd.get("objective"):
                marks += "👑" if nd.get("captured") else "🏳"
            if nd.get("ai"):
                marks += "★"
            if nd.get("dual"):
                marks += "⇄"
            if marks:
                g.append(f"<text x='{x:.0f}' y='{y + 3.5:.0f}' fill='#f7d7ee' font-size='9' "
                         f"text-anchor='middle'>{marks}</text>")
            name = nd.get("hostname") or nd["ip"]
            g.append(f"<text x='{x:.0f}' y='{y - rad - 4:.0f}' fill='{'#8a6f82' if is_summary else '#f4e9f1'}' "
                     f"font-size='{7.5 if is_summary else 8.5}' "
                     f"font-family='monospace' text-anchor='middle'>{_esc(name)}</text>")
            if not is_summary:
                # Under-ring stage label; noise on a summary node ("undiscovered
                # · +246 undiscovered" is redundant), so omit for summaries.
                g.append(f"<text x='{x:.0f}' y='{y + rad + 11:.0f}' fill='#c1a3ba' font-size='7' "
                         f"font-family='monospace' text-anchor='middle'>{_esc(nd['stage'])}</text>")
            node = "".join(g)
            if standalone or not linkify or is_summary:
                # Summary nodes never link — there's no per-host page for
                # a bulk-undiscovered marker.
                parts.append(f"<g>{node}</g>")
            else:
                dp = _esc("|".join(_chain(label)))  # this host's route back to the operator
                parts.append(
                    f"<a class='nn-node' data-path=\"{dp}\" "
                    f"href='/host?ip={quote(str(nd['ip']))}'>{node}</a>")
    parts.append("</svg>")
    return "".join(parts)


def _network_map(conn, eid: int) -> str:
    """The network map: a live topology of every discovered host with the ports
    and services each exposes, built entirely from memory (host + service +
    surface). It grows as hosts are scanned -> enumerated -> owned, so by the end
    of the lab it is the whole network."""
    hosts = conn.execute(
        "SELECT id, ip, COALESCE(hostname,'') hostname, COALESCE(os,'') os, "
        "stage, COALESCE(role,'') role FROM host WHERE engagement_id=? "
        "ORDER BY (stage IN ('foothold','looted','pivoted','done')) DESC, ip",
        (eid,),
    ).fetchall()
    if not hosts:
        return (
            "<h2 class='sec'>Network map</h2><div class='netwrap'>"
            "<p class='empty' style='margin:0'>no hosts discovered yet — run a scan</p></div>"
        )

    ids = [h["id"] for h in hosts]
    ph = ",".join("?" * len(ids))
    svc = conn.execute(
        f"SELECT id, host_id, port, COALESCE(proto,'tcp') proto, COALESCE(product,'') product, "
        f"COALESCE(version,'') version FROM service WHERE host_id IN ({ph}) ORDER BY port",
        ids,
    ).fetchall()
    surf = conn.execute(
        f"SELECT host_id, service_id, kind, COALESCE(auth,'') auth FROM surface "
        f"WHERE host_id IN ({ph})",
        ids,
    ).fetchall()
    by_service = {s["service_id"]: s for s in surf if s["service_id"] is not None}
    svc_by_host: dict[int, list] = {}
    for s in svc:
        svc_by_host.setdefault(s["host_id"], []).append(s)
    ai_hosts = {s["host_id"] for s in surf if s["kind"] in AI_KINDS}
    surf_kinds_by_host: dict[int, set] = {}
    for s in surf:
        surf_kinds_by_host.setdefault(s["host_id"], set()).add(s["kind"])
    tags_by_host = yhdb.tags_for_hosts(conn, eid)

    # Enrich for the pivot tree: objectives (crown), interfaces (dual-homing),
    # tunnels (the pivot edges).
    objs = {r["host_id"]: r["captured"] for r in conn.execute(
        "SELECT host_id, captured FROM objective WHERE engagement_id=? AND host_id IS NOT NULL",
        (eid,)).fetchall()}
    seg_by_host: dict[int, set] = {}
    for r in conn.execute(
            f"SELECT host_id, COALESCE(segment,'') seg FROM host_interface "
            f"WHERE host_id IN ({ph})", ids).fetchall():
        if r["seg"]:
            seg_by_host.setdefault(r["host_id"], set()).add(r["seg"])
    tunnel_rows = conn.execute(
        "SELECT t.subnet, COALESCE(t.kind,'ligolo') kind, h.ip via_ip "
        "FROM tunnel t LEFT JOIN host h ON h.id=t.via_host_id WHERE t.engagement_id=?",
        (eid,)).fetchall()
    tunnels = [{"subnet": t["subnet"], "kind": t["kind"], "via_ip": t["via_ip"],
                "via_subnet": _subnet_of(t["via_ip"])}
               for t in tunnel_rows if t["via_ip"]]

    id_to_ip = {h["id"]: h["ip"] for h in hosts}
    dual_ips: set = set()
    for hid, segs in seg_by_host.items():
        own = _subnet_of(id_to_ip.get(hid, ""))
        if len(segs) > 1 or (segs and own not in segs):
            dual_ips.add(id_to_ip.get(hid))
    for t in tunnels:  # a tunnel's via_host is a bridge by definition
        dual_ips.add(t["via_ip"])

    # Filter undiscovered lenses out of the SVG — a fresh /24 scope
    # expansion (256 hosts) would otherwise draw 256 tiny eyes across the
    # band, dwarfing the 10 real hosts. Instead each subnet that has any
    # undiscovered hosts gets a single "+N undiscovered" summary node
    # rendered next to its enumerated peers, so the count is still
    # visible without the visual spam.
    undisc_by_subnet: dict[str, int] = {}
    nodes_by_subnet: dict[str, list[dict]] = {}
    for h in hosts:
        sn = _subnet_of(h["ip"])
        if h["stage"] == "undiscovered":
            undisc_by_subnet[sn] = undisc_by_subnet.get(sn, 0) + 1
            # Ensure the subnet exists in the map even if only undiscovered
            # hosts populate it — the summary node below will render.
            nodes_by_subnet.setdefault(sn, [])
            continue
        nodes_by_subnet.setdefault(sn, []).append({
            "ip": h["ip"], "hostname": h["hostname"], "stage": h["stage"],
            "ai": h["id"] in ai_hosts, "objective": h["id"] in objs,
            "captured": bool(objs.get(h["id"])), "dual": h["ip"] in dual_ips,
            "summary": False,
        })
    # Append the summary node per subnet (rendered muted; the SVG picks
    # up the 'summary' flag to skip hover/click behaviour and use a
    # smaller, un-focused lens).
    for sn, n in undisc_by_subnet.items():
        nodes_by_subnet.setdefault(sn, []).append({
            "ip": f"+{n} undiscovered", "hostname": "", "stage": "undiscovered",
            "ai": False, "objective": False, "captured": False, "dual": False,
            "summary": True,
        })

    # depth per subnet: 0 = perimeter; +1 past each tunnel into it (relax to fixpoint)
    subnets = set(nodes_by_subnet)
    depth = dict.fromkeys(subnets, 0)
    for _ in range(len(subnets) + 1):
        for t in tunnels:
            # Skip a self-referential tunnel (a host opening its OWN subnet, e.g. a
            # ligolo agent on a DMZ box exposing the DMZ) — it adds no depth and
            # would otherwise run away under relaxation.
            if (t["subnet"] in depth and t["via_subnet"] in depth
                    and t["subnet"] != t["via_subnet"]):
                depth[t["subnet"]] = max(depth[t["subnet"]], depth[t["via_subnet"]] + 1)
    bands = [(sn, nodes_by_subnet[sn]) for sn in sorted(subnets, key=lambda s: (depth[s], s))]

    owned = sum(1 for h in hosts if h["stage"] in _OWNED)
    n_ports = len(svc)
    meta = (f"{len(hosts)} host(s) · {n_ports} open port(s) · {owned} owned · "
            f"{len(tunnels)} pivot(s)")

    def _card(h) -> str:
        col = _stage_colour(h["stage"])
        badge = _stage_badge(h["stage"])
        hn = f"<span class='hn'>{_esc(h['hostname'])}</span>" if h["hostname"] else ""
        role = h["role"] or _derive_role(
            [s["product"] for s in svc_by_host.get(h["id"], []) if s["product"]],
            surf_kinds_by_host.get(h["id"], set()))
        hmeta = " · ".join(b for b in (_esc(h["os"]), _esc(role)) if b)
        tag_html = _tag_chips(tags_by_host.get(h["id"], []))
        ports_html = ""
        for s in svc_by_host.get(h["id"], []):
            srf = by_service.get(s["id"])
            name = srf["kind"] if srf else (s["product"] or "?")
            star = " <span class='star'>★AI</span>" if srf and srf["kind"] in AI_KINDS else ""
            ver = (
                f"<span class='pv'>{_esc(s['product'])} {_esc(s['version'])}</span>".strip()
                if s["product"]
                else ""
            )
            auth = (f" <span class='pv'>[{_esc(srf['auth'])}]</span>"
                    if srf and srf["auth"] and srf["auth"] != "unknown" else "")
            full = f"{s['product']} {s['version'] or ''}".strip() if s["product"] else name
            noise = (not srf) and (not s["product"] or name in ("?", "tcpwrapped"))
            pcls = "port port-dim" if noise else "port"
            ports_html += (
                f"<div class='{pcls}' title='{_esc(full)}'>"
                f"<span class='pn'>{s['port']}/{_esc(s['proto'])}</span>"
                f"<span class='ps'>{_esc(name)}{star}{auth}</span>{ver}</div>"
            )
        if not ports_html:
            hint = (
                "scanned — no open ports yet" if h["stage"] != "undiscovered" else "not scanned yet"
            )
            ports_html = f"<div class='port'><span class='pv'>{hint}</span></div>"
        return (
            f"<div class='nethost' style='border-left-color:{col}'>"
            f"<div class='hh'><span class='hip'>{_esc(h['ip'])}</span>{hn}{badge}</div>"
            + (f"<div class='hmeta'>{hmeta}</div>" if hmeta else "")
            + (f"<div class='hmeta'>{tag_html}</div>" if tag_html else "")
            + f"<div class='ports'>{ports_html}</div></div>"
        )

    # Group host cards by /24, ordered by pivot depth (perimeter first) to mirror
    # the tree above. Undiscovered hosts are hidden from the card grid —
    # they carry no per-host info (no ports, role, OS) so 246 empty cards
    # just push the useful ones off the page. The pivot-tree SVG above
    # still shows every host as a lens, and the "Hosts by stage" panel
    # names the count. A subnet header carries the hidden count as a hint.
    visible = [h for h in hosts if h["stage"] != "undiscovered"]
    hidden_by_subnet: dict[str, int] = {}
    for h in hosts:
        if h["stage"] == "undiscovered":
            hidden_by_subnet[_subnet_of(h["ip"])] = hidden_by_subnet.get(_subnet_of(h["ip"]), 0) + 1
    groups: dict[str, list] = {}
    for h in visible:
        groups.setdefault(_subnet_of(h["ip"]), []).append(h)

    def _subnet_head(sn: str) -> str:
        hidden = hidden_by_subnet.get(sn, 0)
        tail = (f" <span class='pv' style='color:var(--muted);font-weight:400'>"
                f"· {hidden} undiscovered hidden</span>") if hidden else ""
        return f"<div class='subhdr'>{_esc(sn)}{tail}</div>"

    all_subnets = sorted(
        set(groups) | set(hidden_by_subnet),
        key=lambda s: (depth.get(s, 0), s),
    )
    if len(all_subnets) > 1:
        cards = "".join(
            _subnet_head(sn) + "".join(_card(h) for h in groups.get(sn, []))
            for sn in all_subnets
        )
    else:
        cards = "".join(_card(h) for h in visible)
    if not cards.strip():
        cards = (
            "<div class='hmeta' style='padding:.6rem'>"
            f"all {sum(hidden_by_subnet.values())} host(s) are undiscovered — "
            "run <code>yhwach_scan --pending</code></div>"
        )

    return (
        "<h2 class='sec'>Network map — pivot tree</h2><div class='netwrap'>"
        f"<div class='nethead'><span class='lbl'>how each subnet was reached</span>"
        f"<span class='meta'>{meta}</span>"
        "<a class='dl' href='/map.svg' download style='margin-left:auto'>⤓ map.svg</a></div>"
        f"{_pivot_tree_svg(bands, tunnels)}{_map_legend()}"
        f"<div class='netgrid'>{cards}</div></div>"
    )


def _map_legend() -> str:
    """Colour/mark key for the pivot tree."""
    stages = [("scanned", "scanned"), ("enumerated", "enumerated"), ("foothold", "foothold"),
              ("looted", "looted"), ("pivoted", "pivoted"), ("done", "done")]
    sw = "".join(f"<span><i style='background:{_STAGE[k]}'></i>{lbl}</span>" for k, lbl in stages)
    marks = ("<span class='mono'>★ AI</span><span class='mono'>👑 objective</span>"
             "<span class='mono'>⇄ bridge</span><span class='mono'>➜ pivot</span>")
    return f"<div class='sevleg' style='margin:.55rem 0 .1rem'>{sw}{marks}</div>"


def _subnet_of(ip: str) -> str:
    """The /24 an IPv4 host sits in ('10.10.0.42' -> '10.10.0.0/24'); the raw
    value for anything that isn't dotted-quad."""
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return str(ip)


def _map_svg_file(conn, eid: int) -> str:
    """A self-contained pivot-tree SVG for download (/map.svg)."""
    hosts = conn.execute(
        "SELECT id, ip, COALESCE(hostname,'') hostname, stage FROM host WHERE engagement_id=? "
        "ORDER BY ip", (eid,)
    ).fetchall()
    if not hosts:
        return (
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 640 200' width='640' height='200'>"
            "<rect width='640' height='200' fill='#0a0509'/>"
            "<text x='320' y='100' fill='#856176' font-family='monospace' font-size='13' "
            "text-anchor='middle'>no hosts discovered yet</text></svg>"
        )
    ids = [h["id"] for h in hosts]
    ph = ",".join("?" * len(ids))
    ai_hosts = {
        s["host_id"]
        for s in conn.execute(
            f"SELECT host_id, kind FROM surface WHERE host_id IN ({ph})", ids
        ).fetchall()
        if s["kind"] in AI_KINDS
    }
    objs = {r["host_id"]: r["captured"] for r in conn.execute(
        "SELECT host_id, captured FROM objective WHERE engagement_id=? AND host_id IS NOT NULL",
        (eid,)).fetchall()}
    tunnel_rows = conn.execute(
        "SELECT t.subnet, COALESCE(t.kind,'ligolo') kind, h.ip via_ip "
        "FROM tunnel t LEFT JOIN host h ON h.id=t.via_host_id WHERE t.engagement_id=?",
        (eid,)).fetchall()
    tunnels = [{"subnet": t["subnet"], "kind": t["kind"], "via_ip": t["via_ip"],
                "via_subnet": _subnet_of(t["via_ip"])} for t in tunnel_rows if t["via_ip"]]
    dual_ips = {t["via_ip"] for t in tunnels}

    # Filter undiscovered lenses out of the SVG — a fresh /24 scope
    # expansion (256 hosts) would otherwise draw 256 tiny eyes across the
    # band, dwarfing the 10 real hosts. Instead each subnet that has any
    # undiscovered hosts gets a single "+N undiscovered" summary node
    # rendered next to its enumerated peers, so the count is still
    # visible without the visual spam.
    undisc_by_subnet: dict[str, int] = {}
    nodes_by_subnet: dict[str, list[dict]] = {}
    for h in hosts:
        sn = _subnet_of(h["ip"])
        if h["stage"] == "undiscovered":
            undisc_by_subnet[sn] = undisc_by_subnet.get(sn, 0) + 1
            # Ensure the subnet exists in the map even if only undiscovered
            # hosts populate it — the summary node below will render.
            nodes_by_subnet.setdefault(sn, [])
            continue
        nodes_by_subnet.setdefault(sn, []).append({
            "ip": h["ip"], "hostname": h["hostname"], "stage": h["stage"],
            "ai": h["id"] in ai_hosts, "objective": h["id"] in objs,
            "captured": bool(objs.get(h["id"])), "dual": h["ip"] in dual_ips,
            "summary": False,
        })
    # Append the summary node per subnet (rendered muted; the SVG picks
    # up the 'summary' flag to skip hover/click behaviour and use a
    # smaller, un-focused lens).
    for sn, n in undisc_by_subnet.items():
        nodes_by_subnet.setdefault(sn, []).append({
            "ip": f"+{n} undiscovered", "hostname": "", "stage": "undiscovered",
            "ai": False, "objective": False, "captured": False, "dual": False,
            "summary": True,
        })
    subnets = set(nodes_by_subnet)
    depth = dict.fromkeys(subnets, 0)
    for _ in range(len(subnets) + 1):
        for t in tunnels:
            # Skip a self-referential tunnel (a host opening its OWN subnet, e.g. a
            # ligolo agent on a DMZ box exposing the DMZ) — it adds no depth and
            # would otherwise run away under relaxation.
            if (t["subnet"] in depth and t["via_subnet"] in depth
                    and t["subnet"] != t["via_subnet"]):
                depth[t["subnet"]] = max(depth[t["subnet"]], depth[t["via_subnet"]] + 1)
    bands = [(sn, nodes_by_subnet[sn]) for sn in sorted(subnets, key=lambda s: (depth[s], s))]
    return _pivot_tree_svg(bands, tunnels, standalone=True)


def _host_detail(conn, eid: int, ip: str, *, reveal: bool = True) -> str:
    """Focus view for one host: its open ports/services, findings, and the
    attempts run against it. Reached by clicking a node on the network map."""
    h = conn.execute(
        "SELECT id, ip, COALESCE(hostname,'') hostname, COALESCE(os,'') os, stage, "
        "COALESCE(role,'') role FROM host WHERE engagement_id=? AND ip=?",
        (eid, ip),
    ).fetchone()
    back = "<a class='back' href='/map'>← back to map</a>"
    if h is None:
        return f"{back}<div class='hostwrap'><p class='empty'>no host {_esc(ip)} in this engagement</p></div>"
    col = _stage_colour(h["stage"])
    badge = _stage_badge(h["stage"])
    svc = conn.execute(
        "SELECT s.port, COALESCE(s.proto,'tcp') proto, COALESCE(s.product,'') product, "
        "COALESCE(s.version,'') version, "
        "(SELECT kind FROM surface su WHERE su.service_id=s.id LIMIT 1) kind, "
        "(SELECT COALESCE(auth,'') FROM surface su WHERE su.service_id=s.id LIMIT 1) auth "
        "FROM service s WHERE s.host_id=? ORDER BY s.port",
        (h["id"],),
    ).fetchall()
    ports = ""
    for s in svc:
        name = s["kind"] or s["product"] or "?"
        star = " <span class='star'>★AI</span>" if s["kind"] in AI_KINDS else ""
        ver = (
            f"<span class='pv'>{_esc(s['product'])} {_esc(s['version'])}</span>".strip()
            if s["product"]
            else ""
        )
        auth = f" <span class='pv'>[{_esc(s['auth'])}]</span>" if s["auth"] else ""
        ports += (
            f"<div class='port'><span class='pn'>{s['port']}/{_esc(s['proto'])}</span>"
            f"<span class='ps'>{_esc(name)}{star}{auth}</span>{ver}</div>"
        )
    ports = ports or "<p class='empty' style='padding:.3rem 0'>no open ports recorded</p>"

    finds = conn.execute(
        "SELECT severity, title, COALESCE(tag,'') tag, COALESCE(class,'') cls "
        "FROM finding WHERE host_id=? AND status IN ('open','confirmed','exploited') "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, id",
        (h["id"],),
    ).fetchall()
    frows = ""
    for f in finds:
        sc = _SEV.get(f["severity"], "#7f8792")
        tag = f" <code class='mono'>{_esc(f['tag'])}</code>" if f["tag"] else ""
        cls = (
            f" <span class='pv'>{_esc(f['cls'])}</span>" if f["cls"] else ""
        )
        frows += (
            f"<div class='port'><span class='chip' style='color:{sc};background:{sc}22'>"
            f"{_esc(f['severity'])}</span> <span class='ps'>{_esc(f['title'])}{tag}{cls}</span></div>"
        )
    frows = frows or "<p class='empty' style='padding:.3rem 0'>no findings yet</p>"

    att = conn.execute(
        "SELECT COALESCE(technique_id,playbook_rule_id) t, result, COALESCE(reason,'') reason "
        "FROM attempt WHERE host_id=? ORDER BY id DESC LIMIT 20",
        (h["id"],),
    ).fetchall()
    arows = ""
    for a in att:
        rc = {"success": "#0ca30c", "partial": "#fab219"}.get(a["result"], "#d03b3b")
        arows += (
            f"<div class='port'><span class='pn'>{_esc(a['result'])}</span>"
            f"<span class='ps' style='color:{rc}'>{_esc(a['t'])}</span>"
            f" <span class='pv'>{_esc(a['reason'])}</span></div>"
        )
    arows = arows or "<p class='empty' style='padding:.3rem 0'>nothing attempted yet</p>"

    hn = f" · {_esc(h['hostname'])}" if h["hostname"] else ""
    hmeta = " · ".join(b for b in (_esc(h["os"]), _esc(h["role"])) if b)
    tags = yhdb.tags_for_hosts(conn, eid).get(h["id"], [])
    tag_html = _tag_chips(tags)

    # Interfaces (dual-homing) + stage-history trail.
    ifaces = conn.execute(
        "SELECT ip, COALESCE(segment,'') seg, is_primary FROM host_interface "
        "WHERE host_id=? ORDER BY is_primary DESC, ip", (h["id"],)).fetchall()
    iface_html = ""
    for i in ifaces:
        seg = f" <span class='pv'>{_esc(i['seg'])}</span>" if i["seg"] else ""
        prim = " <span class='pv'>(primary)</span>" if i["is_primary"] else ""
        iface_html += (f"<div class='port'><span class='pn'>{_esc(i['ip'])}</span>{seg}{prim}</div>")

    hist = yhdb.stage_history(conn, h["id"])
    trail = ""
    for t in hist:
        frm = f"{_esc(t['from_stage'])} → " if t["from_stage"] else ""
        col = _stage_colour(t["to_stage"])
        why = (f" <span class='ps'>— {_esc(t['note'])}</span>"
               if "note" in t.keys() and t["note"] else "")  # noqa: SIM118 — sqlite3.Row
        trail += (f"<div class='port'><span class='pv'>{_esc(t['ts'])}</span> "
                  f"<span class='ps'>{frm}</span>"
                  f"<span class='chip' style='color:{col};background:{col}22'>"
                  f"{_esc(t['to_stage'])}</span>{why}</div>")
    trail = trail or "<p class='empty' style='padding:.3rem 0'>no transitions recorded</p>"

    parts = [
        f"{back}<div class='hostwrap'>",
        f"<div class='hh'><span class='hip' style='font-size:1.1rem'>{_esc(h['ip'])}</span>"
        f"{hn} {badge}</div>",
        (f"<div class='hmeta'>{hmeta}</div>" if hmeta else ""),
        (f"<div class='hmeta'>{tag_html}</div>" if tag_html else ""),
    ]
    # The stage dossier: what this box is, what each surface kind IS, and what is
    # still dark — composed from the DB and the shipped packs, no model involved.
    # /host has no poll_url (one-shot render per click), so it can afford this.
    try:
        from yhwach import dossier as _dossier

        brief = _dossier.build(conn, eid, h["ip"])
    except Exception:  # noqa: BLE001 — a pack error must never break the host page
        brief = ""
    if brief and reveal:
        parts += ["<h2 class='sec'>Dossier</h2>",
                  f"<div class='report dossier'>{_md_to_html(brief)}</div>"]
    elif brief:
        # The dossier quotes credential identifiers, loot summaries and finding
        # evidence, so --redact withholds the body rather than masking per-line.
        parts += ["<h2 class='sec'>Dossier</h2>",
                  "<div class='card'>" + _empty(
                      "withheld under --redact — it quotes credentials, loot summaries "
                      "and finding evidence") + "</div>"]
    # Model-authored prose, visibly distinct from scan results and labelled with
    # its author and whether the world model has moved on since it was written.
    # The board only ever SELECTs this: it never writes, never clears a stale row
    # and never calls a model.
    for a in yhdb.host_annotations(conn, h["id"]):
        stale = (" <span class='chip' style='color:#d9a441;background:#d9a44122'>"
                 "written at an earlier state of this host"
                 f" (stage was {_esc(a['stage'])})</span>" if a["stale"] else "")
        # An annotation is free text a model wrote about the host; it can quote
        # anything. Keep the header so the operator knows a note exists.
        note_body = (_md_to_html(a["body"]) if reveal
                     else "<div class='muted'>[redacted]</div>")
        parts += [
            f"<h2 class='sec'>Note — {_esc(a['section'])}</h2>",
            f"<div class='report annot{' stale' if a['stale'] else ''}'>"
            f"<div class='annot-by'>by {_esc(a['author'] or 'unknown')}"
            f"{(' · ' + _esc(a['model'])) if a['model'] else ''} · "
            f"{_esc(str(a['created_at'])[:19])}{stale}</div>"
            f"{note_body}</div>",
        ]
    if iface_html:
        parts += ["<h2 class='sec'>Interfaces</h2><div class='ports'>", iface_html, "</div>"]
    parts += [
        "<h2 class='sec'>Stage history</h2><div class='ports'>", trail, "</div>",
        "<h2 class='sec'>Open ports &amp; services</h2><div class='ports'>", ports, "</div>",
        "<h2 class='sec'>Findings</h2><div class='ports'>", frows, "</div>",
        "<h2 class='sec'>Attempts</h2><div class='ports'>", arows, "</div></div>",
    ]
    return "".join(parts)


def _attack_path(conn, eid: int) -> str:
    """The attack path, as a query over memory (never authored): the host-stage
    progression owned so far, the crown objectives it drives toward, and the
    BloodHound-style graph edges that connect them. Read-only; regenerable."""
    # Host nodes worth putting on the path: enumerated-or-deeper, or any host
    # carrying a high/critical open finding (an entry point), plus their top lead.
    hosts = conn.execute(
        "SELECT h.ip, h.stage, COALESCE(h.role,'') role, "
        "(SELECT f.tag FROM finding f WHERE f.host_id=h.id AND f.status IN ('open','confirmed','exploited') "
        " AND COALESCE(f.tag,'')<>'' ORDER BY CASE f.severity WHEN 'critical' THEN 0 "
        " WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.id LIMIT 1) top_tag, "
        "(SELECT f.severity FROM finding f WHERE f.host_id=h.id AND f.status IN ('open','confirmed','exploited') "
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        " WHEN 'medium' THEN 2 ELSE 3 END, f.id LIMIT 1) top_sev "
        "FROM host h WHERE h.engagement_id=?",
        (eid,),
    ).fetchall()
    path_hosts = [
        r
        for r in hosts
        if r["stage"] in _OWNED
        or r["stage"] == "enumerated"
        or r["top_sev"] in ("critical", "high")
    ]
    path_hosts.sort(key=lambda r: (_RANK.get(r["stage"], 0), r["ip"]))

    objs = conn.execute(
        "SELECT o.label, o.kind, o.captured, COALESCE(h.ip,'') ip FROM objective o "
        "LEFT JOIN host h ON h.id=o.host_id WHERE o.engagement_id=? ORDER BY o.captured, o.id",
        (eid,),
    ).fetchall()
    edges = conn.execute(
        "SELECT src, dst, kind, COALESCE(confidence,'') conf FROM edge "
        "WHERE engagement_id=? ORDER BY id DESC LIMIT 12",
        (eid,),
    ).fetchall()
    n_cred = _scalar(conn, "SELECT COUNT(*) FROM credential WHERE engagement_id=?", (eid,))
    n_owned = sum(1 for r in hosts if r["stage"] in _OWNED)

    head = "<h2 class='sec'>Attack path</h2>"
    if not path_hosts and not objs and not edges:
        return (
            head + "<div class='path'><p class='empty' style='margin:0'>no path yet — "
            "run recon to surface entry points</p></div>"
        )

    # -- the flow: entry/owned hosts left->right, crown objectives terminal ----
    nodes: list[str] = []
    for r in path_hosts:
        col = _stage_colour(r["stage"])
        lead = ""
        if r["top_tag"]:
            sc = _SEV.get(r["top_sev"], "#7f8792")
            lead = (
                f"<div class='meta'><span class='chip' style='color:{sc};"
                f"background:{sc}22'>{_esc(r['top_tag'])}</span></div>"
            )
        role = f"<div class='meta'>{_esc(r['role'])}</div>" if r["role"] else ""
        nodes.append(
            f"<div class='node' style='border-left-color:{col}'>"
            f"<div class='ip'>{_esc(r['ip'])}</div>"
            f"<div class='st' style='color:{col}'>{_esc(r['stage'])}</div>"
            f"{role}{lead}</div>"
        )
    for o in objs:
        won = o["captured"]
        cls = "node crown won" if won else "node crown"
        mark = "✔ captured" if won else "pending"
        mc = "var(--ok)" if won else "var(--accent)"
        where = f"<div class='meta'>{_esc(o['ip'])}</div>" if o["ip"] else ""
        nodes.append(
            f"<div class='{cls}'><div class='ip'>👑 {_esc(o['label'])}</div>"
            f"<div class='st' style='color:{mc}'>{mark}</div>{where}</div>"
        )
    flow = "<span class='arrow'>›</span>".join(nodes) if nodes else ""

    # -- the graph edges (real BloodHound-style attack graph) -----------------
    obj_ips = {o["ip"] for o in objs if o["ip"]}
    edge_rows = ""
    for e in edges:
        hot = e["dst"] in obj_ips or "admin" in (e["dst"] or "").lower()
        edge_rows += (
            f"<div class='edge{' hot' if hot else ''}'>"
            f"<code>{_esc(e['src'])}</code><span class='k'>{_esc(e['kind'])}</span>"
            f"<code>{_esc(e['dst'])}</code></div>"
        )
    edge_block = f"<div class='edges'>{edge_rows}</div>" if edge_rows else ""

    note = ""
    if n_cred and n_owned:
        note = (
            f"<div class='pathnote'>🔑 <b>{n_cred}</b> credential(s) held — "
            f"reusable across all {n_owned} owned host(s) (credential_reuse)</div>"
        )
    elif n_cred:
        note = f"<div class='pathnote'>🔑 <b>{n_cred}</b> credential(s) held</div>"

    # Live shortest paths from what we own to each objective / DA crown — the
    # first surface to actually render db.shortest_path. Best-effort.
    from yhwach import pathfind

    try:
        obj_paths = pathfind.paths_to_objectives(conn, eid)
    except Exception:  # noqa: BLE001 — decoration only
        obj_paths = []
    path_rows = ""
    for p in obj_paths:
        if p.reachable:
            path_rows += (
                f"<div class='edge hot'><code>{_esc(pathfind.render_path(conn, p.path))}</code>"
                f"<span class='k'>{p.hops} hop → {_esc(p.target_label)}</span></div>"
            )
        else:
            path_rows += (
                f"<div class='edge'><code>{_esc(p.target_label)}</code>"
                "<span class='k'>no known path yet</span></div>"
            )
    paths_block = (
        "<div class='edges'><div class='pathnote'>🎯 Paths to objectives "
        f"(from what you own):</div>{path_rows}</div>" if path_rows else ""
    )

    inner = flow or "<p class='empty' style='margin:0'>no reachable nodes yet</p>"
    return head + (
        f"<div class='path'>{paths_block}<div class='flow'>{inner}</div>{edge_block}{note}</div>"
    )


def _hosts(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT h.ip, COALESCE(h.os,'') os, h.stage, COALESCE(h.role,'') role, "
        "(SELECT GROUP_CONCAT(s.kind) FROM surface s WHERE s.host_id=h.id) kinds "
        "FROM host h WHERE h.engagement_id=? ORDER BY "
        "(h.stage IN ('foothold','looted','pivoted','done')) DESC, h.ip",
        (eid,),
    ).fetchall()
    if not rows:
        return "<h2 class='sec'>Hosts</h2><div class='card'><p class='empty' style='padding:.9rem'>none</p></div>"
    # Hide `undiscovered` rows by default — they carry no per-host info
    # (no OS, role, surfaces) so they're just visual weight; the
    # Hosts-by-stage panel above already reports how many exist and lets
    # the operator drill in. A "hidden" footer names the count so nothing
    # is invisible.
    visible = [r for r in rows if r["stage"] != "undiscovered"]
    hidden = len(rows) - len(visible)
    shown = visible[:_BOARD_ROW_CAP]
    body = ""
    for r in shown:
        badge = _stage_badge(r["stage"])
        kinds = (r["kinds"] or "").split(",") if r["kinds"] else []
        surf = ", ".join(kinds) if kinds else "—"
        star = " <span class='star'>★AI</span>" if any(k in AI_KINDS for k in kinds) else ""
        body += (
            f"<tr><td class='mono'>{_hlink(r['ip'])}</td><td class='mono'>{_esc(r['os'])}</td>"
            f"<td>{badge}</td><td class='mono'>{_esc(r['role']) or '—'}</td>"
            f"<td class='mono'>{_esc(surf)}{star}</td></tr>"
        )
    if not visible:
        body = ("<tr><td colspan='5' class='mono' style='padding:.6rem;color:var(--muted)'>"
                f"all {hidden} host(s) are undiscovered — run <code>yhwach_scan --pending</code></td></tr>")
    hidden_note = (
        f"<div class='hidden-note'>{hidden} undiscovered host(s) hidden — "
        "see <em>Hosts by stage</em> above.</div>"
        if hidden else ""
    )
    return (
        "<h2 class='sec'>Hosts</h2><div class='card'><table><thead><tr><th>ip</th><th>os</th>"
        f"<th>stage</th><th>role</th><th>surfaces</th></tr></thead><tbody>{body}</tbody></table>"
        + _more_note(len(visible), len(shown), "see the Recon tab for every host")
        + f"{hidden_note}</div>"
    )


def _findings(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT COALESCE(h.ip,'-') ip, f.severity, f.title, COALESCE(f.tag,'') tag, "
        "COALESCE(f.class,'') cls "
        "FROM finding f LEFT JOIN host h ON h.id=f.host_id WHERE f.engagement_id=? AND f.status IN ('open','confirmed','exploited') "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, f.id",
        (eid,),
    ).fetchall()
    if not rows:
        return (
            "<h2 class='sec'>Findings</h2><div class='card'>"
            "<p class='empty' style='padding:.9rem'>none yet</p></div>"
        )
    shown = rows[:_BOARD_ROW_CAP]
    body = ""
    for r in shown:
        col = _SEV.get(r["severity"], "#7f8792")
        chip = f"<span class='chip' style='color:{col};background:{col}22'>{_esc(r['severity'])}</span>"
        tag = f"<code class='mono'>{_esc(r['tag'])}</code>" if r["tag"] else ""
        # finding.class = the taxonomy axis (ATT&CK / OWASP-LLM / ATLAS / CWE / CVE);
        # previously invisible in the UI though it drives the audit lens + report.
        cls = (
            f"<code class='mono' style='color:var(--muted);font-size:.66rem'>"
            f"{_esc(r['cls'])}</code>" if r["cls"] else ""
        )
        body += (
            f"<tr><td>{chip}</td><td class='mono'>{_hlink(r['ip'])}</td>"
            f"<td>{_esc(r['title'])}</td><td>{tag}</td><td>{cls}</td></tr>"
        )
    return (
        "<h2 class='sec'>Findings</h2><div class='card'><table><thead><tr><th>sev</th><th>host</th>"
        f"<th>title</th><th>tag</th><th>class</th></tr></thead><tbody>{body}</tbody></table>"
        + _more_note(len(rows), len(shown), "severity-ordered; see `yhwach findings`")
        + "</div>"
    )


_LLM_STATUS_COL = {"PRESENT": "#6bb36b", "ABSENT": "#e06767", "UNKNOWN": "#5b626d"}


def _creds_vault(conn, eid: int, *, reveal: bool = True,
                 cap: int | None = _BOARD_ROW_CAP) -> str:
    """The credential vault: every cred, its secret (masked, click-to-reveal +
    copy), what it opens (host:port/proto, proven), whether it's validated, and
    its provenance. Read-only view over `credential` + `credential_access`."""
    creds = yhdb.list_credentials(conn, eid)
    access = yhdb.list_credential_access(conn, eid)
    head = "<h2 class='sec'>Credential vault</h2>"
    if not creds:
        return (
            head + "<div class='card'><p class='empty' style='padding:.9rem'>"
            "no credentials captured yet</p></div>"
        )

    def _secret_cell(secret: str | None) -> str:
        if secret is None or secret == "":
            return "<span class='mono'>—</span>"
        if not reveal:  # `yhwach ui --redact` only
            return "<span class='mono'>[redacted]</span>"
        # Local-only board: show the secret in plaintext, with a copy button.
        s = _esc(secret)  # html.escape quotes too → safe in the data attribute + text
        return (
            f"<code class='sec' data-s=\"{s}\">{s}</code> "
            "<button class='mini' title='copy' onclick=\"var s=this.parentElement."
            "querySelector('.sec').getAttribute('data-s');"
            "navigator.clipboard&&navigator.clipboard.writeText(s);"
            "var b=this;b.textContent='copied';setTimeout(function(){b.textContent='copy';},900);"
            "\">copy</button>"
        )

    def _opens_cell(cid: int, validated_ip: str | None) -> str:
        rows = access.get(cid, [])
        if not rows:
            if validated_ip:
                return f"<span class='ps'>{_esc(validated_ip)}</span>"
            return "<span class='mono'>untried</span>"
        # Condensed view: a cred sprayed across a /24 produces dozens of access
        # rows. The signal is WHAT it opens (by service) + how many hosts — the
        # per-host IPs are repetitive (the host is in the 'validated' column + the
        # service matrix) and the failures are expected spray noise. So: proven ->
        # distinct service chips (port/proto, no IP) + an "opens N" host count;
        # failed -> one collapsed count with the full list behind <details>.
        proven = [a for a in rows if a["result"] != "fail"]
        failed = [a for a in rows if a["result"] == "fail"]
        out = ""
        if proven:
            svc: dict[str, bool] = {}   # "port/proto" -> any host gave admin
            for a in proven:
                proto = _esc(a["proto"] or "?")
                key = f"{a['port']}/{proto}" if a["port"] else proto
                svc[key] = svc.get(key, False) or (a["result"] == "admin")
            chips = ""
            for key, adm in svc.items():
                col = "#0ca30c" if adm else "#199e70"
                mark = " ★" if adm else ""
                chips += (f"<span class='chip' style='color:{col};background:{col}22;"
                          f"margin:1px 2px'>{key}{mark}</span>")
            n_hosts = len({a["host_ip"] for a in proven})
            out += (f"<span class='chip' style='color:#0ca30c;background:#0ca30c22;"
                    f"margin:1px 2px'>✓ opens {n_hosts}</span>{chips}")
        if failed:
            items = ""
            for a in failed:
                tgt = _esc(a["host_ip"])
                if a["port"]:
                    tgt += f":{a['port']}"
                if a["proto"]:
                    tgt += f"/{_esc(a['proto'])}"
                items += (f"<span class='chip' style='color:#e67878;background:#d03b3b22;"
                          f"margin:1px 2px'>{tgt}</span>")
            det = (f"<details class='fails'><summary class='sub2' style='cursor:pointer'>"
                   f"✗ {len(failed)} failed</summary>"
                   f"<div style='margin-top:.25rem'>{items}</div></details>")
            out += f"<div style='margin-top:.25rem'>{det}</div>" if proven else det
        return out or "<span class='mono'>untried</span>"

    _n_creds = len(creds)
    _shown_creds = creds if cap is None else creds[:cap]
    _n_shown = len(_shown_creds)
    body = ""
    for c in _shown_creds:
        cid = int(c["id"])
        validated_ip = c["validated_on_host_ip"] if "validated_on_host_ip" in c.keys() else None  # noqa: SIM118
        vchip = (
            f"<span class='chip' style='color:#0ca30c;background:#0ca30c22'>✓ {_esc(validated_ip)}</span>"
            if validated_ip
            else "<span class='chip' style='color:#856176;background:#2f1b2c'>untried</span>"
        )
        src = _esc(c["source"])
        src_ip = c["source_host_ip"] if "source_host_ip" in c.keys() else None  # noqa: SIM118
        if src_ip:
            src += f" <span class='mono'>@{_esc(src_ip)}</span>"
        body += (
            f"<tr><td><b>{_esc(c['identifier'])}</b></td>"
            f"<td>{_secret_cell(c['secret'])}</td>"
            f"<td class='mono'>{_esc(c['kind'])}</td>"
            f"<td>{_opens_cell(cid, validated_ip)}</td>"
            f"<td>{vchip}</td>"
            f"<td class='mono' style='font-size:.76rem'>{src}</td></tr>"
        )
    return (
        head + "<div class='card'><table><thead><tr><th>user</th><th>secret</th><th>kind</th>"
        "<th>access (proven / failed)</th><th>validated</th><th>source</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
        + _more_note(_n_creds, _n_shown, "see the Vault tab")
        + "</div>"
    )


def _poc_panel(conn, eid: int) -> str:
    """Every objective and whether it can be proved — not only the ones with steps.

    `poc.list_objectives` derives its list from `poc_step` events, so an
    objective with ZERO recorded steps could never appear: the page whose job is
    "can I prove this?" was structurally blind to the one case that loses points,
    a captured flag with no chain. This reads the `objective` table instead and
    joins the steps on, so an unproved capture is the loudest row here.
    """
    from yhwach import poc

    head = "<h2 class='sec'>PoC chains — can I prove what I captured?</h2>"
    objectives = conn.execute(
        "SELECT o.label, o.kind, o.captured, o.points, COALESCE(h.ip,'') host_ip "
        "FROM objective o LEFT JOIN host h ON h.id=o.host_id "
        "WHERE o.engagement_id=? ORDER BY o.captured DESC, o.points DESC, o.label",
        (eid,),
    ).fetchall()
    with_steps = dict(poc.list_objectives(conn, eid))
    # Steps can also exist for a label that is not in the objective table.
    orphans = [lbl for lbl in with_steps if not any(r["label"] == lbl for r in objectives)]

    if not objectives and not orphans:
        return (head + "<div class='card'>"
                + _empty("no objective recorded yet — add them with `yhwach objective`")
                + "</div>")

    def _chain(label: str, n_steps: int) -> str:
        steps = poc.steps_for(conn, eid, label) if n_steps else []
        rows = ""
        for s in steps:
            cmd = _esc(s.get("command") or "")
            out = _esc((s.get("output") or "").strip())
            title = _esc(s.get("title") or f"step {s.get('seq')}")
            # The four fields the old panel threw away.
            meta = []
            if s.get("host"):
                meta.append(f"host {_hlink(s['host'])}")
            if s.get("cve"):
                meta.append(f"<code class='mono'>{_esc(s['cve'])}</code>")
            if s.get("script"):
                meta.append(f"script <code class='mono'>{_esc(s['script'])}</code>")
            if s.get("source"):
                meta.append(f"source {_esc(s['source'])}")
            if s.get("_ts"):
                meta.append(f"<span class='muted'>{_esc(str(s['_ts'])[:19])}</span>")
            metaline = (f"<div class='wk-meta'>{' · '.join(meta)}</div>" if meta else "")
            stub = ("<span class='mk n'>TODO stub</span> "
                    if cmd.strip().upper().startswith("TODO") else "")
            truncated = ("<span class='mk p'>output truncated</span> "
                         if "[truncated]" in (s.get("output") or "") else "")
            outblock = (f"<pre class='report' style='margin:.3rem 0;padding:.6rem .8rem'>{out}</pre>"
                        if out else "<div class='muted' style='font-size:.74rem'>no output "
                                    "recorded for this step</div>")
            cmdblock = (f"<pre class='report' style='margin:.3rem 0;padding:.6rem .8rem'>"
                        f"$ {cmd}</pre>" if cmd else "")
            rows += (f"<div style='padding:.5rem 0;border-bottom:1px solid var(--line)'>"
                     f"<div class='wk-ip'>{s.get('seq')}. {title} {stub}{truncated}</div>"
                     f"{cmdblock}{outblock}{metaline}</div>")
        return rows

    blocks = ""
    for r in objectives:
        label = r["label"]
        n = with_steps.get(label, 0)
        captured = bool(r["captured"])
        if captured and not n:
            state = "<span class='mk n'>CAPTURED, NO PROOF</span>"
        elif captured:
            state = f"<span class='mk y'>captured · {n} step(s)</span>"
        elif n:
            state = f"<span class='mk p'>not captured · {n} step(s)</span>"
        else:
            state = "<span class='muted'>outstanding</span>"
        where = f" <span class='muted mono'>@{_esc(r['host_ip'])}</span>" if r["host_ip"] else ""
        pts = f" <span class='muted'>{r['points']}pts</span>" if r["points"] else ""
        body = _chain(label, n) or (
            "<div class='muted' style='padding:.5rem 0'>No step recorded. "
            + ("<b>This objective is marked captured and cannot be reproduced</b> — "
               if captured else "")
            + "record the chain with <code class='mono'>yhwach poc-step</code>.</div>")
        blocks += (
            f"<details class='card' style='margin-bottom:.7rem;padding:.6rem .9rem'>"
            f"<summary style='cursor:pointer;font-weight:600'>\U0001F451 {_esc(label)}{where}"
            f"{pts} · {state}</summary>"
            f"<div style='margin-top:.5rem'>{body}</div></details>"
        )
    for label in orphans:
        blocks += (
            f"<details class='card' style='margin-bottom:.7rem;padding:.6rem .9rem'>"
            f"<summary style='cursor:pointer;font-weight:600'>\U0001F451 {_esc(label)} "
            f"· <span class='mk p'>steps recorded, not in the objective table</span>"
            f"</summary><div style='margin-top:.5rem'>{_chain(label, with_steps[label])}</div>"
            f"</details>")

    n_cap = sum(1 for r in objectives if r["captured"])
    n_unproved = sum(1 for r in objectives if r["captured"] and not with_steps.get(r["label"], 0))
    summary = (f"<div class='hidden-note'>{len(objectives)} objective(s) · {n_cap} captured"
               + (f" · <b>{n_unproved} captured with no reproducible chain</b>"
                  if n_unproved else " · every capture has a chain")
               + ". This page lists every objective, not only those with steps — a captured "
                 "flag you cannot reproduce is the case that loses the point.</div>")
    return head + summary + blocks


_EVENT_SUBJECT_KEYS = (
    "host", "ip", "target", "to", "stage", "identifier", "user", "cred",
    "subnet", "via", "title", "kind", "mode", "count", "n", "reason",
)


def _event_summary(payload_json: str | None) -> str:
    """A short human subject decoded from event.payload_json — the timeline was
    bare verbs (kind only); this gives each row its subject (host, cred, stage…)."""
    import json as _json

    try:
        p = _json.loads(payload_json) if payload_json else {}
    except (ValueError, TypeError):
        return ""
    if not isinstance(p, dict):
        return ""
    parts: list[str] = []
    for k in _EVENT_SUBJECT_KEYS:
        v = p.get(k)
        if v in (None, "", [], {}):
            continue
        parts.append(f"{k}={v}" if k in ("to", "stage", "reason", "mode") else str(v))
        if len(parts) >= 3:
            break
    return " · ".join(parts)[:90]


def _activity(conn, eid: int) -> str:
    evs = conn.execute(
        "SELECT ts, kind, payload_json FROM event WHERE engagement_id=? ORDER BY id DESC LIMIT 14",
        (eid,),
    ).fetchall()
    lines: list[str] = []
    for e in evs:
        sub = _event_summary(e["payload_json"])
        subhtml = (
            f" <span class='d' style='color:var(--muted)'>{_esc(sub)}</span>" if sub else ""
        )
        lines.append(
            f"<li><span class='t'>{_esc(e['ts'])}</span>"
            f"<span class='e'>{_esc(e['kind'])}</span>{subhtml}</li>"
        )
    items = "".join(lines) or "<li class='empty'>no activity</li>"
    return f"<h2 class='sec'>Recent activity</h2><div class='card' style='padding:.3rem .9rem'><ul class='tl'>{items}</ul></div>"


_ATTEMPT_COL = {
    "success": "#6bb36b", "admin": "#7be07b", "fail": "#e06767",
    "blocked": "#d9a441", "partial": "#9aa0a6",
}


# ─── PR-4 UI panels — the three surfaces the world-model repair exposes ─────


def _host_stage_board(conn, eid: int) -> str:
    """Every host grouped by FSM stage, colored per _STAGE.

    Answers "what's the shape of the estate?" at a glance — the operator sees
    the big undiscovered bucket (proof PR-1's scope expansion worked), the
    scanned/enumerated buckets they've grown, and the coloured owned tail.

    Undiscovered hosts are rolled up by /24 subnet inside a native <details>
    so a fresh scope expansion (256 chips) doesn't spam the page — clicking
    the subnet row reveals the individual IPs. Other stages keep per-host
    chips because their labels carry real info (hostname/role) worth seeing
    at a glance.
    """
    rows = conn.execute(
        "SELECT ip, COALESCE(hostname,'') hostname, stage, "
        "COALESCE(discovery_source,'') src, scan_needed, "
        "COALESCE(role,'') role "
        "FROM host WHERE engagement_id=? ORDER BY stage, ip",
        (eid,),
    ).fetchall()
    if not rows:
        return ""

    # Bucket by stage in _RANK order (undiscovered → done, blocked last).
    buckets: dict[str, list] = {}
    for r in rows:
        buckets.setdefault(r["stage"], []).append(r)
    order = sorted(buckets.keys(), key=lambda s: _RANK.get(s, 99))

    # Per-bucket cap for stages that render as chips (see below).
    cap = 24

    def _chip(r, col: str) -> str:
        label = r["hostname"] or r["ip"]
        tip = r["ip"] if r["hostname"] else ""
        pend = " •" if r["scan_needed"] else ""
        return (
            f"<span class='hostchip' title='{_esc(tip)}' "
            f"style='color:{col};border-color:{col};background:{col}18'>"
            f"{_esc(label)}{pend}</span>"
        )

    def _subnet_of(ip: str) -> str:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else ip

    def _undiscovered_col(items: list, col: str) -> str:
        """Undiscovered special-case: /24 rollup, click-to-expand chips."""
        by_subnet: dict[str, list] = {}
        for r in items:
            by_subnet.setdefault(_subnet_of(r["ip"]), []).append(r)
        subnet_rows = ""
        # Sort subnets by size desc so the biggest bulk sits at the top.
        for subnet, subnet_items in sorted(
            by_subnet.items(), key=lambda kv: (-len(kv[1]), kv[0]),
        ):
            n = len(subnet_items)
            # Show the chips inside <details>; the <summary> is the rollup line.
            # No JS — native browser expand/collapse.
            inner = "".join(_chip(r, col) for r in subnet_items)
            subnet_rows += (
                f"<details class='subnet-fold'>"
                f"<summary style='color:{col}'>"
                f"<span class='mono'>{_esc(subnet)}</span>"
                f"<span class='sn-n'>{n} host{'s' if n != 1 else ''}</span>"
                f"</summary>"
                f"<div class='chips subnet-chips'>{inner}</div>"
                f"</details>"
            )
        return f"<div class='chips'>{subnet_rows}</div>"

    cols_html = ""
    for stage in order:
        col = _stage_colour(stage)
        items = buckets[stage]
        total = len(items)
        if stage == "undiscovered":
            body = _undiscovered_col(items, col)
        else:
            shown = items[:cap]
            chips = "".join(_chip(r, col) for r in shown)
            overflow = (
                f"<span class='hostchip more'>+{total - cap} more</span>"
                if total > cap else ""
            )
            body = f"<div class='chips'>{chips}{overflow}</div>"
        cols_html += (
            f"<div class='stagecol'>"
            f"<div class='stagehdr' style='color:{col};border-color:{col}'>"
            f"<b>{_esc(stage)}</b><span class='n'>{total}</span></div>"
            f"{body}"
            f"</div>"
        )
    # Legend line: pending-scan dot legend + a note about the fold.
    legend = ("<div class='stageleg'>"
              "<span class='hostchip' style='color:#5b626d;border-color:#5b626d;background:#5b626d18'>•</span>"
              " = pending scan (scan_needed=1). Run yhwach_scan to drain. "
              "Click an <span class='mono'>undiscovered</span> subnet row to expand its hosts.</div>")
    return (
        "<h2 class='sec'>Hosts by stage</h2>"
        f"<div class='card' style='padding:.9rem'><div class='stageboard'>{cols_html}</div>{legend}</div>"
    )


def _cred_service_matrix(conn, eid: int) -> str:
    """The vault × reachable services grid.

    Every vault credential is a row; every discovered service is a column.
    Cells are the sprayer's verdict: green ADMIN / green ✓ success / red ✗
    fail / grey · untried. Answers "have my creds been tried against every
    place they can be tried?" — the exact question PR-3's auto-spray hook
    is designed to make trivial to answer.
    """
    creds = conn.execute(
        "SELECT id, identifier, kind FROM credential WHERE engagement_id=? ORDER BY id",
        (eid,),
    ).fetchall()
    services = conn.execute(
        "SELECT s.id sid, h.ip, s.port, COALESCE(s.product,'') product "
        "FROM service s JOIN host h ON h.id=s.host_id "
        "WHERE h.engagement_id=? ORDER BY h.ip, s.port",
        (eid,),
    ).fetchall()
    if not creds or not services:
        return ""

    # Compute the sprayer's protocol classification per service — services
    # whose protocol is None (unknown/webbish) are hidden from the matrix so
    # the grid stays informative. Matches sprayer._protocol_for exactly.
    from yhwach import sprayer as yhspray

    scored: list[tuple] = []
    for s in services:
        proto = yhspray._protocol_for(s["port"], s["product"])
        if proto is None:
            continue
        scored.append((s["sid"], s["ip"], s["port"], proto))
    if not scored:
        return ""

    # Reorder columns so services with a positive auth (admin/success) come
    # FIRST — the operator's eye lands on the win instead of a wall of
    # untried dots. Otherwise the interesting column often gets cut off by
    # the col_cap truncation on a wide estate.
    positive_hids: set[int] = set()
    for r in conn.execute(
        "SELECT DISTINCT host_id, port, proto FROM credential_access "
        "WHERE engagement_id=? AND result IN ('admin','success')", (eid,),
    ):
        positive_hids.add((r["host_id"], r["port"], r["proto"]))
    hid_by_ip_lookup = {r["ip"]: r["id"] for r in conn.execute(
        "SELECT id, ip FROM host WHERE engagement_id=?", (eid,))}
    def _priority(entry):
        _sid, ip, port, proto = entry
        hid = hid_by_ip_lookup.get(ip)
        return (0 if (hid, port, proto) in positive_hids else 1, ip, port)
    scored.sort(key=_priority)

    # Cap columns to keep the matrix readable on a large estate.
    col_cap = 40
    truncated = len(scored) > col_cap
    scored = scored[:col_cap]

    # Fetch every credential_access row keyed by (cred, service).
    access = {}
    for r in conn.execute(
        "SELECT credential_id, host_id, port, proto, result "
        "FROM credential_access WHERE engagement_id=?", (eid,),
    ):
        # Match a service by (host.ip, port, proto) via a small join.
        access[(r["credential_id"], r["host_id"], r["port"], r["proto"])] = r["result"]
    # We need host_id per service for the lookup — one bulk query.
    hid_by_ip = {r["ip"]: r["id"] for r in conn.execute(
        "SELECT id, ip FROM host WHERE engagement_id=?", (eid,))}

    def cell(cred_id, ip, port, proto):
        result = access.get((cred_id, hid_by_ip.get(ip), port, proto))
        if result == "admin":
            return "<td class='mx admin' title='admin'>◉</td>"
        if result == "success":
            return "<td class='mx ok' title='success'>✓</td>"
        if result == "fail":
            return "<td class='mx bad' title='logon_failure'>✗</td>"
        return "<td class='mx none' title='untried'>·</td>"

    # Header: two-line column labels (proto over ip:port).
    hdr = "<tr><th></th>"
    for _sid, ip, port, proto in scored:
        hdr += (
            f"<th class='mxh' title='{_esc(ip)}:{port}/{proto}'>"
            f"<div>{proto}</div><div class='mono'>{_esc(ip)}:{port}</div></th>"
        )
    hdr += "</tr>"

    body = ""
    for c in creds:
        cid = int(c["id"])
        row_cells = "".join(
            cell(cid, ip, port, proto) for _sid, ip, port, proto in scored
        )
        body += (
            f"<tr><th class='mxr'><b>{_esc(c['identifier'])}</b>"
            f"<span class='mono'>{_esc(c['kind'])}</span></th>{row_cells}</tr>"
        )

    trunc_note = (
        f"<div class='matrix-note'>showing first {col_cap} services "
        f"(of {len(services)} total). Filter with yhwach_spray.</div>"
        if truncated else ""
    )
    legend = (
        "<div class='matrix-legend'>"
        "<span class='mx admin'>◉</span> admin "
        "<span class='mx ok'>✓</span> success "
        "<span class='mx bad'>✗</span> fail "
        "<span class='mx none'>·</span> untried"
        "</div>"
    )
    return (
        "<h2 class='sec'>Credential × Service matrix</h2>"
        f"<div class='card' style='padding:.6rem;overflow-x:auto'>"
        f"{legend}<table class='matrix'><thead>{hdr}</thead>"
        f"<tbody>{body}</tbody></table>{trunc_note}</div>"
    )


def _spray_feed(conn, eid: int) -> str:
    """Live tail of the sprayer's writes to credential_access.

    Rank order: newest first, admins bubbled up so a fresh win is the
    top-of-panel signal. The recorded_at column carries "when the sprayer
    proved it", so the operator's brief-history matches wall clock.
    """
    rows = conn.execute(
        "SELECT ca.checked_at ts, ca.result, ca.port, ca.proto, "
        "c.identifier user, h.ip "
        "FROM credential_access ca "
        "JOIN credential c ON c.id=ca.credential_id "
        "JOIN host h ON h.id=ca.host_id "
        "WHERE ca.engagement_id=? "
        "ORDER BY (ca.result='admin') DESC, (ca.result='success') DESC, "
        "ca.checked_at DESC LIMIT 12",
        (eid,),
    ).fetchall()
    if not rows:
        return ""
    items = ""
    for r in rows:
        result = r["result"]
        if result == "admin":
            badge = "<span class='sp admin'>ADMIN</span>"
        elif result == "success":
            badge = "<span class='sp ok'>OK</span>"
        else:
            badge = "<span class='sp bad'>FAIL</span>"
        tgt = f"{_esc(r['ip'])}:{r['port']}/{_esc(r['proto'] or '?')}"
        items += (
            f"<li>{badge}<span class='mono'>{_esc(r['user'])}</span>"
            f"<span class='arrow'>→</span>"
            f"<span class='mono'>{tgt}</span>"
            f"<span class='t'>{_esc(r['ts'])}</span></li>"
        )
    return (
        "<h2 class='sec'>Spray activity</h2>"
        f"<div class='card' style='padding:.3rem .9rem'>"
        f"<ul class='sprayfeed'>{items}</ul></div>"
    )


_MD_ESCAPED = re.compile(r"\\([|`*\\])")


def _md_unescape(s: str) -> str:
    r"""Turn a composer's `\|` back into a literal `|`, after structure is parsed."""
    return _MD_ESCAPED.sub(r"\1", s)


def _md_split_cells(row: str) -> list[str]:
    r"""Split a pipe-table row on UNESCAPED pipes only.

    A `\|` inside a cell is data — a finding's evidence containing a pipe used to
    add a column and shift every value in the row one place right.
    """
    cells, cur, i = [], [], 0
    while i < len(row):
        c = row[i]
        if c == "\\" and i + 1 < len(row):
            cur.append(row[i:i + 2])
            i += 2
            continue
        if c == "|":
            cells.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    cells.append("".join(cur))
    return cells


def _md_inline(escaped: str) -> str:
    """`code` and **bold** spans inside an ALREADY-escaped line.

    Only those two: the input is generated text that embeds host-controlled
    strings, and anything richer is another way to smuggle markup. A span
    delimiter the composer escaped (`\\*`, `` \\` ``) is data and is skipped, then
    unescaped on the way out.
    """
    def _spans(text: str, delim: str, open_tag: str, close_tag: str) -> str:
        # split on unescaped delimiters only
        parts, cur, i = [], [], 0
        while i < len(text):
            if text[i] == "\\" and i + 1 < len(text):
                cur.append(text[i:i + 2])
                i += 2
                continue
            if text.startswith(delim, i):
                parts.append("".join(cur))
                cur = []
                i += len(delim)
                continue
            cur.append(text[i])
            i += 1
        parts.append("".join(cur))
        if len(parts) < 3:
            return text
        return "".join(f"{open_tag}{c}{close_tag}" if i % 2 else c
                       for i, c in enumerate(parts))

    # bold first: ** would otherwise be eaten as two empty code spans
    out = _spans(escaped, "**", "<b>", "</b>")
    out = _spans(out, "`", "<code class='mono'>", "</code>")
    return _md_unescape(out)


def _md_to_html(md: str) -> str:
    r"""Light, safe Markdown -> HTML for the report view.

    Two separate protections, because they stop different attacks:

    * **Escape-first**, always — every branch runs `_esc` before it builds markup,
      so a hostile banner cannot inject a tag.
    * **Structure** — the composer (`dossier.md`, `report.py`) neutralises markdown
      metacharacters in every interpolated DB value, and this renderer honours
      that escaping. Without it a newline in a scanned product string injects new
      *lines* of markdown, and a target can forge a whole "## Objectives captured"
      section with a pipe table into the operator's write-up. That output is
      perfectly escaped HTML which simply says something untrue, so escaping alone
      does not catch it.

    A pipe line only opens a table once a `|---|` separator row has been seen, so
    one stray `|a|b|` line in prose cannot start one.

    Handles h1/h2/h3, bullets at two indents, inline code, bold, pipe tables and
    rules.
    """
    out: list[str] = []
    pending: list[list[str]] = []   # pipe rows not yet proven to be a table
    table: list[list[str]] = []     # rows of a table whose separator we have seen

    def _emit_table() -> None:
        if table:
            head = "".join(f"<th>{_md_inline(c)}</th>" for c in table[0])
            body = "".join(
                "<tr>" + "".join(f"<td>{_md_inline(c)}</td>" for c in r) + "</tr>"
                for r in table[1:]
            )
            out.append(f"<table class='r-t'><thead><tr>{head}</tr></thead>"
                       f"<tbody>{body}</tbody></table>")
        table.clear()

    def _flush() -> None:
        _emit_table()
        for row in pending:                    # never a table: render as prose
            out.append(f"<div>{_md_inline('|' + '|'.join(row) + '|')}</div>")
        pending.clear()

    for raw in md.splitlines():
        line = _esc(raw)
        stripped = raw.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in _md_split_cells(_esc(stripped).strip("|"))]
            if all(set(_md_unescape(c).strip()) <= set("-: ") and c.strip() for c in cells):
                table.extend(pending)          # the rows above were the header
                pending.clear()
                continue                       # the separator itself is not a row
            (table if table else pending).append(cells)
            continue
        _flush()
        if raw.startswith("### "):
            out.append(f"<div class='r-h3'>{_md_inline(line[4:])}</div>")
        elif raw.startswith("## "):
            out.append(f"<div class='r-h2'>{_md_inline(line[3:])}</div>")
        elif raw.startswith("# "):
            out.append(f"<div class='r-h1'>{_md_inline(line[2:])}</div>")
        elif stripped.startswith("- "):
            indent = len(raw) - len(raw.lstrip())
            pad = " style='padding-left:1.1rem'" if indent >= 2 else ""
            out.append(f"<div class='r-li'{pad}>• {_md_inline(_esc(stripped[2:]))}</div>")
        elif set(stripped) == {"-"} and len(stripped) >= 3:
            out.append("<hr style='border:0;border-top:1px solid var(--line);margin:.6rem 0'>")
        elif stripped == "":
            out.append("<div style='height:.5rem'></div>")
        else:
            out.append(f"<div>{_md_inline(line)}</div>")
    _flush()
    return "".join(out)


# ─── /recon — "where have I not looked yet?" ───────────────────────────────
# An inventory tab, not a worklist: every panel states a fact about what has
# actually been done. Nothing here ranks hosts or suggests a move; the matrix
# sorts by how FEW of the three scans exist, which is a count, not a priority.
# See docs/design-ui-information-surface.md §4.2.

_MATRIX_COLS = [
    ("-p-", "full TCP range recorded"),
    ("-sV", "a version scan recorded"),
    ("UDP", "any UDP coverage row"),
    ("services", "rows in service"),
    ("surfaces", "rows in surface — recorded, not the same as probed"),
    ("web app", "rows in web_app"),
    ("web paths", "rows in web_path across this host's apps"),
    ("shares", "rows in share"),
    ("principals", "principals anchored to this host or its domain"),
    ("cred tries", "credential_access: proven / attempted"),
]


def _mk(ok: bool) -> str:
    cls, glyph = ("y", "✔") if ok else ("n", "✘")
    return f"<span class='mk {cls}'>{glyph}</span>"


def _mkn(n) -> str:
    n = int(n or 0)
    return f"<span class='mk {'y' if n else 'n'}'>{n}</span>"


def _recon_segments(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT 'tunnel' origin, t.subnet cidr, COALESCE(t.kind,'') detail, "
        "       COALESCE(h.ip,'') via_ip, t.created_at learned_at "
        "  FROM tunnel t LEFT JOIN host h ON h.id=t.via_host_id WHERE t.engagement_id=? "
        "UNION ALL "
        "SELECT 'interface', i.segment, COALESCE(i.source,''), h2.ip, i.discovered_at "
        "  FROM host_interface i JOIN host h2 ON h2.id=i.host_id "
        " WHERE h2.engagement_id=? AND COALESCE(i.segment,'') <> '' "
        " ORDER BY learned_at DESC, cidr",
        (eid, eid),
    ).fetchall()
    body = []
    for r in rows:
        cidr = r["cidr"] or ""
        # Numeric membership, and undiscovered scope placeholders excluded:
        # `engage` materialises every IP in scope, so a string-truncated LIKE
        # reported an untouched /24 as 254 hosts "known inside".
        inside, _owned = yhdb.hosts_in_subnet(conn, eid, cidr)
        via = _hlink(r["via_ip"]) if r["via_ip"] else "<span class='muted'>-</span>"
        body.append([
            f"<code class='mono'>{_esc(cidr)}</code>", _esc(r["origin"]), _esc(r["detail"]),
            via, _mkn(inside),
            f"<span class='muted mono'>{_esc((r['learned_at'] or '')[:19])}</span>",
        ])
    return _panel(
        "Segments learned in-engagement",
        _rows_table(["cidr", "learned via", "detail", "via host", "hosts known inside", "when"],
                    body,
                    empty="no segment beyond the written scope — no tunnel and no host "
                          "interface has named a subnet yet"),
        note="Address space the engagement discovered after scope was written. A subnet with 0 "
             "hosts known inside is reachable and completely unenumerated. "
             "<code class='mono'>host_interface</code> is only written by "
             "<code class='mono'>yhwach interface</code>, so an unrecorded dual-homed host does "
             "not appear here.")


def _recon_names(conn, eid: int) -> str:
    """Names the scan revealed beyond the PTR — vhosts and TLS cert SANs.

    Each one is a distinct web surface that will not answer on the bare IP, and
    none of it was recorded at all until the nmap parser started reading
    ssl-cert output.
    """
    rows = conn.execute(
        "SELECT d.name, COALESCE(d.type,'') type, COALESCE(d.ip,'') ip, "
        "COALESCE(h.ip,'') host_ip, COALESCE(d.source,'') source "
        "FROM domain d LEFT JOIN host h ON h.id=d.host_id "
        "WHERE d.engagement_id=? ORDER BY d.name", (eid,),
    ).fetchall()
    body = [[
        f"<code class='mono'>{_esc(r['name'])}</code>", _esc(r["type"]),
        _hlink(r["host_ip"] or r["ip"]) if (r["host_ip"] or r["ip"])
        else "<span class='muted'>—</span>",
        f"<span class='muted' style='font-size:.72rem'>{_esc(r['source'])}</span>",
    ] for r in rows[:_BOARD_ROW_CAP]]
    return _panel(
        "Names — vhosts and certificate subjects",
        _rows_table(["name", "type", "on host", "source"], body,
                    empty="no name beyond the PTR recorded — ingest an nmap scan run with "
                          "-sC, which carries the TLS certificate names"),
        note=_more_note(len(rows), min(len(rows), _BOARD_ROW_CAP), "")
             or "Each name is a web surface that may not answer on the bare IP.")


def _recon_provenance(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT COALESCE(NULLIF(TRIM(COALESCE(discovery_source,'')),''),'(unrecorded)') src, "
        "COUNT(*) n FROM host WHERE engagement_id=? GROUP BY src ORDER BY n DESC, src",
        (eid,),
    ).fetchall()
    body = [[f"<code class='mono'>{_esc(r['src'])}</code>", _mkn(r["n"])] for r in rows]
    return _panel(
        "Discovery provenance — how each host entered the model",
        _rows_table(["source", "hosts"], body, empty="no hosts in this engagement yet"),
        note="Which intake paths are feeding the world model, and which are silent. Hosts "
             "materialised from the scope before a discovery hook ran carry no source and count "
             "as <code class='mono'>(unrecorded)</code>.")


def _recon_body(conn, eid: int) -> str:
    return "\n".join((
        _recon_segments(conn, eid),
        _recon_names(conn, eid),
        _recon_provenance(conn, eid),
    ))


# ─── board strips ──────────────────────────────────────────────────────────
# The board used to render _network_map and the three vault panels in full —
# each of which is also the entire body of /map and /vault. These strips keep
# the headline numbers on the board and send the operator to the tab that owns
# the detail. See docs/design-ui-information-surface.md §4.1.


def _topology_strip(conn, eid: int) -> str:
    subnets: dict[str, dict[str, int]] = {}
    for r in conn.execute(
        "SELECT ip, stage FROM host WHERE engagement_id=? ORDER BY ip", (eid,)
    ):
        net = _subnet_of(r["ip"])
        b = subnets.setdefault(net, {"n": 0, "owned": 0, "undisc": 0})
        b["n"] += 1
        if r["stage"] in _OWNED:
            b["owned"] += 1
        if r["stage"] == "undiscovered":
            b["undisc"] += 1
    tunnels = yhdb.list_tunnels(conn, eid)
    if not subnets:
        return ""

    chips = "".join(
        f"<span class='chip' style='color:var(--ink2);background:var(--surface2);margin:1px 3px'>"
        f"<code class='mono'>{_esc(net)}</code> {b['owned']}/{b['n']} owned"
        + (f" · {b['undisc']} undiscovered" if b["undisc"] else "")
        + "</span>"
        for net, b in sorted(subnets.items())
    )
    tun = ""
    if tunnels:
        tun = " · " + ", ".join(
            f"<code class='mono'>{_esc(t['subnet'])}</code> via {_hlink(t['via_ip'])}"
            for t in tunnels[:4]
        )
    total = sum(b["n"] for b in subnets.values())
    owned = sum(b["owned"] for b in subnets.values())
    inner = (
        f"<div style='padding:.7rem .9rem;font-size:.82rem'>"
        f"<b>{owned}</b> of <b>{total}</b> host(s) owned across {len(subnets)} subnet(s)"
        f"{tun}<div style='margin-top:.45rem'>{chips}</div>"
        f"<div style='margin-top:.5rem'><a class='dl' href='/map'>the full map →</a> "
        f"<a class='dl' href='/recon'>enumeration matrix →</a></div></div>"
    )
    return _panel("Topology", inner)


def _vault_strip(conn, eid: int, *, reveal: bool = True) -> str:
    n_cred = _scalar(conn, "SELECT COUNT(*) FROM credential WHERE engagement_id=?", (eid,))
    if not n_cred:
        return ""
    n_proven = _scalar(
        conn, "SELECT COUNT(DISTINCT credential_id) FROM credential_access "
        "WHERE engagement_id=? AND result IN ('success','admin')", (eid,))
    n_admin = _scalar(
        conn, "SELECT COUNT(DISTINCT credential_id) FROM credential_access "
        "WHERE engagement_id=? AND result='admin'", (eid,))
    n_failed = _scalar(
        conn, "SELECT COUNT(*) FROM credential_access WHERE engagement_id=? AND result='fail'",
        (eid,))
    kinds = conn.execute(
        "SELECT kind, COUNT(*) n FROM credential WHERE engagement_id=? GROUP BY kind "
        "ORDER BY n DESC", (eid,)).fetchall()
    kchips = "".join(
        f"<span class='chip' style='color:var(--ink2);background:var(--surface2);margin:1px 3px'>"
        f"{_esc(r['kind'])} {r['n']}</span>" for r in kinds)
    adm = f" · <b>{n_admin}</b> admin" if n_admin else ""
    fail = f" · {n_failed} proven failure(s)" if n_failed else ""
    inner = (
        f"<div style='padding:.7rem .9rem;font-size:.82rem'>"
        f"<b>{n_cred}</b> credential(s) held, <b>{n_proven}</b> proven somewhere{adm}{fail}"
        f"<div style='margin-top:.45rem'>{kchips}</div>"
        f"<div style='margin-top:.5rem'><a class='dl' href='/vault'>the vault, the "
        f"credential×service matrix and the spray feed →</a></div></div>"
    )
    return _panel("Credentials", inner)


# ─── /surfaces — "what is running, and what is known about it?" ────────────
# surface.meta_json is the richest column in the schema and had zero production
# readers: every probe writes what it learned there (model lists, MCP tool names,
# OpenAPI paths, versions, page titles) and nothing ever rendered it.
# See docs/design-ui-information-surface.md §4.3.

# Keys the probes actually write, in the order an operator wants them. Anything
# not listed still renders, verbatim and last, so a new probe needs no UI change.
_META_ORDER = ("engine", "product", "version", "scheme", "endpoint", "title",
               "models", "tools", "tool_detail", "skills", "capabilities", "collections",
               "name", "description", "paths", "http_status")


def _decode_meta(raw: str | None) -> list[tuple[str, str]]:
    """surface.meta_json -> ordered (key, display) pairs.

    The JSON is written from probe responses, i.e. it is attacker-influenced:
    anything could be in a key or a value. Callers escape both.
    """
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return [("(unparseable)", str(raw)[:120])]
    if not isinstance(data, dict):
        return [("value", str(data)[:200])]

    def _one(x) -> str:
        # An MCP tool_detail entry is the richest thing a probe records: name,
        # what the tool claims to do, and the parameters it takes.
        if isinstance(x, dict) and "name" in x:
            bits = [str(x["name"])]
            if x.get("params"):
                bits.append("(" + ", ".join(str(p) for p in x["params"]) + ")")
            if x.get("description"):
                bits.append("— " + str(x["description"]))
            return " ".join(bits)
        if isinstance(x, dict):
            return json.dumps(x)[:200]
        return str(x)

    def _fmt(v) -> str:
        if isinstance(v, list):
            items = [_one(x) for x in v[:12]]
            more = f" (+{len(v) - 12})" if len(v) > 12 else ""
            return " · ".join(items) + more
        if isinstance(v, dict):
            return json.dumps(v)[:200]
        return str(v)

    known = [(k, _fmt(data[k])) for k in _META_ORDER if k in data]
    rest = [(k, _fmt(v)) for k, v in data.items() if k not in _META_ORDER]
    return known + rest


def _meta_cell(raw: str | None) -> str:
    pairs = _decode_meta(raw)
    if not pairs:
        return "<span class='muted'>— nothing recorded</span>"
    return "<dl class='kv'>" + "".join(
        f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>" for k, v in pairs) + "</dl>"


def _surface_rows(conn, eid: int, *, ai_only: bool | None = None):
    rows = conn.execute(
        "SELECT u.id sid, h.ip, COALESCE(h.hostname,'') hostname, h.stage, "
        "COALESCE(s.port,0) port, COALESCE(s.proto,'tcp') proto, "
        "COALESCE(s.product,'') product, COALESCE(s.version,'') version, "
        "COALESCE(s.cpe,'') cpe, COALESCE(s.banner,'') banner, "
        "u.kind, COALESCE(u.auth,'unknown') auth, u.meta_json, u.discovered_at "
        "FROM surface u JOIN host h ON h.id=u.host_id "
        "LEFT JOIN service s ON s.id=u.service_id "
        "WHERE h.engagement_id=? ORDER BY h.ip, s.port, u.kind",
        (eid,),
    ).fetchall()
    if ai_only is None:
        return rows
    return [r for r in rows if (r["kind"] in AI_KINDS) == ai_only]


def _surfaces_ai_band(conn, eid: int) -> str:
    rows = _surface_rows(conn, eid, ai_only=True)
    body = [[
        f"{_hlink(r['ip'])}<div class='sub2'>{_esc(r['hostname'])}</div>",
        _stage_badge(r["stage"]),
        f"<code class='mono'>{_esc(r['port'])}/{_esc(r['proto'])}</code>",
        f"<span class='chip' style='color:#e83bb0;background:#e83bb022'>{_esc(r['kind'])}</span>",
        _esc(r["auth"]),
        _esc(r["product"]) or "<span class='muted'>—</span>",
        _meta_cell(r["meta_json"]),
    ] for r in rows]
    return _panel(
        "AI surfaces — every probe hit, decoded",
        _rows_table(["host", "stage", "port", "kind", "auth", "product",
                     "what the probe recorded"], body,
                    empty="no AI surface detected yet — `yhwach probe` fingerprints them"),
        note="Decoded from <code class='mono'>surface.meta_json</code>, which nothing rendered "
             "before. Unknown keys appear verbatim, so a new probe needs no UI change. The MCP, "
             "A2A and Qdrant probes currently fetch tool descriptions, agent skills and "
             "collection names and then drop them before this column — see "
             "<code class='mono'>docs/design-ui-information-surface.md</code> §7.3.")


def _surfaces_asset_rollup(conn, eid: int) -> str:
    """Every distinct thing the probes named anywhere in the estate."""
    assets: dict[tuple[str, str], list[str]] = {}
    for r in _surface_rows(conn, eid):
        where = f"{r['ip']}:{r['port']}"
        try:
            data = json.loads(r["meta_json"] or "{}")
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        for cls, key in (("model", "models"), ("tool", "tools"), ("api path", "paths")):
            for v in (data.get(key) or []):
                assets.setdefault((cls, str(v)), []).append(where)
        for cls, key in (("endpoint", "endpoint"), ("engine", "engine")):
            if data.get(key):
                assets.setdefault((cls, str(data[key])), []).append(where)
    body = [[
        f"<span class='chip' style='color:#c05bd8;background:#c05bd822'>{_esc(cls)}</span>",
        f"<code class='mono'>{_esc(name)}</code>",
        ", ".join(f"<code class='mono'>{_esc(w)}</code>" for w in sorted(set(where))[:6]),
        _mkn(len(set(where))),
    ] for (cls, name), where in sorted(assets.items())]
    return _panel(
        "Estate asset rollup — every model, tool, endpoint and API path",
        _rows_table(["class", "asset", "seen on", "surfaces"], body[:_BOARD_ROW_CAP],
                    empty="nothing named yet — no probe has recorded a model, tool or "
                          "endpoint"),
        note=_more_note(len(body), min(len(body), _BOARD_ROW_CAP), "see the per-surface rows below")
             or "One row per distinct thing the probes named, with where it was seen.")


def _surfaces_service_inventory(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT h.ip, COALESCE(h.hostname,'') hostname, h.stage, s.port, "
        "COALESCE(s.proto,'tcp') proto, COALESCE(s.product,'') product, "
        "COALESCE(s.version,'') version, COALESCE(s.cpe,'') cpe, COALESCE(s.banner,'') banner, "
        # The version may live on `software` rather than `service`: nmap writes
        # both, but a probe that recovers a version writes only software. Saying
        # "product only" while the model holds the version would misinform.
        "(SELECT sw.version FROM software sw WHERE sw.service_id=s.id "
        "   AND COALESCE(sw.version,'') <> '' LIMIT 1) sw_version, "
        "(SELECT sw2.version FROM software sw2 WHERE sw2.host_id=s.host_id "
        "   AND LOWER(sw2.name)=LOWER(COALESCE(s.product,'')) "
        "   AND COALESCE(sw2.version,'') <> '' LIMIT 1) sw_version_byname, "
        "(SELECT GROUP_CONCAT(DISTINCT u.kind) FROM surface u WHERE u.service_id=s.id) kinds, "
        "(SELECT COALESCE(u2.auth,'') FROM surface u2 WHERE u2.service_id=s.id LIMIT 1) auth "
        "FROM service s JOIN host h ON h.id=s.host_id "
        "WHERE h.engagement_id=? ORDER BY h.ip, s.port",
        (eid,),
    ).fetchall()
    body = []
    for r in rows[:_BOARD_ROW_CAP]:
        version = r["version"] or r["sw_version"] or r["sw_version_byname"] or ""
        via_sw = not r["version"] and version
        if version:
            recovered = "<span class='mk y'>version</span>"
            if via_sw:
                recovered += " <span class='muted' style='font-size:.66rem'>via software</span>"
        elif r["product"]:
            recovered = "<span class='mk p'>product only</span>"
        else:
            recovered = "<span class='mk n'>bare port</span>"
        kinds = (r["kinds"] or "").replace(",", ", ")
        star = " <span class='star'>★AI</span>" if any(
            k in AI_KINDS for k in (r["kinds"] or "").split(",") if k) else ""
        body.append([
            _hlink(r["ip"]), f"<code class='mono'>{_esc(r['port'])}/{_esc(r['proto'])}</code>",
            _esc(r["product"]) or "<span class='muted'>—</span>",
            _esc(version) or "<span class='muted'>—</span>",
            recovered,
            (f"{_esc(kinds)}{star}" if kinds else "<span class='muted'>not classified</span>"),
            _esc(r["auth"]) or "<span class='muted'>—</span>",
            (f"<code class='mono'>{_esc(r['cpe'])}</code>" if r["cpe"]
             else "<span class='muted'>—</span>"),
        ])
    return _panel(
        "Service inventory — what is listening, and how much is known about it",
        _rows_table(["host", "port", "product", "version", "version recovery", "surface kinds",
                     "auth", "cpe"], body,
                    empty="no service recorded yet — ingest an nmap scan"),
        note=_more_note(len(rows), min(len(rows), _BOARD_ROW_CAP),
                        "see `yhwach brief` for the full list")
             or "<b>version recovery</b> says how far fingerprinting got: a bare port cannot be "
                "matched against the CVE map at all.")


def _surfaces_body(conn, eid: int, *, reveal: bool = True) -> str:
    return "\n".join((
        _surfaces_ai_band(conn, eid),
        _surfaces_asset_rollup(conn, eid),
        _surfaces_service_inventory(conn, eid),
        _payload_ledger(conn, eid, reveal=reveal),
    ))


# ─── /identity — "who is here, and is it safe to spray?" ───────────────────
# The whole AD graph was invisible: principal / membership / privilege / share /
# password_policy / domain have no renderer anywhere on the board, and the
# lockout threshold — a pre-flight safety fact — was readable only by sprayer.py.
# See docs/design-ui-information-surface.md §4.4.

# principal.flags is a comma list the ingest writes; spell it out for the operator.
_FLAG_MEANING = {
    "dont_require_preauth": "AS-REP roastable",
    "adminCount": "protected (adminCount=1)",
    "unconstrained_deleg": "unconstrained delegation",
    "constrained_deleg": "constrained delegation",
    "passwd_notreqd": "password not required",
    "passwd_never_expires": "password never expires",
    "spn": "has an SPN",
    "disabled": "disabled",
    "trusted_for_deleg": "trusted for delegation",
}

# Words in a description that usually mean a secret was written into it.
# `ldap_user_descriptions` (T1552.001) is a real playbook rule; this is a hint
# for the eye, never a verdict.
_LEAK_WORDS = ("pass", "pwd", "pw:", "secret", "cred", "temp", "welcome", "default",
               "login", "key")


def _identity_spray_safety(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT p.domain, p.min_length, p.lockout_threshold, p.lockout_window_min, "
        "p.complexity, COALESCE(p.source,'') source, p.discovered_at, "
        "COALESCE(h.ip,'') host_ip "
        "FROM password_policy p LEFT JOIN host h ON h.id=p.host_id "
        "WHERE p.engagement_id=? ORDER BY p.id DESC",
        (eid,),
    ).fetchall()
    body = []
    for r in rows:
        thr = r["lockout_threshold"]
        if thr is None:
            badge = "<span class='lk unk'>UNKNOWN — guard NOT engaged</span>"
        elif int(thr) == 0:
            badge = "<span class='lk none'>NO LOCKOUT (0)</span>"
        else:
            badge = f"<span class='lk set'>LOCKOUT AT {_esc(thr)}</span>"
        body.append([
            _esc(r["domain"] or r["host_ip"] or "—"), badge,
            _esc(r["min_length"] if r["min_length"] is not None else "—"),
            _esc(r["lockout_window_min"] if r["lockout_window_min"] is not None else "—"),
            ("yes" if r["complexity"] else "no") if r["complexity"] is not None else "—",
            f"<code class='mono'>{_esc(r['source'])}</code>" if r["source"] else "—",
        ])
    if not body:
        # No row at all is the dangerous state, and it is the DEFAULT state.
        # It must never render as an absence; it renders as UNKNOWN.
        body = [["<span class='muted'>no policy observed</span>",
                 "<span class='lk unk'>UNKNOWN — guard NOT engaged</span>",
                 "—", "—", "—",
                 "<span class='muted'>run smb_password_policy</span>"]]
    return _panel(
        "Spray safety — observed password policy",
        _rows_table(["scope", "lockout", "min length", "window (min)", "complexity", "source"],
                    body, empty=""),
        note="This is a pre-flight fact: a spray against an unknown lockout policy can lock out "
             "the estate. No row at all renders as UNKNOWN, never as safe. Only "
             "<code class='mono'>sprayer.py</code> read this table before.")


def _identity_roster(conn, eid: int, *, reveal: bool = True) -> str:
    rows = conn.execute(
        "SELECT p.id, p.name, COALESCE(p.domain,'') domain, p.type, p.rid, p.enabled, "
        "COALESCE(p.flags,'') flags, COALESCE(p.spn,'') spn, "
        "COALESCE(p.description,'') description, COALESCE(p.source,'') source, "
        "(SELECT COUNT(*) FROM privilege pv WHERE pv.principal_id=p.id) n_rights, "
        "(SELECT COUNT(*) FROM credential c WHERE c.engagement_id=p.engagement_id "
        "   AND (LOWER(c.identifier)=LOWER(p.name) "
        # A vault identifier is usually DOMAIN\name; backslash is not a LIKE
        # wildcard in SQLite, so no ESCAPE clause is needed (and one here was wrong).
        "        OR LOWER(c.identifier) LIKE '%\\' || LOWER(p.name))) n_vault "
        "FROM principal p WHERE p.engagement_id=? "
        "ORDER BY (p.type='group') DESC, p.name",
        (eid,),
    ).fetchall()
    body = []
    for r in rows:
        flags = [f.strip() for f in (r["flags"] or "").split(",") if f.strip()]
        if r["spn"] and "spn" not in flags:
            flags.append("spn")
        fchips = "".join(
            f"<span class='chip' style='color:#ec835a;background:#ec835a22;margin:1px 2px'>"
            f"{_esc(_FLAG_MEANING.get(f, f))}</span>" for f in flags)
        desc = r["description"] or ""
        low = desc.lower()
        looks_leaky = bool(desc) and any(w in low for w in _LEAK_WORDS)
        if desc and not reveal:
            # The whole point of this column is that passwords are written into
            # it, so --redact must mask it — while still saying the row is worth
            # a second look.
            desc_html = ("<span class='leak'>[redacted · matched a leak keyword]</span>"
                         if looks_leaky else "<span class='mono'>[redacted]</span>")
        elif looks_leaky:
            desc_html = f"<span class='leak'>{_esc(desc)}</span>"
        else:
            desc_html = _esc(desc) or "<span class='muted'>—</span>"
        vault = ("<span class='mk y'>in vault</span>" if r["n_vault"]
                 else "<span class='muted'>—</span>")
        body.append([
            f"<b class='mono'>{_esc(r['name'])}</b>"
            + (f"<div class='sub2'>{_esc(r['domain'])}</div>" if r["domain"] else ""),
            _esc(r["type"]),
            _esc(r["rid"] if r["rid"] is not None else "—"),
            ("<span class='muted'>disabled</span>" if r["enabled"] == 0 else "yes"),
            fchips or "<span class='muted'>—</span>",
            (f"<code class='mono'>{_esc(r['spn'])}</code>" if r["spn"]
             else "<span class='muted'>—</span>"),
            desc_html,
            _mkn(r["n_rights"]),
            vault,
        ])
    return _panel(
        "Principal roster",
        _rows_table(["principal", "type", "rid", "enabled", "flags", "spn", "description",
                     "rights", "vault"], body[:_BOARD_ROW_CAP],
                    empty="no principal recorded — ingest BloodHound output, or run the "
                          "LDAP/SMB enumeration rules"),
        note=(_more_note(len(body), min(len(body), _BOARD_ROW_CAP), "see `yhwach brief`") or "")
             + " The <b>description</b> column is why this panel exists: "
               "<code class='mono'>ldap_user_descriptions</code> (T1552.001) is a real playbook "
               "rule, yhwach stores what it finds, and nothing rendered it anywhere before. "
               "Highlighting is a plain keyword hint, not a verdict.")


def _identity_privileges(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT COALESCE(p.name,'(unknown)') who, COALESCE(p.type,'') ptype, v.right, "
        "COALESCE(v.target,'') target, COALESCE(h.ip,'') host_ip, COALESCE(v.source,'') source "
        "FROM privilege v LEFT JOIN principal p ON p.id=v.principal_id "
        "LEFT JOIN host h ON h.id=v.host_id "
        "WHERE v.engagement_id=? ORDER BY (v.host_id IS NULL) DESC, p.name, v.right",
        (eid,),
    ).fetchall()
    body = [[
        f"<b class='mono'>{_esc(r['who'])}</b>",
        f"<code class='mono'>{_esc(r['right'])}</code>",
        _esc(r["target"]) or "<span class='muted'>—</span>",
        (_hlink(r["host_ip"]) if r["host_ip"]
         else "<span class='chip' style='color:#c05bd8;background:#c05bd822'>domain-wide</span>"),
        f"<span class='muted' style='font-size:.72rem'>{_esc(r['source'])}</span>",
    ] for r in rows[:_BOARD_ROW_CAP]]
    return _panel(
        "Rights held — per principal, per host",
        _rows_table(["principal", "right", "over", "where", "source"], body,
                    empty="no privilege recorded"),
        note=_more_note(len(rows), min(len(rows), _BOARD_ROW_CAP), "see `yhwach brief`")
             or "Domain-wide rights are listed first. The right string is recorded verbatim "
                "from the ingest, not normalised.")


def _identity_shares(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT h.ip, COALESCE(h.hostname,'') hostname, s.name, COALESCE(s.proto,'smb') proto, "
        "COALESCE(s.access,'') access, COALESCE(s.remark,'') remark, COALESCE(s.source,'') source "
        "FROM share s JOIN host h ON h.id=s.host_id WHERE h.engagement_id=? "
        "ORDER BY (UPPER(s.access) LIKE '%WRITE%') DESC, h.ip, s.name",
        (eid,),
    ).fetchall()
    default = {"ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON", "PRINT$"}
    body = []
    for r in rows[:_BOARD_ROW_CAP]:
        acc = (r["access"] or "").upper()
        if "WRITE" in acc:
            acc_html = f"<span class='mk y'>{_esc(r['access'])}</span>"
        elif "READ" in acc:
            acc_html = f"<span class='mk p'>{_esc(r['access'])}</span>"
        elif acc:
            acc_html = f"<span class='mk n'>{_esc(r['access'])}</span>"
        else:
            acc_html = "<span class='muted'>unknown</span>"
        is_default = r["name"].upper() in default
        body.append([
            _hlink(r["ip"]),
            (f"<span class='muted mono'>{_esc(r['name'])}</span>" if is_default
             else f"<b class='mono'>{_esc(r['name'])}</b>"),
            _esc(r["proto"]), acc_html,
            _esc(r["remark"]) or "<span class='muted'>—</span>",
            "<span class='muted'>default</span>" if is_default else "",
        ])
    return _panel(
        "Shares",
        _rows_table(["host", "share", "proto", "access", "remark", ""], body,
                    empty="no share recorded — run the SMB enumeration rules"),
        note=(_more_note(len(rows), min(len(rows), _BOARD_ROW_CAP), "see `yhwach brief`") or "")
             + " Writable first, and the built-in shares are dimmed so a non-default one stands "
               "out. <b>access reflects whoever authenticated</b> when the share was enumerated, "
               "not what every principal can reach.")


def _identity_inventory(conn, eid: int) -> str:
    """What the AD half of the world model holds, and — just as important — what
    is NOT COLLECTED, so an empty panel is never misread as a flat domain."""
    counts = {
        "domains": _scalar(conn, "SELECT COUNT(*) FROM domain WHERE engagement_id=?", (eid,)),
        "principals": _scalar(conn, "SELECT COUNT(*) FROM principal WHERE engagement_id=?", (eid,)),
        "group memberships": _scalar(
            conn, "SELECT COUNT(*) FROM membership WHERE engagement_id=?", (eid,)),
        "privileges": _scalar(conn, "SELECT COUNT(*) FROM privilege WHERE engagement_id=?", (eid,)),
        "graph edges": _scalar(conn, "SELECT COUNT(*) FROM edge WHERE engagement_id=?", (eid,)),
        "shares": _scalar(
            conn, "SELECT COUNT(*) FROM share s JOIN host h ON h.id=s.host_id "
                  "WHERE h.engagement_id=?", (eid,)),
        "password policies": _scalar(
            conn, "SELECT COUNT(*) FROM password_policy WHERE engagement_id=?", (eid,)),
    }
    # Facts no writer produces today: an empty count means NOT COLLECTED, not
    # "none exist". See docs/design-ui-information-surface.md §7.4 and §7.5.
    uncollected = {"group memberships": "no ingest path writes `membership` — "
                                        "BloodHound import skips MemberOf",
                   "domains": "`db.add_domain` has no caller; vhosts and TLS SANs "
                              "are parsed and discarded"}
    body = []
    for name, n in counts.items():
        if n:
            state = "<span class='mk y'>PRESENT</span>"
            why = ""
        elif name in uncollected:
            state = "<span class='mk p'>NOT COLLECTED</span>"
            why = uncollected[name]
        else:
            state = "<span class='mk n'>ABSENT</span>"
            why = "nothing recorded yet"
        body.append([_esc(name), state, f"<span class='mono'>{n}</span>",
                     f"<span class='muted' style='font-size:.74rem'>{why}</span>"])
    return _panel(
        "AD world model — what is here, and what is not collected",
        _rows_table(["fact class", "state", "rows", "note"], body, empty=""),
        note="A zero is only ABSENT when something would have written it. Where no writer "
             "exists the row says NOT COLLECTED — an empty Groups panel must never be read "
             "as “this domain is flat”.")


def _identity_body(conn, eid: int, *, reveal: bool = True) -> str:
    return "\n".join((
        _identity_spray_safety(conn, eid),
        _identity_roster(conn, eid, reveal=reveal),
        _identity_privileges(conn, eid),
        _identity_shares(conn, eid),
        _identity_inventory(conn, eid),
    ))


# ─── /report — "what do I paste in, and what lacks evidence?" ──────────────


def _report_phase(conn, eid: int) -> str:
    """The real stage histogram. /report called phase_report with no phase kwarg,
    so its header always read "after enumeration" whatever the estate looked like."""
    rows = conn.execute(
        "SELECT stage, COUNT(*) n FROM host WHERE engagement_id=? GROUP BY stage", (eid,)
    ).fetchall()
    counts = {r["stage"]: r["n"] for r in rows}
    for stage in ("pivoted", "looted", "foothold", "enumerated", "scanned"):
        if counts.get(stage):
            return stage
    return "scanned"


def _report_gaps(conn, eid: int) -> str:
    """An inventory of what the write-up cannot yet support. Facts, not a to-do
    list: each row is something that exists in the model without its evidence."""
    blocks = []

    no_ev = conn.execute(
        "SELECT f.severity, f.title, COALESCE(h.ip,'-') ip FROM finding f "
        "LEFT JOIN host h ON h.id=f.host_id "
        "WHERE f.engagement_id=? AND f.status IN ('open','confirmed','exploited') AND COALESCE(TRIM(f.evidence),'')='' "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, f.id",
        (eid,),
    ).fetchall()
    n_find = _scalar(
        conn, "SELECT COUNT(*) FROM finding WHERE engagement_id=? AND status IN ('open','confirmed','exploited')", (eid,))
    blocks.append((
        "Findings with no evidence line",
        f"{len(no_ev)} of {n_find} open finding(s)",
        [[_hlink(r["ip"]), f"<span class='chip' style='color:{_SEV.get(r['severity'], '#7f8792')};"
          f"background:{_SEV.get(r['severity'], '#7f8792')}22'>{_esc(r['severity'])}</span>",
          _esc(r["title"])] for r in no_ev[:_BOARD_ROW_CAP]],
        ["host", "sev", "title"],
    ))

    from yhwach import poc

    with_steps = dict(poc.list_objectives(conn, eid))
    objs = conn.execute(
        "SELECT o.label, o.captured, o.points, COALESCE(h.ip,'') ip FROM objective o "
        "LEFT JOIN host h ON h.id=o.host_id WHERE o.engagement_id=? AND o.captured=1 "
        "ORDER BY o.points DESC, o.label",
        (eid,),
    ).fetchall()
    unproved = [o for o in objs if not with_steps.get(o["label"], 0)]
    blocks.append((
        "Captured objectives with no reproducible chain",
        f"{len(unproved)} of {len(objs)} capture(s)",
        [[_esc(o["label"]), _hlink(o["ip"]) if o["ip"] else "<span class='muted'>—</span>",
          f"{o['points']}pts" if o["points"] else "—"] for o in unproved[:_BOARD_ROW_CAP]],
        ["objective", "host", "points"],
    ))

    loot = conn.execute(
        "SELECT COALESCE(h.ip,'') ip, COALESCE(l.path,'') path, COALESCE(l.type,'') type "
        "FROM loot l LEFT JOIN host h ON h.id=l.host_id "
        "WHERE l.engagement_id=? AND COALESCE(TRIM(l.local_path),'')='' ORDER BY l.id",
        (eid,),
    ).fetchall()
    n_loot = _scalar(conn, "SELECT COUNT(*) FROM loot WHERE engagement_id=?", (eid,))
    blocks.append((
        "Loot recorded but not saved locally",
        f"{len(loot)} of {n_loot} loot row(s)",
        [[_hlink(r["ip"]) if r["ip"] else "<span class='muted'>—</span>",
          f"<code class='mono'>{_esc(r['path'])}</code>", _esc(r["type"])]
         for r in loot[:_BOARD_ROW_CAP]],
        ["host", "remote path", "type"],
    ))

    inner = ""
    for title, count, rows, headers in blocks:
        tone = "mk n" if rows else "mk y"
        inner += (
            f"<div style='padding:.6rem .9rem;border-bottom:1px solid var(--line)'>"
            f"<b>{_esc(title)}</b> <span class='{tone}'>{_esc(count)}</span></div>"
        )
        if rows:
            inner += _rows_table(headers, rows, empty="")
    return _panel(
        "Evidence — what the write-up cannot support yet", inner,
        note="An inventory, not a task list: each row is something the model holds without the "
             "evidence a write-up needs. A zero here is a real all-clear for that class.")


_VERDICT_COL = {"signal": "#6bb36b", "refused": "#d9a441", "silent": "#7f8792",
                "not_delivered": "#e06767"}


def _payload_ledger(conn, eid: int, *, reveal: bool = True) -> str:
    """What was delivered to an AI surface, what came back, and whether a
    guardrail refused it.

    The payload used to survive only in the dry-run stub — recorded when it was
    NOT sent — and a refusal produced no row anywhere, because `_REFUSAL_RE` was
    used solely to suppress a finding. For an operator deciding whether to
    escalate direct -> indirect -> encoded, both are the reusable facts.
    """
    rows = conn.execute(
        "SELECT ts, payload_json FROM event WHERE engagement_id=? AND kind='craft_executed' "
        "ORDER BY id DESC LIMIT 40", (eid,),
    ).fetchall()
    body = []
    for r in rows:
        try:
            p = json.loads(r["payload_json"] or "{}")
        except (ValueError, TypeError):
            continue
        if not p.get("payload"):
            continue
        verdict = p.get("verdict") or "—"
        col = _VERDICT_COL.get(verdict, "#7f8792")
        resp = (p.get("response") or "").strip()
        body.append([
            f"<span class='muted mono' style='font-size:.68rem'>{_esc(str(r['ts'])[:19])}</span>",
            _hlink(p.get("host")),
            f"<code class='mono'>{_esc(p.get('technique') or '')}</code>",
            f"<span class='chip' style='color:{col};background:{col}22'>{_esc(verdict)}</span>",
            # A payload can carry a credential and a response can carry the
            # secret it exfiltrated, so --redact masks both. The columns that
            # make the panel useful — when, host, technique, verdict — survive.
            (f"<pre class='report' style='margin:0;padding:.4rem .6rem;max-height:7rem;"
             f"overflow:auto'>{_esc(p['payload'])}</pre>" if reveal
             else f"<span class='mono'>[redacted · {len(p['payload'])} chars]</span>"),
            ("<span class='muted'>no response recorded</span>" if not resp
             else (f"<pre class='report' style='margin:0;padding:.4rem .6rem;max-height:7rem;"
                   f"overflow:auto'>{_esc(resp)}</pre>" if reveal
                   else f"<span class='mono'>[redacted · {len(resp)} chars]</span>")),
        ])
    return _panel(
        "Payloads delivered \u2014 what was sent, and what answered",
        _rows_table(["when", "host", "technique", "verdict", "payload", "response"], body,
                    empty="no payload delivered yet \u2014 this fills as craft actions run"),
        note="<b>signal</b> the response carried a finding \u00b7 <b>refused</b> a guardrail "
             "rejected the phrasing \u00b7 <b>silent</b> delivered, nothing came back. A refusal "
             "is a fact worth as much as a hit: it is what says to escalate direct \u2192 "
             "indirect \u2192 encoded.")


def _segment_inventory(conn, eid: int) -> str:
    """Per /24: how far into it the engagement has actually got."""
    rows = conn.execute(
        "SELECT ip, stage, COALESCE(scan_needed,0) scan_needed FROM host "
        "WHERE engagement_id=? ORDER BY ip", (eid,),
    ).fetchall()
    tunnelled = {r["subnet"] for r in conn.execute(
        "SELECT subnet FROM tunnel WHERE engagement_id=?", (eid,))}
    segs: dict[str, dict] = {}
    for r in rows:
        net = _subnet_of(r["ip"])
        b = segs.setdefault(net, {"n": 0, "undisc": 0, "owned": 0, "pending": 0, "ports": 0})
        b["n"] += 1
        if r["stage"] == "undiscovered":
            b["undisc"] += 1
        if r["stage"] in _OWNED:
            b["owned"] += 1
        if r["scan_needed"]:
            b["pending"] += 1
    # One grouped pass instead of a _scalar per segment, and keyed on the host's
    # own subnet rather than a truncated LIKE — the second rsplit matched the
    # whole /16, so every /24 in it showed the same inflated port count.
    ports_by_net: dict[str, int] = {}
    for r in conn.execute(
        "SELECT h.ip, COUNT(s.id) n FROM host h LEFT JOIN service s ON s.host_id=h.id "
        "WHERE h.engagement_id=? GROUP BY h.id", (eid,),
    ):
        ports_by_net[_subnet_of(r["ip"])] = ports_by_net.get(_subnet_of(r["ip"]), 0) + r["n"]
    for net, b in segs.items():
        b["ports"] = ports_by_net.get(net, 0)
    body = [[
        f"<code class='mono'>{_esc(net)}</code>"
        + (" <span class='chip' style='color:#c05bd8;background:#c05bd822'>via tunnel</span>"
           if net in tunnelled else ""),
        _mkn(b["n"] - b["undisc"]), _mkn(b["owned"]), _mkn(b["ports"]),
        (f"<span class='mk p'>{b['pending']}</span>" if b["pending"] else "<span class='mk y'>0</span>"),
        (f"<span class='muted'>{b['undisc']}</span>" if b["undisc"] else "—"),
    ] for net, b in sorted(segs.items())]
    return _panel(
        "Segments \u2014 how far into each one",
        _rows_table(["segment", "discovered", "owned", "open ports", "pending scan",
                     "undiscovered"], body, empty="no host materialised yet"),
        note="One row per /24 the world model knows about, whether it came from scope or from a "
             "tunnel.")


def _interfaces_panel(conn, eid: int) -> str:
    rows = conn.execute(
        "SELECT h.ip host_ip, COALESCE(h.hostname,'') hostname, i.ip, "
        "COALESCE(i.segment,'') segment, COALESCE(i.mac,'') mac, i.is_primary "
        "FROM host_interface i JOIN host h ON h.id=i.host_id "
        "WHERE h.engagement_id=? ORDER BY h.ip, i.is_primary DESC, i.ip",
        (eid,),
    ).fetchall()
    body = [[
        _hlink(r["host_ip"]), f"<code class='mono'>{_esc(r['ip'])}</code>",
        f"<code class='mono'>{_esc(r['segment'])}</code>" if r["segment"] else "—",
        _esc(r["mac"]) or "—",
        "<span class='mk y'>primary</span>" if r["is_primary"] else "",
    ] for r in rows]
    return _panel(
        "Interfaces \u2014 where a host has a second home",
        _rows_table(["host", "interface", "segment", "mac", ""], body,
                    empty="no interface recorded"),
        note="Only <code class='mono'>yhwach interface</code> writes this table, so a dual-homed "
             "host nobody recorded does not appear here and its second segment stays invisible.")


def _map_body(conn, eid: int) -> str:
    return "\n".join((
        _segment_inventory(conn, eid),
        _network_map(conn, eid),
        _interfaces_panel(conn, eid),
    ))
