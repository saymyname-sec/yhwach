# UI mockups

Static renders of the eight tabs proposed in
[`docs/design-ui-information-surface.md`](../design-ui-information-surface.md), so the layouts can
be judged before any of it is built.

These are **not** part of the package and nothing imports them. They read `yhwach.ui._CSS` directly,
so a mockup always looks like the real board — the point is to judge information design, not a skin.

```bash
python docs/mockups/pages.py docs/ui-panel-spec.json $YHWACH_DATA_DIR/state/yhwach.db out/
```

Then open `out/index.html`. No server needed.

- `render.py` — shell, markup helpers, and the generic panel renderer that drives any panel
  straight from its verified query in `ui-panel-spec.json`.
- `pages.py` — the eight pages. The panels where the encoding *is* the design (the enumeration
  matrix, the decoded AI band, the lockout band, the vault access split, the principal roster)
  are hand-rendered; the rest render generically.

Two things the mockups deliberately show on top of the current board:

- the §3.4 figure/ground and type-scale patch, applied as a CSS override in `render.py` and
  clearly separated from `ui._CSS`;
- panels that are **honestly empty** against a given DB. The PoC tab renders three blanks on a
  database with no `poc_step` events — which is exactly the gap that tab exists to expose.

Every query in `ui-panel-spec.json` was executed against a seeded nine-host engagement before being
written down; `rows_in_reference_db` records what it returned there.
