#!/usr/bin/env python3
"""yhwach-vault-check.py — the done-gate for an engagement's Obsidian notes.

Run it on one lab folder before you call a flag (or the engagement) done:

    scripts/yhwach-vault-check.py ~/notes/acme

It reports the defects that silently cost points in real write-ups:

  * an image embed ( ![[x.png]] ) whose file doesn't exist
  * an embed that won't render: inside backticks / a code block, or split across lines
  * the literal  SCREENSHOT-MISSING  token left in a note
  * a chain note (chains/*.md) missing one of the 7 sections
    (Target, Vulnerability, Prerequisites, Steps, Proof, Source, Cleanup)
  * TODO / UNVERIFIED markers left in a chain note
  * a screenshot no note references, and a .txt sidecar with no image
    (the capture failed and was never redone)
  * a [[link]] to a note that doesn't exist

Exit code 1 if any chain note has a blocking problem, else 0. Standard library only.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp"}
CHAIN_SECTIONS = {
    "Target": r"target",
    "Vulnerability": r"vulnerab",
    "Prerequisites": r"prereq",
    "Steps": r"steps?\b",
    "Proof": r"proof",
    "Source & modifications": r"source|script",
    "Cleanup": r"clean",
}
EMBED = re.compile(r"!\[\[([^\]|#\n]+)(?:[#|][^\]\n]*)?\]\]")
LINK = re.compile(r"(?<!!)\[\[([^\]|#\n]+)(?:[#|][^\]\n]*)?\]\]")
SPLIT_EMBED = re.compile(r"!\[\[[^\]\n]*\n")
INLINE_CODE = re.compile(r"`[^`\n]*`")
HEADING = re.compile(r"^#{1,6}\s+(.*)$", re.M)
MISSING = "SCREENSHOT-MISSING"


def strip_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def split_code(text: str) -> tuple[str, str]:
    """Return (prose, code): text outside fenced blocks, and inside them."""
    prose, code, in_fence = [], [], False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        (code if in_fence else prose).append(line)
    return "\n".join(prose), "\n".join(code)


def main() -> int:
    ap = argparse.ArgumentParser(description="Done-gate for a lab's Obsidian notes.")
    ap.add_argument("lab_dir", type=Path, help="the lab folder inside your vault, e.g. ~/notes/acme")
    ap.add_argument("--vault", type=Path, help="vault root, to resolve links into other folders "
                                               "(default: the lab folder's parent)")
    args = ap.parse_args()
    lab = args.lab_dir.expanduser().resolve()
    if not lab.is_dir():
        print(f"not a folder: {lab}", file=sys.stderr)
        return 2
    vault = (args.vault.expanduser().resolve() if args.vault else lab.parent)

    def visible(p: Path) -> bool:
        return not any(part.startswith(".") for part in p.relative_to(vault).parts)

    # Obsidian resolves [[name]] by basename anywhere in the vault.
    files = [p for p in vault.rglob("*") if p.is_file() and visible(p)]
    by_name = {p.name.lower() for p in files}
    note_stems = {p.stem.lower() for p in files if p.suffix == ".md"} | {p.name.lower() for p in files}
    notes = sorted(p for p in lab.rglob("*.md") if visible(p))

    problems: dict[Path, list[str]] = {}
    blocking = False
    referenced: set[str] = set()

    for note in notes:
        rel = note.relative_to(lab)
        raw = note.read_text(errors="replace")
        text = strip_comments(raw)
        prose, code = split_code(text)
        issues: list[str] = []
        is_chain = rel.parts[0] == "chains"

        for m in EMBED.finditer(text):
            referenced.add(Path(m.group(1).strip()).name.lower())
        for m in EMBED.finditer(prose):
            target = Path(m.group(1).strip()).name
            if Path(target).suffix.lower() in IMG_EXT and target.lower() not in by_name:
                issues.append(f"embed points at a missing file: ![[{target}]]")
        for frag in INLINE_CODE.findall(prose):
            for m in EMBED.finditer(frag):
                issues.append(f"embed inside backticks won't render: {m.group(0)}")
        for m in EMBED.finditer(code):
            issues.append(f"embed inside a code block won't render: {m.group(0)}")
        if SPLIT_EMBED.search(prose):
            issues.append("an embed is split across lines (![[ … newline) — it won't render")

        n_missing = text.count(MISSING)
        if n_missing:
            issues.append(f"{n_missing}× {MISSING} — a capture point has no screenshot")

        prose_no_code = INLINE_CODE.sub("", prose)
        for m in LINK.finditer(prose_no_code):
            name = m.group(1).strip()
            key = Path(name).name.lower()
            if key not in note_stems and f"{key}.md" not in by_name:
                issues.append(f"link to a note that doesn't exist: [[{name}]]")

        if is_chain:
            heads = " | ".join(h.lower() for h in HEADING.findall(prose))
            absent = [s for s, pat in CHAIN_SECTIONS.items() if not re.search(pat, heads)]
            if absent:
                issues.append("chain note is missing: " + ", ".join(absent))
            for marker in ("TODO", "UNVERIFIED"):
                if re.search(rf"\b{marker}\b", prose):
                    issues.append(f"'{marker}' left in the chain note")
            if any(i.startswith(("embed", "chain note is missing")) or MISSING in i
                   or i.startswith("an embed") for i in issues):
                blocking = True

        if issues:
            problems[rel] = issues

    shots = lab / "screenshots"
    orphans, sidecar_only = [], []
    if shots.is_dir():
        for p in sorted(shots.iterdir()):
            if p.name.startswith("."):
                continue
            if p.suffix.lower() in IMG_EXT and p.name.lower() not in referenced:
                orphans.append(p.name)
            if p.suffix == ".txt" and not any(p.with_suffix(e).exists() for e in IMG_EXT):
                sidecar_only.append(p.name)

    print(f"vault check — {lab}")
    print(f"  {len(notes)} notes · "
          f"{sum(1 for n in notes if n.relative_to(lab).parts[0] == 'chains')} chain notes · "
          f"{len(list(shots.glob('*.png'))) if shots.is_dir() else 0} screenshots\n")
    for rel, issues in problems.items():
        tag = "✗" if rel.parts[0] == "chains" else "!"
        print(f"{tag} {rel}")
        for i in issues:
            print(f"    - {i}")
    if orphans:
        print("\n! screenshots no note embeds (embed them, or delete superseded ones):")
        for o in orphans:
            print(f"    - {o}")
    if sidecar_only:
        print("\n✗ output saved but no image (the capture failed — capture again):")
        for s in sidecar_only:
            print(f"    - {s}")
        blocking = True
    if not problems and not orphans and not sidecar_only:
        print("✓ no problems found")
    print("\n" + ("NOT DONE — fix the ✗ items above." if blocking
                  else "chain notes pass the done-gate."))
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
