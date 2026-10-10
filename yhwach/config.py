"""Workspace / path resolver.

One place that answers "where does yhwach keep its state, recon, loot and
arsenal?" so no other module hard-codes an operator's personal layout. Every
path is overridable by environment variable and otherwise derives from a single
workspace root:

    $YHWACH_HOME                      explicit workspace root
    $XDG_DATA_HOME/yhwach             if XDG_DATA_HOME is set
    ~/.local/share/yhwach             default

Per-directory overrides (each wins over the derived default):

    $YHWACH_STATE_DIR    state/   (the world-model DB lives here)
    $YHWACH_RECON_DIR    recon/
    $YHWACH_LOOT_DIR     loot/
    $YHWACH_ARSENAL_DIR  arsenal/

`$YHWACH_DB` (an explicit DB file path) still wins over `default_db()` for the
database specifically — see callers.
"""
from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    """The workspace root (first match wins)."""
    if v := os.environ.get("YHWACH_HOME"):
        return Path(os.path.expanduser(v))
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(os.path.expanduser(xdg)) if xdg else Path.home() / ".local" / "share"
    return base / "yhwach"


def _sub(env: str, name: str) -> Path:
    v = os.environ.get(env)
    return Path(os.path.expanduser(v)) if v else home() / name


def state_dir() -> Path:
    return _sub("YHWACH_STATE_DIR", "state")


def recon_dir() -> Path:
    return _sub("YHWACH_RECON_DIR", "recon")


def loot_dir() -> Path:
    return _sub("YHWACH_LOOT_DIR", "loot")


def arsenal_dir() -> Path:
    return _sub("YHWACH_ARSENAL_DIR", "arsenal")


def default_db() -> str:
    """Default world-model DB path (state/yhwach.db under the workspace)."""
    return str(state_dir() / "yhwach.db")
