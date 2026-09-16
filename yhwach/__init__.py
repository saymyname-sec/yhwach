"""Yhwach — deterministic red-team engagement engine for the OSAI exam and authorized labs."""
from __future__ import annotations

from pathlib import Path

__version__ = "0.0.1"


def schema_sql_path() -> Path:
    """Locate schema.sql for both source checkouts and installed wheels.

    Order:
      1. `yhwach/_schema.sql` (installed wheel — see hatch force-include in a
         future build config).
      2. `<repo>/db/schema.sql` (source checkout / editable install).
    """
    pkg_root = Path(__file__).resolve().parent

    installed = pkg_root / "_schema.sql"
    if installed.exists():
        return installed

    dev = pkg_root.parent / "db" / "schema.sql"
    if dev.exists():
        return dev

    raise FileNotFoundError(
        "yhwach schema.sql not found — expected in package (_schema.sql) or repo db/ dir"
    )


def persona_path() -> Path:
    """Locate the operator persona markdown (source checkout / installed wheel)."""
    pkg_root = Path(__file__).resolve().parent

    installed = pkg_root / "_operator.md"
    if installed.exists():
        return installed

    dev = pkg_root.parent / "persona" / "operator.md"
    if dev.exists():
        return dev

    raise FileNotFoundError(
        "yhwach operator persona not found — expected in package (_operator.md) "
        "or repo persona/ dir"
    )
