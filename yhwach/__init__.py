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


def cve_map_path() -> Path:
    """Locate the bundled CVE knowledge base (source checkout / installed wheel)."""
    pkg_root = Path(__file__).resolve().parent
    installed = pkg_root / "_cve_map.yaml"
    if installed.exists():
        return installed
    dev = pkg_root.parent / "data" / "cve_map.yaml"
    if dev.exists():
        return dev
    raise FileNotFoundError(
        "yhwach cve_map.yaml not found — expected in package (_cve_map.yaml) or repo data/ dir"
    )


def data_path(name: str) -> Path:
    """Locate a bundled reference data file by basename (e.g. 'adcs_esc.yaml').

    Checks the packaged `yhwach/_data/<name>` first, then the repo `data/<name>`."""
    pkg_root = Path(__file__).resolve().parent
    installed = pkg_root / "_data" / name
    if installed.exists():
        return installed
    dev = pkg_root.parent / "data" / name
    if dev.exists():
        return dev
    raise FileNotFoundError(f"yhwach data file '{name}' not found in package (_data/) or repo data/")


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
