"""Shared pytest fixtures for Yhwach tests."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    """A fresh SQLite DB with the schema applied. Cleaned up automatically."""
    from yhwach import db as yhdb

    path = tmp_path / "test.db"
    yhdb.init(path)
    return path


@pytest.fixture()
def sample_nmap_xml() -> Path:
    return Path(__file__).parent / "fixtures" / "nmap_sample.xml"
