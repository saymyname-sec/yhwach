"""Operator persona access.

Post-strip: yhwach no longer builds an EV-ranked "next move" context block — the
model reasons over `yhwach brief`. This module keeps only the persona helpers the
`persona` command / MCP tool use (the operator frame that travels with the engine).
"""
from __future__ import annotations

import hashlib

from yhwach import persona_path


def load_persona() -> str:
    """Return the operator persona markdown as a string."""
    return persona_path().read_text(encoding="utf-8").rstrip()


def persona_digest() -> str:
    """Short SHA-256 of the persona in effect — proof of which frame shaped a judgment."""
    return hashlib.sha256(load_persona().encode()).hexdigest()[:12]
