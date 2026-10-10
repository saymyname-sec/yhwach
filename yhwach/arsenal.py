"""Arsenal — canonical absolute paths to the pre-staged tooling.

Single source of truth. Every yhwach action, playbook rule, runner, or MCP tool
that names a binary or a generator script MUST import from here — never inline a
path. That way one edit fixes drift everywhere.

Naming discipline:

  * ``SVCMON_WIN``            — obfuscated Windows ligolo-ng agent (canonical)
  * ``LIGOLO_AGENT_LINUX``    — static ELF ligolo agent (Linux foothold drop)
  * ``LIGOLO_PROXY``          — Kali-side ligolo proxy (needs root for tun)
  * ``CHISEL``                — Linux pivot fast path (no root, reverse SOCKS)
  * ``REVSHELL_GEN_WIN``      — v2 C# revshell generator (jitter+XOR+reconnect)
  * ``REVSHELL_GEN_LINUX``    — 7-payload Linux revshell generator

Every entry carries its ``kind``, target ``os``, and a ``sha256`` for the
signed binaries so ``resolve()`` can also verify integrity.

Paths are resolved at import via :func:`_pick`, which prefers the copy
**vendored inside this repo** (``<repo>/arsenal/``) and falls back to the
workspace arsenal dir (``yhwach.config.arsenal_dir()``; env
``$YHWACH_ARSENAL_DIR``) only if the vendored file is absent. A fresh clone
works out of the box; an operator who keeps binaries outside the repo points
``$YHWACH_ARSENAL_DIR`` at them.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from yhwach import config as yhconfig


@dataclass(frozen=True)
class ArsenalItem:
    """A single canonical arsenal entry.

    ``path`` is absolute, home-expanded at load time. ``sha256`` is optional
    (only pinned for signed/obfuscated binaries where an unexpected build
    would be operationally significant).
    """

    key: str
    path: Path
    kind: str          # ligolo_agent | ligolo_proxy | chisel_client | revshell_gen | loader_builder
    os: str            # windows | linux | any
    sha256: str | None = None
    notes: str = ""

    def exists(self) -> bool:
        return self.path.exists()

    def verify_sha256(self) -> bool:
        """Return True iff the file exists and (if pinned) matches its sha256."""
        if not self.path.exists():
            return False
        if self.sha256 is None:
            return True
        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest().lower() == self.sha256.lower()


# The arsenal vendored inside this repo: ``<repo_root>/arsenal/``. Resolved
# relative to this file so it works wherever the repo is cloned.
_ARSENAL = Path(__file__).resolve().parent.parent / "arsenal"

# The workspace arsenal dir (env $YHWACH_ARSENAL_DIR / $YHWACH_HOME) — the
# fallback when a binary is not vendored in-repo.
_WORKSPACE_ARSENAL = yhconfig.arsenal_dir()


def _pick(*candidates: Path) -> Path:
    """Return the first candidate that exists, else the first candidate.

    Lets a canonical entry prefer its vendored copy and fall back to a legacy
    external path, while never returning a relative or empty path.
    """
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


# ── Canonical entries ────────────────────────────────────────────────────────
# Keep this list short and stable. Anything the operator invokes routinely
# during a foothold/pivot belongs here; ad-hoc one-offs do not.

SVCMON_WIN = ArsenalItem(
    key="SVCMON_WIN",
    path=_pick(
        _ARSENAL / "svcmon.exe",
        _WORKSPACE_ARSENAL / "svcmon.exe",
    ),
    kind="ligolo_agent",
    os="windows",
    sha256="ea77d2b807ca89f6369fefac4109e4fcb121e50bd76664bd245944cb9eff3251",
    notes="Obfuscated PE; AV/Defender-evasive. THE Windows ligolo drop-in. "
    "Canonical copy vendored at <repo>/arsenal/svcmon.exe (sha256-pinned).",
)

LIGOLO_AGENT_LINUX = ArsenalItem(
    key="LIGOLO_AGENT_LINUX",
    path=_pick(
        Path("/usr/bin/ligolo-agent"),           # Kali apt: ligolo-ng package
        _ARSENAL / "ligolo-agent-linux",         # optional vendored override
        _WORKSPACE_ARSENAL / "ligolo-agent-linux",
    ),
    kind="ligolo_agent",
    os="linux",
    sha256=None,  # apt-managed (ligolo-ng pkg); upgrades rotate the hash — like CHISEL
    notes="Linux ligolo agent (x86-64 ELF) from the Kali `ligolo-ng` apt package. "
    "Copy to the Linux target to run. Drop a static build at "
    "<repo>/arsenal/ligolo-agent-linux to override.",
)

LIGOLO_PROXY = ArsenalItem(
    key="LIGOLO_PROXY",
    path=_pick(
        Path("/usr/bin/ligolo-proxy"),           # Kali apt: ligolo-ng package
        _WORKSPACE_ARSENAL / "ligolo-proxy",
    ),
    kind="ligolo_proxy",
    os="linux",
    sha256=None,  # apt-managed (ligolo-ng pkg); upgrades rotate the hash — like CHISEL
    notes="Kali-side proxy from the `ligolo-ng` apt package; needs root for the `tun` interface.",
)

CHISEL = ArsenalItem(
    key="CHISEL",
    path=Path("/usr/local/bin/chisel"),
    kind="chisel_client",
    os="any",
    sha256=None,  # system-installed, may be updated out of band
    notes="Reverse-SOCKS pivot. No root needed on target or Kali.",
)

REVSHELL_GEN_WIN = ArsenalItem(
    key="REVSHELL_GEN_WIN",
    path=_pick(
        _ARSENAL / "gen_cs_shell.sh",
        _WORKSPACE_ARSENAL / "gen_cs_shell.sh",
    ),
    kind="revshell_gen",
    os="windows",
    sha256=None,  # script; content-hashing a generator is low value
    notes="C# generator: 4-byte XOR, per-run random symbols, reconnect+jitter. "
    "Proven to land a shell on Win11 with AV enabled. Vendored: <repo>/arsenal/gen_cs_shell.sh.",
)

REVSHELL_GEN_LINUX = ArsenalItem(
    key="REVSHELL_GEN_LINUX",
    path=_pick(
        _ARSENAL / "gen_linux_shell.sh",
        _WORKSPACE_ARSENAL / "gen_linux_shell.sh",
    ),
    kind="revshell_gen",
    os="linux",
    sha256=None,
    notes="Emits 7 payloads (bash/dev/tcp, python PTY, socat, nc, perl, php, ELF). "
    "Vendored: <repo>/arsenal/gen_linux_shell.sh.",
)


_REGISTRY: dict[str, ArsenalItem] = {
    item.key: item
    for item in (
        SVCMON_WIN,
        LIGOLO_AGENT_LINUX,
        LIGOLO_PROXY,
        CHISEL,
        REVSHELL_GEN_WIN,
        REVSHELL_GEN_LINUX,
    )
}


class ArsenalMissingError(FileNotFoundError):
    """Raised when a caller asks for an arsenal item whose file is absent.

    Distinct from a plain ``FileNotFoundError`` so runners can catch and
    downgrade to a manual-render fallback rather than crashing the loop.
    """


# Back-compat alias for callers that import the old name; keeps ruff N818
# happy without breaking imports mid-branch.
ArsenalMissing = ArsenalMissingError


def get(key: str) -> ArsenalItem:
    """Look up an entry by its stable key (e.g. ``"SVCMON_WIN"``)."""
    try:
        return _REGISTRY[key]
    except KeyError as e:
        raise KeyError(
            f"unknown arsenal key {key!r}; known: {sorted(_REGISTRY)}"
        ) from e


def resolve(key: str, *, require_exists: bool = True) -> Path:
    """Return the absolute path for ``key``.

    With ``require_exists=True`` (the default), raises ``ArsenalMissing`` when
    the file is absent so downstream renderers do not silently emit a command
    referencing a binary that will 404 on the target.
    """
    item = get(key)
    if require_exists and not item.exists():
        raise ArsenalMissing(
            f"arsenal item {key} declared at {item.path} but the file is missing; "
            f"vendor it under <repo>/arsenal/ or set $YHWACH_ARSENAL_DIR"
        )
    return item.path


def all_items() -> list[ArsenalItem]:
    """Return every canonical entry (for doctor / status listings)."""
    return list(_REGISTRY.values())


def for_os(os_hint: str, kind: str) -> ArsenalItem | None:
    """Pick the canonical entry for a given (os, kind) pair.

    ``os_hint`` is ``"windows"`` or ``"linux"``; ``kind`` is ``"ligolo_agent"``
    / ``"revshell_gen"`` / etc. Returns ``None`` when the (os, kind) pair has
    no canonical answer — the caller decides whether that is a bug or a
    legitimate "no such tool" (e.g. a Linux svcmon).
    """
    for item in _REGISTRY.values():
        if item.kind != kind:
            continue
        if item.os == os_hint or item.os == "any":
            return item
    return None
