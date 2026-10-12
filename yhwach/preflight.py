"""G6a — pure preflight helpers for `yhwach doctor`.

Two advisor-relevant checks the old doctor lacked:

* **Network filesystem** — the world-model DB holds credentials in the clear and
  SQLite's locking is unsafe over NFS/CIFS/FUSE. A creds DB on a network share also
  leaks off the operator's box. Doctor warns when the DB lives on such a mount.
* **Traffic state** — one line answering "if a move runs right now, do packets go
  out?" Packets flow only when the engagement is armed, scope is non-empty, and the
  `YHWACH_AUTOSPRAY=0` kill switch is not set.

Everything here is pure (no DB, no real filesystem unless asked) so it unit-tests
without a live box; the CLI feeds it the facts it reads.
"""
from __future__ import annotations

import os
import posixpath

# filesystem families where SQLite locking is unsafe and/or a creds DB would leave
# the operator's box. Matched case-insensitively; any `fuse*` is treated as remote.
_NETWORK_FS = (
    "nfs", "nfs4", "cifs", "smbfs", "smb3", "afpfs", "ncpfs", "9p",
    "glusterfs", "ceph", "beegfs", "lustre", "fuseblk",
)


def is_network_fs(fstype: str | None) -> bool:
    f = (fstype or "").strip().lower()
    if not f:
        return False
    if f.startswith("fuse"):          # sshfs, rclone, s3fs, gdrive, … — all remote-ish
        return True
    return any(f == n for n in _NETWORK_FS)


def parse_mounts(text: str) -> list[tuple[str, str]]:
    """(mountpoint, fstype) pairs from /proc/mounts / /proc/self/mountinfo-style text.

    Accepts the simple `/proc/mounts` layout (dev mountpoint fstype opts …).
    """
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].startswith("/"):
            out.append((parts[1], parts[2]))
    return out


def mount_fstype_for(path: str | os.PathLike, mounts_text: str | None = None) -> str | None:
    """Filesystem type of the mount backing `path` (longest mountpoint prefix wins),
    or None when it cannot be determined (e.g. no /proc/mounts on this platform)."""
    if mounts_text is None:
        try:
            with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
                mounts_text = fh.read()
        except OSError:
            return None
    # mount points are always POSIX paths; normalise the target the same way so
    # this resolves identically regardless of the host OS running the check.
    target = posixpath.normpath(str(path).replace("\\", "/"))
    best: str | None = None
    best_len = -1
    for mp, fstype in parse_mounts(mounts_text):
        mp_norm = posixpath.normpath(mp)
        under = target == mp_norm or target.startswith(mp_norm.rstrip("/") + "/")
        if under and len(mp_norm) > best_len:
            best, best_len = fstype, len(mp_norm)
    return best


def autospray_env_off(env: dict[str, str] | None = None) -> bool:
    """True when ``YHWACH_AUTOSPRAY`` is set to a falsey value (the hard kill switch)."""
    src = os.environ if env is None else env
    return src.get("YHWACH_AUTOSPRAY", "1").strip().lower() in ("0", "false", "no", "off")


def traffic_state_line(*, armed: bool, env_off: bool, scope_count: int) -> str:
    """One checklist line: will active tools send packets for this engagement right now?"""
    if env_off:
        return "Traffic OFF — YHWACH_AUTOSPRAY=0 hard-disables every active tool"
    n = scope_count
    scope_txt = f"{n} scope entr" + ("y" if n == 1 else "ies")
    if not armed:
        return ("Traffic record-only — active tools refused until `yhwach arm` "
                f"(lab/ctf auto-arm) · {scope_txt}")
    if n == 0:
        return "Traffic ARMED but NO SCOPE — every target refused until `yhwach scope` is set"
    return f"Traffic ARMED — scan/enum/probe/spray will send packets · {scope_txt}"
