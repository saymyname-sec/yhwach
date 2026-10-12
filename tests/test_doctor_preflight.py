"""G6a — `yhwach doctor` preflight: network-filesystem check + traffic-state line,
and the dropped API-key line."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import preflight as pf
from yhwach.cli import main

# --- is_network_fs ----------------------------------------------------------


def test_is_network_fs_true() -> None:
    for f in ("nfs", "nfs4", "cifs", "smbfs", "9p", "glusterfs", "ceph",
              "fuseblk", "fuse.sshfs", "FUSE.rclone", "fuse"):
        assert pf.is_network_fs(f), f


def test_is_network_fs_false() -> None:
    for f in ("ext4", "btrfs", "xfs", "zfs", "tmpfs", "overlay", "vfat", "apfs", ""):
        assert not pf.is_network_fs(f), f
    assert not pf.is_network_fs(None)


# --- mount parsing / resolution ---------------------------------------------

_MOUNTS = (
    "proc /proc proc rw 0 0\n"
    "/dev/sda1 / ext4 rw 0 0\n"
    "/dev/sda2 /home ext4 rw 0 0\n"
    "server:/exports /home/kali/share nfs4 rw 0 0\n"
    "//nas/creds /mnt/nas cifs rw 0 0\n"
)


def test_mount_longest_prefix_wins() -> None:
    # under /home/kali/share (nfs4) beats the shorter / and /home (ext4)
    assert pf.mount_fstype_for("/home/kali/share/state/yhwach.db", _MOUNTS) == "nfs4"
    assert pf.mount_fstype_for("/mnt/nas/yhwach.db", _MOUNTS) == "cifs"
    assert pf.mount_fstype_for("/home/kali/eng/yhwach.db", _MOUNTS) == "ext4"
    assert pf.mount_fstype_for("/opt/x.db", _MOUNTS) == "ext4"   # falls back to /


def test_mount_unknown_when_no_mounts() -> None:
    assert pf.mount_fstype_for("/whatever.db", "") is None


def test_parse_mounts_skips_junk() -> None:
    assert pf.parse_mounts("garbage\nonly two\n/dev/x / ext4 rw 0 0") == [("/", "ext4")]


# --- autospray env ----------------------------------------------------------


def test_autospray_env_off() -> None:
    assert pf.autospray_env_off({"YHWACH_AUTOSPRAY": "0"})
    assert pf.autospray_env_off({"YHWACH_AUTOSPRAY": "off"})
    assert pf.autospray_env_off({"YHWACH_AUTOSPRAY": "FALSE"})
    assert not pf.autospray_env_off({"YHWACH_AUTOSPRAY": "1"})
    assert not pf.autospray_env_off({})   # default on


# --- traffic-state line -----------------------------------------------------


def test_traffic_state_env_off_wins() -> None:
    line = pf.traffic_state_line(armed=True, env_off=True, scope_count=5)
    assert "OFF" in line and "AUTOSPRAY" in line


def test_traffic_state_record_only() -> None:
    line = pf.traffic_state_line(armed=False, env_off=False, scope_count=3)
    assert "record-only" in line and "yhwach arm" in line and "3 scope entries" in line


def test_traffic_state_armed_no_scope() -> None:
    line = pf.traffic_state_line(armed=True, env_off=False, scope_count=0)
    assert "ARMED" in line and "NO SCOPE" in line


def test_traffic_state_armed_with_scope_singular() -> None:
    line = pf.traffic_state_line(armed=True, env_off=False, scope_count=1)
    assert "ARMED" in line and "send packets" in line and "1 scope entry" in line


# --- CLI integration --------------------------------------------------------


def _engage(tmp_db: Path, kind: str | None = None) -> None:
    with yhdb.transaction(tmp_db) as conn:
        yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24", kind=kind)


def test_doctor_shows_traffic_line_and_drops_api_key(tmp_db: Path) -> None:
    _engage(tmp_db)
    r = CliRunner().invoke(main, ["doctor", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0, r.output
    assert "Traffic" in r.output
    assert "DB filesystem" in r.output
    # the API-key line is gone from the advisor preflight
    assert "ANTHROPIC_API_KEY" not in r.output


def test_doctor_without_lab_notes_traffic_is_lab_scoped(tmp_db: Path) -> None:
    r = CliRunner().invoke(main, ["doctor", "--db", str(tmp_db)])
    assert r.exit_code == 0, r.output
    assert "pass --lab" in r.output
