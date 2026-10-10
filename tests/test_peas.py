"""Tests for linPEAS / winPEAS privesc extraction."""
from __future__ import annotations

from yhwach.parsers.peas import parse_linpeas, parse_peas, parse_winpeas


def _titles(findings):
    return {f.title for f in findings}


def test_linpeas_sudo_nopasswd() -> None:
    text = "Checking sudo -l\nUser may run the following:\n    (root) NOPASSWD: /usr/bin/find"
    f = parse_linpeas(text)
    assert "sudo NOPASSWD entry" in _titles(f)
    assert any(x.severity == "high" for x in f)


def test_linpeas_suid_gtfobins() -> None:
    text = "-rwsr-xr-x 1 root root 100 Jan 1 /usr/bin/find\n-rwsr-xr-x 1 root root 5 x /usr/bin/vim"
    f = parse_linpeas(text)
    titles = _titles(f)
    assert "Exploitable SUID binary (GTFObins)" in titles
    ev = next(x.evidence for x in f if x.title.startswith("Exploitable SUID"))
    assert "find" in ev and "vim" in ev


def test_linpeas_capability() -> None:
    text = "Files with capabilities:\n/usr/bin/python3 = cap_setuid+ep"
    f = parse_linpeas(text)
    assert "Dangerous file capability" in _titles(f)


def test_linpeas_writable_passwd() -> None:
    text = "You have write privileges over /etc/passwd"
    f = parse_linpeas(text)
    crit = [x for x in f if x.title == "Writable /etc/passwd"]
    assert crit and crit[0].severity == "critical"


def test_linpeas_private_key() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA..."
    assert "Private SSH key found on host" in _titles(parse_linpeas(text))


def test_linpeas_clean_output_no_findings() -> None:
    assert parse_linpeas("nothing juicy here, all patched") == []


def test_winpeas_seimpersonate() -> None:
    text = "SeImpersonatePrivilege             Enabled"
    assert "SeImpersonate/SeAssignPrimaryToken (Potato)" in _titles(parse_winpeas(text))


def test_winpeas_always_install_elevated() -> None:
    text = "AlwaysInstallElevated HKLM: 1\nAlwaysInstallElevated HKCU: 1"
    assert "AlwaysInstallElevated enabled" in _titles(parse_winpeas(text))


def test_winpeas_unquoted_service() -> None:
    text = "No quotes and Space detected in C:\\Program Files\\app\\svc.exe"
    assert "Unquoted service path" in _titles(parse_winpeas(text))


def test_winpeas_gpp_cpassword() -> None:
    text = "Found Groups.xml with cpassword=abcdef"
    f = parse_winpeas(text)
    assert "GPP cpassword recoverable" in _titles(f)
    assert _tag_for(f, "GPP cpassword") == "gpp_password"


def _tag_for(findings, title_prefix):
    return next(f.tag for f in findings if f.title.startswith(title_prefix))


def test_linpeas_aws_credentials_tagged() -> None:
    f = parse_linpeas("Found /home/dev/.aws/credentials with aws_access_key_id=AKIAABCDEFGHIJKLMNOP")
    assert "AWS credentials on host" in _titles(f)
    assert _tag_for(f, "AWS credentials") == "aws_credentials"


def test_winpeas_chrome_login_data_tagged() -> None:
    f = parse_winpeas(r"Google Chrome found: C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Login Data")
    assert _tag_for(f, "Chrome credential store") == "chrome_login_data"


def test_winpeas_dpapi_masterkey_tagged() -> None:
    f = parse_winpeas(r"DPAPI Master Keys found: C:\Users\dev\AppData\Roaming\Microsoft\Protect\S-1-5-21\...")
    assert _tag_for(f, "DPAPI master key") == "dpapi_master_key"


def test_parse_peas_dispatch() -> None:
    assert parse_peas("(root) NOPASSWD: /bin/sh", "linpeas")
    assert parse_peas("SeImpersonatePrivilege Enabled", "winpeas")


def test_parse_peas_unknown_kind() -> None:
    import pytest
    with pytest.raises(ValueError):
        parse_peas("x", "bogus")


# --- P1: revived high_ev_leads triggers + new privesc tags ---

def test_winpeas_revives_high_ev_lead_triggers() -> None:
    text = (
        r"C:\Windows\Panther\unattend.xml found" "\n"
        r"C:\Users\dev\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" "\n"
        r"HKCU\Software\SimonTatham\PuTTY\Sessions\prod" "\n"
        r"C:\Users\dev\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json" "\n"
        r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\MetaMask"
    )
    tags = {f.tag for f in parse_winpeas(text)}
    assert {"unattend_xml", "powershell_history", "putty_session_reg",
            "firefox_logins_json", "browser_wallet_extension"} <= tags


def test_winpeas_new_privesc_tags() -> None:
    assert _tag_for(parse_winpeas("SeBackupPrivilege Enabled"), "SeBackup") == "sebackup_restore"
    assert _tag_for(parse_winpeas("AlwaysInstallElevated HKLM: 1"),
                    "AlwaysInstallElevated") == "always_install_elevated"
    assert _tag_for(parse_winpeas(r"No quotes and Space detected in C:\Program Files\a\s.exe"),
                    "Unquoted service path") == "unquoted_service_path"


def test_linpeas_new_privesc_tags() -> None:
    assert _tag_for(parse_linpeas("(root) NOPASSWD: /usr/bin/find"),
                    "sudo NOPASSWD") == "sudo_nopasswd"
    assert _tag_for(parse_linpeas("-rwsr-xr-x 1 root root 1 x /usr/bin/find"),
                    "Exploitable SUID") == "suid_gtfobins"
    assert _tag_for(parse_linpeas("/usr/bin/python3 = cap_setuid+ep"),
                    "Dangerous file capability") == "linux_capabilities"
    assert _tag_for(parse_linpeas("/mnt/backups *(rw,no_root_squash)"),
                    "NFS export") == "nfs_no_root_squash"


# --- P1b: container/k8s software extraction feeds the cve_map rows ---

def test_parse_peas_software_container_versions() -> None:
    from yhwach.parsers.peas import parse_peas_software
    text = (
        "runc version 1.1.0\n"
        "containerd github.com/containerd/containerd v1.4.2\n"
        "NVIDIA Container Toolkit CLI version 1.17.0\n"
        "Kubernetes v1.12.0 (kubelet)\n"
    )
    got = {name: ver for name, ver, _ in parse_peas_software(text, "linpeas")}
    assert got["runc"] == "1.1.0"
    assert got["containerd"] == "1.4.2"
    assert got["nvidia-container-toolkit"] == "1.17.0"
    assert got["kubernetes"] == "1.12.0"
