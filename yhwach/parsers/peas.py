"""linPEAS / winPEAS output -> privesc findings.

PEAS output is huge and noisy. We extract only high-signal, unambiguous privesc
leads by pattern — sudo NOPASSWD, known-exploitable SUID (GTFObins), dangerous
capabilities, SeImpersonate, AlwaysInstallElevated, GPP/autologon creds, unquoted
service paths. Everything else stays for the operator to read in the raw file.
"""
from __future__ import annotations

import re

from yhwach.interpret import ExtractedFinding

# GTFObins SUID/privesc binaries worth flagging when the SUID bit is set.
_GTFO_SUID = {
    "find", "vim", "vi", "nmap", "bash", "sh", "less", "more", "nano", "cp", "mv",
    "python", "python2", "python3", "perl", "awk", "gawk", "tar", "zip", "gdb",
    "env", "make", "ruby", "lua", "node", "docker", "systemctl", "dmesg",
    "strace", "tcpdump", "openssl", "cpulimit", "ionice", "nice", "flock",
    "pkexec", "base64", "cat", "dd", "sed", "ed",
}


_CHECKPOINT_FILE_RE = re.compile(r"(?i)(/[\w./-]*\.(?:pt|pth|ckpt)\b|[\w./-]*pytorch_model\.bin)")
_TRAINING_FILE_RE = re.compile(
    r"(?i)(adapter_config\.json|adapter_model[\w.]*|trainer_state\.json|training_args[\w.]*"
    r"|/[\w./-]*(?:datasets?|fine[_-]?tun\w*)/[\w./-]*)")
# linPEAS marks what a low-priv user can write; a writable checkpoint is the
# difference between "interesting" and "RCE on the next model load".
_WRITABLE_RE = re.compile(r"(?i)writable|rwx|[ -]rw.rw|\bw\b")


def _model_artifacts(text: str) -> list[ExtractedFinding]:
    """Checkpoint / training artifacts in a PEAS file listing -> chaining tags.

    One pass over the output; stops as soon as both chains have a witness."""
    out: list[ExtractedFinding] = []
    ckpt: tuple[str, bool] | None = None
    train: str | None = None

    for line in text.splitlines():
        if ckpt is None:
            m = _CHECKPOINT_FILE_RE.search(line)
            if m:
                ckpt = (m.group(1), bool(_WRITABLE_RE.search(line)))
        if train is None:
            m = _TRAINING_FILE_RE.search(line)
            if m:
                train = m.group(1)
        if ckpt is not None and train is not None:
            break

    if ckpt is not None:
        path, writable = ckpt
        out.append(ExtractedFinding(
            "CWE-502", "Pickle-backed model checkpoint on host", "high" if writable else "medium",
            f"{path[:90]}"
            + (" (writable — overwrite it and the next torch.load() is RCE)" if writable
               else " — check write access; torch.load() unpickles it on the model server"),
            tag="model_checkpoint_load"))
    if train is not None:
        out.append(ExtractedFinding(
            "LLM03", "Training / fine-tuning artifacts on host", "medium",
            f"{train[:90]} — dataset, LoRA adapter or tokenizer poisoning against the next run",
            tag="training_pipeline"))
    return out


def parse_linpeas(text: str) -> list[ExtractedFinding]:
    out: list[ExtractedFinding] = []

    # sudo NOPASSWD
    if re.search(r"NOPASSWD", text):
        entries = re.findall(r"\(([^)]*)\)\s*NOPASSWD:\s*(\S+)", text)
        ev = "; ".join(f"({u}) {c}" for u, c in entries[:5]) or "NOPASSWD entry present"
        out.append(ExtractedFinding("CWE-250", "sudo NOPASSWD entry", "high", ev[:160]))

    # SUID GTFObins (match the SUID permission bit -rws...)
    suid = set()
    for m in re.finditer(r"-rws[rwxsS-]{6}.*?(/\S+)", text):
        b = m.group(1).rsplit("/", 1)[-1]
        if b in _GTFO_SUID:
            suid.add(b)
    if suid:
        out.append(ExtractedFinding(
            "CWE-250", "Exploitable SUID binary (GTFObins)", "high",
            "SUID: " + ", ".join(sorted(suid))[:150]))

    # capabilities
    caps = re.findall(r"(/\S+)\s*=\s*cap_(setuid|setgid|dac_override)", text)
    if caps:
        out.append(ExtractedFinding(
            "CWE-250", "Dangerous file capability", "high",
            "; ".join(f"{p} cap_{c}" for p, c in caps[:4])[:150]))

    # writable /etc/passwd or /etc/shadow
    if re.search(r"/etc/passwd.*(writable|is writable)", text, re.I) or \
            re.search(r"You have write privileges over /etc/passwd", text, re.I):
        out.append(ExtractedFinding(
            "CWE-732", "Writable /etc/passwd", "critical", "root via crafted passwd row"))

    # private keys / creds in files
    if re.search(r"BEGIN (RSA|OPENSSH|EC) PRIVATE KEY", text):
        out.append(ExtractedFinding(
            "CWE-522", "Private SSH key found on host", "high", "reuse for lateral SSH"))

    # Membership of the docker group is root-equivalent (mount host / in a container).
    if re.search(r"(?i)groups?\b[^\n]*\bdocker\b|\bdocker\b[^\n]*\bgroup\b|"
                 r"member of the docker group", text):
        out.append(ExtractedFinding(
            "CWE-250", "User is in the docker group (root-equivalent)", "high",
            "mount host / into a container to read/write any file as root", tag="docker_group"))

    # AWS credentials on disk / in env -> tag for the cloud chaining rules.
    if re.search(r"aws_access_key_id|\.aws/credentials|AKIA[0-9A-Z]{16}", text):
        out.append(ExtractedFinding(
            "CWE-522", "AWS credentials on host", "high",
            "IAM keys in ~/.aws/credentials or env", tag="aws_credentials"))

    # Inside a Kubernetes pod: a mounted service-account token is the entry to
    # the K8s attack chain (enumerate perms -> secret sweep -> privileged pod).
    if re.search(r"/var/run/secrets/kubernetes\.io/serviceaccount|KUBERNETES_SERVICE_HOST", text):
        out.append(ExtractedFinding(
            "CWE-522", "Kubernetes service-account token mounted in pod", "high",
            "read the SA token and enumerate cluster permissions", tag="k8s_sa_token"))

    # GPU node with a vulnerable nvidia-container-toolkit -> LD_PRELOAD escape.
    if re.search(r"nvidia-container-(toolkit|cli|runtime)", text, re.I):
        out.append(ExtractedFinding(
            "CVE-2025-23266", "nvidia-container-toolkit present (GPU container escape)", "high",
            "LD_PRELOAD OCI-hook escape to host root if toolkit <= 1.17.7", tag="nvidia_toolkit"))

    # GitLab PAT on disk / in env -> feeds the GitLab CI exfil rules.
    if re.search(r"glpat-[A-Za-z0-9_\-]{15,}", text):
        out.append(ExtractedFinding(
            "CWE-522", "GitLab personal access token on host", "high",
            "glpat- token in a config / history / env — reuse against the GitLab API",
            tag="gitlab_token"))

    # A requirements.txt -> candidate for dependency-confusion / typosquat inspection.
    if re.search(r"\brequirements\.txt\b", text):
        out.append(ExtractedFinding(
            "CWE-1104", "Python requirements file present", "low",
            "audit requirements.txt for typosquats / unpinned internal packages",
            tag="python_requirements"))

    # ML artifacts on disk. A .pt/.pth/.ckpt checkpoint is a pickle archive: if
    # a model server torch.load()s it, overwriting the file is RCE as that
    # service (the poisoned-checkpoint chain). Training/LoRA artifacts open the
    # pipeline-poisoning chain instead. .safetensors is deliberately excluded —
    # not being a pickle is the whole point of that format.
    out += _model_artifacts(text)

    # A writable MCP client config -> CVE-2025-6514 mcp-remote OAuth RCE.
    for line in text.splitlines():
        if re.search(r"(?i)(?:\.mcp\.json|mcp\.json|claude_desktop_config\.json)", line) and \
                re.search(r"(?i)writable|[0-7]?[2367]{2}\b|rwx|Users?:.*W", line):
            out.append(ExtractedFinding(
                "CVE-2025-6514", "Writable MCP client config", "high",
                "poison the MCP server URL for OAuth command injection (mcp-remote)",
                tag="mcp_config_writable"))
            break

    return out


def parse_winpeas(text: str) -> list[ExtractedFinding]:
    out: list[ExtractedFinding] = []

    if re.search(r"Se(Impersonate|AssignPrimaryToken)Privilege", text):
        out.append(ExtractedFinding(
            "CWE-250", "SeImpersonate/SeAssignPrimaryToken (Potato)", "high",
            "token-impersonation privesc to SYSTEM (GodPotato/PrintSpoofer)",
            tag="seimpersonate"))

    if re.search(r"AlwaysInstallElevated.*?1", text, re.S):
        out.append(ExtractedFinding(
            "CWE-250", "AlwaysInstallElevated enabled", "high",
            "malicious MSI runs as SYSTEM"))

    if re.search(r"No quotes and Space detected|Unquoted Service Path", text, re.I):
        out.append(ExtractedFinding(
            "CWE-428", "Unquoted service path", "high",
            "writable-directory hijack -> SYSTEM"))

    if re.search(r"cpassword", text, re.I):
        out.append(ExtractedFinding(
            "CWE-256", "GPP cpassword recoverable", "high",
            "decrypt with gpp-decrypt for domain creds", tag="gpp_password"))

    # A scheduled task that RUNS AS SYSTEM whose action file/dir is writable by a
    # low-priv group -> overwrite + trigger -> SYSTEM (Double_Hellix devws01/rsrchws01).
    if re.search(r"(?i)task", text) and \
            re.search(r"(?i)Run\s*As\s*:?\s*(?:NT AUTHORITY\\)?(?:SYSTEM|LocalSystem)|as SYSTEM", text) and \
            re.search(r"(?i)(?:BUILTIN\\)?(?:Users|Everyone|Authenticated Users)\b.{0,40}"
                      r"(?:Write|Modify|FullControl|AddFile|CreateFiles|WriteData)", text):
        out.append(ExtractedFinding(
            "CWE-732", "Writable scheduled-task script runs as SYSTEM", "high",
            "overwrite the task action file (writable by Users) then schtasks /run -> SYSTEM",
            tag="writable_scheduled_task"))

    # DefaultPassword lives in the SECURITY/SOFTWARE hive as an LSA secret;
    # secretsdump LOCAL recovers it (Double_Hellix rsrchws01 -> domain cred).
    if re.search(r"DefaultPassword\s*:\s*\S+|AutoLogon", text):
        out.append(ExtractedFinding(
            "CWE-256", "LSA DefaultPassword / autologon credential", "high",
            "recover DefaultPassword via secretsdump LOCAL (SECURITY hive) then reuse/spray",
            tag="lsa_defaultpassword"))

    if re.search(r"Currently stored credentials|cmdkey", text, re.I) and "Target:" in text:
        out.append(ExtractedFinding(
            "CWE-522", "Stored credentials (cmdkey)", "medium",
            "runas /savecred against stored targets"))

    # Chrome credential store -> tag for chrome_abe_credential_decrypt.
    if re.search(r"chrome", text, re.I) and re.search(r"Login Data", text, re.I):
        out.append(ExtractedFinding(
            "CWE-522", "Chrome credential store present", "high",
            "Chrome 'Login Data' — App-Bound Encryption decrypt from a SYSTEM/user context",
            tag="chrome_login_data"))

    # DPAPI master keys / Credential Manager blobs -> tag for the DPAPI chain.
    if re.search(r"DPAPI\s+Master", text, re.I) or re.search(r"masterkey", text, re.I) or \
            re.search(r"(?i)Credential Manager|Microsoft\\+Credentials|Microsoft\\+Protect", text):
        out.append(ExtractedFinding(
            "CWE-522", "DPAPI master key / Credential Manager blobs", "high",
            "decrypt DPAPI blobs (Credential Manager / cookies) with the master key",
            tag="dpapi_master_key"))

    # A KeePass database on disk -> tag keepass_kdbx (P0 lead). KDBX4 (v40000) is
    # NOT supported by keepass2john; open with pykeepass once the master is found.
    if re.search(r"\.kdbx\b", text, re.I):
        out.append(ExtractedFinding(
            "CWE-522", "KeePass database (.kdbx) on disk", "high",
            "open with pykeepass; KDBX4 (v40000) is unsupported by keepass2john. Master often "
            "in Credential Manager or an HKCU\\Run -pw: argument",
            tag="keepass_kdbx"))

    # An autorun/Run command line that carries a secret as an argument (e.g. a
    # KeePass launcher with -pw:<master>) -> tag autorun_secret.
    if re.search(r"(?i)(?:HKCU|HKLM).{0,80}\\Run\b", text) and \
            re.search(r"(?i)-pw:|/pass(?:word)?[:=]|--password", text):
        out.append(ExtractedFinding(
            "CWE-522", "Secret leaked in an autorun command line", "high",
            "an HKCU/HKLM Run entry passes a password as an argument (e.g. KeePass -pw:)",
            tag="autorun_secret"))

    return out


def parse_peas(text: str, kind: str) -> list[ExtractedFinding]:
    if kind == "linpeas":
        return parse_linpeas(text)
    if kind == "winpeas":
        return parse_winpeas(text)
    raise ValueError(f"unknown peas kind: {kind}")


# name, version, software-kind — high-signal versioned components worth CVE-matching.
def parse_peas_software(text: str, kind: str) -> list[tuple[str, str, str]]:
    """Extract versioned software from PEAS output for the CVE pipeline.

    Deliberately narrow: kernel + sudo on Linux (both classic local-root CVE
    sources), Windows build on Windows. The operator adds the rest by hand."""
    out: list[tuple[str, str, str]] = []
    if kind == "linpeas":
        m = re.search(r"Linux version (\d+\.\d+\.\d+[\w.\-]*)", text)
        if m:
            out.append(("Linux kernel", m.group(1), "kernel"))
        m = re.search(r"[Ss]udo version (\d+\.\d+\.\d+[\w.\-]*)", text)
        if m:
            out.append(("sudo", m.group(1), "package"))
    elif kind == "winpeas":
        m = re.search(r"(Windows (?:Server )?\d{4}[\w ]*?)\s*(?:Build|\().*?(\d{4,5})", text)
        if m:
            out.append((m.group(1).strip(), m.group(2), "kernel"))
    return out
