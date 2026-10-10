#!/usr/bin/env bash
# yhwach — opt-in arsenal fetch helper.
#
# yhwach ships NO offensive binaries. This script is a convenience for setting up
# the OPTIONAL, user-provided arsenal directory that yhwach.config.arsenal_dir()
# resolves ($YHWACH_ARSENAL_DIR, else $YHWACH_HOME/arsenal, else
# ~/.local/share/yhwach/arsenal). It fetches ONLY the common dual-use pivot infra
# (ligolo-ng, chisel) from official sources; for everything else it prints the
# official upstream URL so YOU fetch and vet it yourself. See arsenal.manifest.yaml.
#
# AUTHORISED USE ONLY. You are responsible for the licence and the legality of
# every tool you place in the arsenal dir. See AUTHORIZATION.md. This script
# downloads nothing you have not explicitly run it to download.
set -euo pipefail

ARSENAL_DIR="${YHWACH_ARSENAL_DIR:-${YHWACH_HOME:-$HOME/.local/share/yhwach}/arsenal}"
mkdir -p "$ARSENAL_DIR"
echo "[*] arsenal dir: $ARSENAL_DIR"

# --- ligolo-ng (pivot) -------------------------------------------------------
if command -v ligolo-agent >/dev/null 2>&1 || command -v ligolo-proxy >/dev/null 2>&1; then
  echo "[+] ligolo-ng already on PATH (apt) — nothing to fetch"
elif command -v apt >/dev/null 2>&1; then
  echo "[*] install ligolo-ng with:  sudo apt install ligolo-ng"
else
  echo "[*] ligolo-ng: build from https://github.com/nicocha30/ligolo-ng/releases"
fi

# --- chisel (pivot) ----------------------------------------------------------
if command -v chisel >/dev/null 2>&1; then
  echo "[+] chisel already on PATH — nothing to fetch"
else
  echo "[*] chisel: download the release for your arch from"
  echo "    https://github.com/jpillora/chisel/releases  and put it on PATH or in $ARSENAL_DIR"
fi

cat <<'EOF'

[*] Fetch-and-vet yourself (official upstreams — review each licence first):
    PEASS-ng (winPEAS/linPEAS)  https://github.com/peass-ng/PEASS-ng/releases
    SharpCollection             https://github.com/Flangvik/SharpCollection
    LaZagne                     https://github.com/AlessandroZ/LaZagne/releases
    mimikatz                    https://github.com/gentilkiwi/mimikatz/releases
    PowerSploit (PowerUp/View)  https://github.com/PowerShellMafia/PowerSploit
    procdump (Sysinternals)     https://learn.microsoft.com/sysinternals/downloads/procdump

[*] Operator-original helpers are NOT distributed. Supply your own under the
    arsenal dir if you want the matching actions to resolve (see arsenal.manifest.yaml):
      REVSHELL_GEN_WIN   -> gen_cs_shell.sh        (Windows C# revshell generator)
      REVSHELL_GEN_LINUX -> gen_linux_shell.sh     (Linux revshell generator)
      SVCMON_WIN         -> svcmon.exe             (Windows ligolo agent)

[*] Done. yhwach works without any of this — absent items degrade to manual-render hints.
EOF
