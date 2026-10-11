#!/usr/bin/env bash
# yhwach-shot.sh — proof screenshots straight into your Obsidian vault.
#
# Every capture lands INSIDE the vault, next to the notes that embed it:
#   <vault>/<lab>/screenshots/<timestamp>_<label>.png
# On success it prints an Obsidian embed line ( ![[file.png]] ) to paste into
# the chain note. It NEVER prints a filename for a file it did not write: if the
# capture produced nothing it prints  ⚠️ SCREENSHOT-MISSING  and exits 1, so a
# note can't claim a screenshot that doesn't exist.
#
# USAGE
#   yhwach-shot.sh -l <lab> -n <label> --cmd -- <command ...>
#   yhwach-shot.sh -l <lab> -n <label> [--full | --region] [--delay N]
#
#   -l, --lab      Lab folder inside the vault (or export YHWACH_LAB).
#   -n, --label    Short label for the file / PoC step (default: capture).
#       --cmd --   Open a visible terminal, run the command there (prompt, command
#                  line and output all on screen), save the output to <base>.txt
#                  next to the image — headed by the UTC time, user@host and the
#                  exact command line — then grab the WHOLE screen. The evidence is
#                  a byproduct of running the step.
#   -f, --full     Grab the whole screen (default when there's no --cmd).
#   -g, --region   Draw a region yourself — frame the flag together with
#                  whoami / hostname / IP in a shell that's already open.
#   -d, --delay N  Wait N seconds before a --full / --region grab (time to bring
#                  your shell window to the front).
#   -t, --timeout N  Max seconds to wait for a --cmd command (default 120).
#   -h, --help     Show this help.
#
# ENV
#   YHWACH_VAULT   Obsidian vault root (default: $HOME/notes)
#   YHWACH_LAB     Default lab folder (default: _unfiled)
#   YHWACH_SHOT_BACKEND  Force a backend: import | flameshot | grim
#   YHWACH_SHOT_TERM     Force a terminal: qterminal | xfce4-terminal | gnome-terminal |
#                        konsole | alacritty | kitty | xterm
#
# NEEDS a graphical session. X11: ImageMagick `import` (apt install imagemagick);
# xdotool is optional and maximises the terminal before the grab. Wayland: grim
# (+ slurp for --region).
#
# EXAMPLES
#   A proof shot should show the proof together with whoami / hostname (and the
#   IP) in the same frame — the output of a command you ran, not a value pasted in.
#
#   # run the step in a visible terminal; image + output .txt land in the vault
#   yhwach-shot.sh -l acme -n host01-proof --cmd -- <the command that prints the proof>
#
#   # a shell that's already on screen: bring it to the front, then frame it
#   yhwach-shot.sh -l acme -n host02-proof --region --delay 3
set -euo pipefail

VAULT="${YHWACH_VAULT:-$HOME/notes}"
LAB="${YHWACH_LAB:-_unfiled}"
LABEL="capture"
MODE="full"
DELAY=0
TIMEOUT=120
CMD=()

die(){ echo "yhwach-shot: $*" >&2; exit 2; }
usage(){ sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^#\( \|$\)//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--lab)     LAB="${2:?--lab needs a value}"; shift 2;;
    -n|--label)   LABEL="${2:?--label needs a value}"; shift 2;;
    -f|--full)    MODE="full"; shift;;
    -g|--region|--gui) MODE="region"; shift;;
    -d|--delay)   DELAY="${2:?--delay needs seconds}"; shift 2;;
    -t|--timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift 2;;
    --cmd)        shift; [[ "${1:-}" == "--" ]] && shift; CMD=("$@"); break;;
    --)           shift; CMD=("$@"); break;;
    -h|--help)    usage; exit 0;;
    *) die "unknown argument: $1 (see --help)";;
  esac
done
[[ "$DELAY" =~ ^[0-9]+$ && "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--delay / --timeout take whole seconds"

# ---- capture backend ---------------------------------------------------------
pick_backend(){
  if [[ -n "${YHWACH_SHOT_BACKEND:-}" ]]; then echo "$YHWACH_SHOT_BACKEND"; return; fi
  if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v grim >/dev/null 2>&1; then echo grim; return; fi
  # `import` talks to X11 directly; flameshot needs a desktop screenshot portal
  # that many window managers lack, so it is only the fallback.
  if command -v import >/dev/null 2>&1; then echo import; return; fi
  if command -v flameshot >/dev/null 2>&1; then echo flameshot; return; fi
  die "no capture tool found — install ImageMagick (X11) or grim + slurp (Wayland)"
}
BACKEND="$(pick_backend)"
if [[ "$BACKEND" != grim ]]; then
  export DISPLAY="${DISPLAY:-:0}"
  export XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}"
fi

grab_full(){   # $1 = output png
  case "$BACKEND" in
    import)    import -window root "$1" 2>/dev/null || true;;
    flameshot) flameshot full -p "$1" >/dev/null 2>&1 || true;;
    grim)      grim "$1" 2>/dev/null || true;;
    *) die "unknown backend: $BACKEND";;
  esac
}
grab_region(){ # $1 = output png
  case "$BACKEND" in
    import)    import "$1" 2>/dev/null || true;;          # click a window or drag a box
    flameshot) flameshot gui -p "$1" >/dev/null 2>&1 || true;;
    grim)      command -v slurp >/dev/null 2>&1 || die "--region on Wayland needs slurp"
               grim -g "$(slurp)" "$1" 2>/dev/null || true;;
    *) die "unknown backend: $BACKEND";;
  esac
}

# ---- output paths ------------------------------------------------------------
outdir="$VAULT/$LAB/screenshots"
mkdir -p "$outdir"
ts="$(date +%Y%m%d-%H%M%S)"
safe_label="$(printf '%s' "$LABEL" | tr -c 'A-Za-z0-9._-' '_')"
base="${ts}_${safe_label}"
png="$outdir/${base}.png"
log=""

# ---- --cmd: run it in a visible terminal, then grab the whole screen ----------
pick_term(){
  if [[ -n "${YHWACH_SHOT_TERM:-}" ]]; then echo "$YHWACH_SHOT_TERM"; return; fi
  local t
  for t in qterminal xfce4-terminal gnome-terminal konsole alacritty kitty xterm; do
    command -v "$t" >/dev/null 2>&1 && { echo "$t"; return; }
  done
  die "--cmd needs a terminal emulator (qterminal, xfce4-terminal, gnome-terminal, konsole, alacritty, kitty or xterm)"
}

if [[ ${#CMD[@]} -gt 0 ]]; then
  log="$outdir/${base}.txt"
  work="$(mktemp -d)"            # the runner holds the command line (maybe secrets) — keep it out of the vault
  trap 'rm -rf "$work"' EXIT
  runner="$work/run.sh"; done_mark="$work/done"; close_mark="$work/close"; rc_file="$work/rc"
  # The sidecar starts with when / who / where and the exact, re-runnable command
  # line, so the chain note can quote it instead of retyping it.
  {
    printf '# %s  %s@%s:%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(id -un)" "$(hostname)" "$PWD"
    printf '$ '; printf '%q ' "${CMD[@]}"; printf '\n'
  } > "$log"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'cd %q\n' "$PWD"
    printf 'clear\n'
    printf 'printf "\\033[1;32m%%s@%%s\\033[0m:\\033[1;34m%%s\\033[0m$ " "$(id -un)" "$(hostname)" "$(dirs +0)"\n'
    printf 'cat <<'\''__YHWACH_CMD__'\''\n%s\n__YHWACH_CMD__\n' "${CMD[*]}"
    printf '{ '; printf '%q ' "${CMD[@]}"; printf '; } 2>&1 | tee -a %q\n' "$log"
    printf 'echo "${PIPESTATUS[0]}" > %q\n' "$rc_file"
    printf 'echo; echo "[exit $(cat %q)]"\n' "$rc_file"
    printf 'touch %q\n' "$done_mark"
    # stay open until the screenshot is taken (or 5 min), then close by itself
    printf 'for _ in $(seq 1 300); do [[ -e %q ]] && exit 0; sleep 1; done\n' "$close_mark"
  } > "$runner"
  chmod +x "$runner"

  term="$(pick_term)"
  case "$term" in
    qterminal)       qterminal -e bash "$runner" >/dev/null 2>&1 &;;
    xfce4-terminal)  xfce4-terminal --maximize -x bash "$runner" >/dev/null 2>&1 &;;
    gnome-terminal)  gnome-terminal --maximize -- bash "$runner" >/dev/null 2>&1 &;;
    konsole)         konsole -e bash "$runner" >/dev/null 2>&1 &;;
    alacritty)       alacritty -e bash "$runner" >/dev/null 2>&1 &;;
    kitty)           kitty bash "$runner" >/dev/null 2>&1 &;;
    xterm)           xterm -geometry 200x50 -fa Monospace -fs 11 -e bash "$runner" >/dev/null 2>&1 &;;
    *) die "unsupported terminal: $term";;
  esac

  # wait for the command to finish, then let the terminal paint
  waited=0
  until [[ -e "$done_mark" ]]; do
    (( waited >= TIMEOUT * 2 )) && { echo "yhwach-shot: command still running after ${TIMEOUT}s — capturing anyway" >&2; break; }
    sleep 0.5; waited=$((waited + 1))
  done
  sleep 1
  # bring the terminal to the front, full screen, so the output fills the shot
  if [[ "$BACKEND" != grim ]] && command -v xdotool >/dev/null 2>&1; then
    wid="$(xdotool getactivewindow 2>/dev/null || true)"
    if [[ -n "$wid" ]]; then
      xdotool windowactivate "$wid" windowraise "$wid" 2>/dev/null || true
      xdotool windowsize "$wid" 100% 100% windowmove "$wid" 0 0 2>/dev/null || true
      sleep 1.5            # let the resize settle (some terminals flash a size overlay)
    fi
  fi
  grab_full "$png"
  touch "$close_mark"
  rc="$(cat "$rc_file" 2>/dev/null || echo '?')"
else
  (( DELAY > 0 )) && sleep "$DELAY"
  if [[ "$MODE" == region ]]; then
    echo "yhwach-shot: draw a box around the proof (flag + whoami + hostname)…" >&2
    grab_region "$png"
  else
    grab_full "$png"
  fi
fi

# ---- anti-fabrication gate: only claim a file that exists and isn't empty -----
if [[ -s "$png" ]]; then
  echo "SAVED:  $png"
  [[ -n "$log" ]] && echo "OUTPUT: $log   (exit $rc)"
  echo "EMBED:  ![[${base}.png]]"
else
  rm -f "$png" 2>/dev/null || true
  echo "⚠️ SCREENSHOT-MISSING (the capture wrote no file — fix the backend and capture again)"
  exit 1
fi
