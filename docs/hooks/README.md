# Hooks & helpers

Two optional helpers for running yhwach alongside an AI agent. Neither is required; both are safe to read before you use them.

| File | What it is |
|---|---|
| [`yhwach-shot.sh`](yhwach-shot.sh) | A proof-screenshot capture tool **you (or your agent) call** at each capture point. Not an event hook — you run it. |
| [`yhwach-sync-reminder.sh`](yhwach-sync-reminder.sh) | A real Claude Code **`PostToolUse` hook** that nudges the agent to record results after offensive commands. |

Related, in [`../../scripts/`](../../scripts/): `yhwach-vault-check.py` (the done-gate for a lab folder). Template: [`../templates/chain-note.md`](../templates/chain-note.md).

---

## `yhwach-shot.sh` — proof screenshots into your vault

Captures a screenshot into `<vault>/<lab>/screenshots/`, saves a `.txt` of the command's output next to it, and prints an Obsidian embed line (`![[file.png]]`) to paste into the chain note. It prints an embed **only for a file that really exists**; if the capture produced nothing it prints `⚠️ SCREENSHOT-MISSING` and exits 1, so a note can never claim a screenshot that isn't there.

### Configure it

**1. Dependencies** — a graphical session plus a capture backend:

- **X11:** ImageMagick (`import`). `sudo apt install imagemagick`. `xdotool` is optional (it maximises the terminal before the grab).
- **Wayland:** `grim` (and `slurp` for `--region`). `sudo apt install grim slurp`.
- `--cmd` also needs a terminal emulator: qterminal, xfce4-terminal, gnome-terminal, konsole, alacritty, kitty or xterm.

**2. Make it executable, and (optional) put it on your `PATH`:**

```bash
chmod +x docs/hooks/yhwach-shot.sh
mkdir -p ~/.local/bin                                                  # ensure it exists (and is on your PATH)
ln -s "$PWD/docs/hooks/yhwach-shot.sh" ~/.local/bin/yhwach-shot.sh     # then call `yhwach-shot.sh` from anywhere
```

(If `~/.local/bin` isn't on your `PATH`, add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile, or just call the script by its full path.)

**3. Point it at your vault** (so you don't repeat `-l` and the path every time) — add to `~/.zshrc` / `~/.bashrc`:

```bash
export YHWACH_VAULT="$HOME/notes"   # vault root; each lab is a folder inside it
export YHWACH_LAB="acme"            # default lab, overridden by -l
```

| Variable | Default | Purpose |
|---|---|---|
| `YHWACH_VAULT` | `$HOME/notes` | Vault root. Shots land in `$YHWACH_VAULT/<lab>/screenshots/`. |
| `YHWACH_LAB` | `_unfiled` | Default lab folder (override per call with `-l`). |
| `YHWACH_SHOT_BACKEND` | auto | Force a backend: `import`, `flameshot` or `grim`. |
| `YHWACH_SHOT_TERM` | auto | Force the `--cmd` terminal (e.g. `qterminal`, `xfce4-terminal`). |

### Use it

```bash
# Run the step in a visible terminal; image + a .txt of the output land in the vault:
yhwach-shot.sh -l acme -n c1-web01-proof --cmd -- <the command that prints the proof>
#   SAVED:  /home/you/notes/acme/screenshots/20261011-093012_c1-web01-proof.png
#   OUTPUT: /home/you/notes/acme/screenshots/20261011-093012_c1-web01-proof.txt   (exit 0)
#   EMBED:  ![[20261011-093012_c1-web01-proof.png]]

# A shell that's already open (reverse shell, C2 session): bring it to the front, frame it yourself:
yhwach-shot.sh -l acme -n ws01-user-flag --region --delay 3
```

| Flag | Meaning |
|---|---|
| `-l, --lab` | Lab folder inside the vault (or set `YHWACH_LAB`). |
| `-n, --label` | Short label for the file / PoC step. |
| `--cmd -- <cmd>` | Open a terminal, run `<cmd>` in it, tee its output to the `.txt`, then grab the whole screen. |
| `-f, --full` | Grab the whole screen (default when there's no `--cmd`). |
| `-g, --region` | Draw a region yourself (X11: click a window or drag; Wayland: `slurp`). |
| `-d, --delay N` | Wait N seconds before a `--full` / `--region` grab (time to bring your shell to the front). |
| `-t, --timeout N` | Max seconds to wait for a `--cmd` command (default 120). |

The `.txt` is headed with the UTC time, `user@host` and the exact command line, so the chain note can quote it instead of retyping the command. See the [README's screenshot rules](../../README.md#proof-screenshots--docshooksyhwach-shotsh) for what makes a proof shot count.

### Have your agent call it

So screenshots happen as a byproduct of each step, tell the agent in your `CLAUDE.md` / `AGENTS.md`:

```markdown
- At every capture point (first shell, each privilege boundary, each landing web/AI request, the proof),
  run `docs/hooks/yhwach-shot.sh -l acme -n <ID>-<step> --cmd -- <command>` and paste the EMBED line it
  prints into the chain note. If it prints SCREENSHOT-MISSING, write that literal token at that step.
```

---

## `yhwach-sync-reminder.sh` — a Claude Code `PostToolUse` hook

Fires after the agent runs an offensive / loot / lateral-movement Bash command (NetExec, impacket, certipy, evil-winrm, `ssh user@…`, …) and reminds it to fold the result into yhwach and the notes **before** the next step — a nudge that survives context compaction, which a `CLAUDE.md` line does not. It records nothing itself, and it does not fire after plain nmap or web scans. Claude Code only; needs `jq`.

### Configure it

```bash
sudo apt install jq                                    # dependency
mkdir -p ~/.claude/hooks
cp docs/hooks/yhwach-sync-reminder.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/yhwach-sync-reminder.sh
```

Then add the matcher to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "~/.claude/hooks/yhwach-sync-reminder.sh" } ] }
    ]
  }
}
```

The reminder is delivered to the agent (exit code 2), not to you. Read the top of the script to see — and adjust — exactly which commands it triggers on.
