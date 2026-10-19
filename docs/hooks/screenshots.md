# Proof screenshots — quick setup

A graded engagement (an OSCP-style exam, a client pentest) is scored on **reproducibility + evidence**, and submission is final — a flag with no valid screenshot is a flag you don't get credit for. [`yhwach-shot.sh`](yhwach-shot.sh) captures proof in the required format and drops it straight into your vault, next to the chain note that cites it.

This is the quick version. Full flag/env reference is in [README.md](README.md#yhwach-shotsh--proof-screenshots-into-your-vault).

---

## 1. Set up (once)

```bash
# dependencies — a graphical session plus a capture backend:
sudo apt install imagemagick xdotool        # X11  (grim + slurp instead, on Wayland)
#   --cmd also needs a terminal emulator (qterminal / xfce4-terminal / gnome-terminal / xterm / …)

chmod +x docs/hooks/yhwach-shot.sh
mkdir -p ~/.local/bin                                                 # ensure it exists (and is on PATH)
ln -s "$PWD/docs/hooks/yhwach-shot.sh" ~/.local/bin/yhwach-shot.sh    # call `yhwach-shot.sh` from anywhere
```

Point it at your vault — add to `~/.zshrc` / `~/.bashrc`:

```bash
export YHWACH_VAULT="$HOME/notes"   # vault root; each lab is a folder inside it
export YHWACH_LAB="acme"            # default lab (override per call with -l)
```

Shots then land in `$YHWACH_VAULT/<lab>/screenshots/`.

---

## 2. The format every proof shot must have

This is what a grader has to *see*. Get it wrong and the step doesn't count.

- **The flag is the OUTPUT of a command you ran — not a value read back to you.** `type` / `cat` the proof file **as the compromised user**. A screenshot of an app or model repeating a string you supplied proves nothing.
- **`whoami` / `id` + `hostname` (+ the IP) + the flag, in ONE frame.** Identity and the proof must be visible together. A flag you downloaded and `cat`'d on your own box doesn't show who read it or where.
- **The triggering command is visible** above its output (the `--cmd` mode prints the prompt + command line for you).
- **A clean frame:** an opaque terminal, the whole screen captured with **no other session or chat visible**, no window-resize overlay, command lines short enough not to wrap.
- **AI targets:** the **exact triggering request AND the real effect** — the tool/model *result* showing execution (the injected command's output, a listener hit, a CI job trace with the runner identity + flag + "succeeded"). "The model said it did it" is not proof.
- **Web exploit:** the request *and* response (curl / Repeater) that lands it.

---

## 3. Capture at each point — the moment it happens

Take a shot at **every** one of these, as you cross it:

| Capture point | Must show |
|---|---|
| First shell / foothold | `whoami` + `hostname` |
| Each privilege boundary crossed (user → admin/root, host → host) | identity before/after |
| The proof / flag | `whoami` + `hostname` + the flag, one frame |
| Each AI target that fires | the request + the real result |
| Each web exploit that lands | the request + response |

Run the step **through** the script so the evidence is a byproduct of doing it:

```bash
yhwach-shot.sh -l acme -n c1-host01-proof --cmd -- <command that prints whoami + hostname + the flag on the target>
#   SAVED:  /home/you/notes/acme/screenshots/20261019-094210_c1-host01-proof.png
#   OUTPUT: /home/you/notes/acme/screenshots/20261019-094210_c1-host01-proof.txt   (exit 0)
#   EMBED:  ![[20261019-094210_c1-host01-proof.png]]
```

For a shell that's already open (reverse shell, C2), run the proof command in it, bring the window to the front, and frame it yourself:

```bash
yhwach-shot.sh -l acme -n c1-host01-proof --region --delay 3
```

- **Label with the chain ID** (`-n c1-host01-proof`) so each image belongs to one note.
- The script prints an `EMBED` line **only for a file that exists**. If the capture produced nothing it prints `⚠️ SCREENSHOT-MISSING` and exits 1.
- A capture point you skipped gets that **literal `⚠️ SCREENSHOT-MISSING` token** at that step in the note — never a made-up filename.

---

## 4. Each shot goes into the chain note — the same step

Paste the `EMBED` line on its **own line** (never inside backticks or a code block) under the step it proves. The `.txt` next to the image is headed with the UTC time, `user@host` and the exact command, so the note can quote the output verbatim. Write the note **as you go** — after a submission or a context reset, an uncaptured step is lost with no recovery.

Chain-note skeleton: [`../templates/chain-note.md`](../templates/chain-note.md).

---

## 5. Before you submit — the done-gate

```bash
scripts/yhwach-vault-check.py ~/notes/acme
```

It fails (exit 1) while any chain note has an embed that points at a missing file or won't render, a leftover `SCREENSHOT-MISSING`, a capture that saved output but no image, or a missing section. **One proof shot per capture point, every embed resolving — then it's done.**
