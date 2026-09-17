#!/usr/bin/env bash
# Yhwach point-of-action sync reminder — Claude Code PostToolUse hook.
#
# WHY: mid-chain momentum makes Claude execute attacks directly and defer folding
# state into Yhwach + writing notes ("do it later" — later never comes). A CLAUDE.md
# line doesn't stick through context compaction. A hook fires at the exact moment of
# action and survives compaction — the enforcement instructions can't provide.
#
# INSTALL:
#   cp docs/hooks/yhwach-sync-reminder.sh ~/.claude/hooks/
#   chmod +x ~/.claude/hooks/yhwach-sync-reminder.sh
#   # then add the PostToolUse matcher below to ~/.claude/settings.json
#
# settings.json:
# {
#   "hooks": {
#     "PostToolUse": [
#       { "matcher": "Bash",
#         "hooks": [ { "type": "command", "command": "~/.claude/hooks/yhwach-sync-reminder.sh" } ] }
#     ]
#   }
# }
#
# Fires only when the bash command looks like an offensive/loot/lateral step whose
# output typically yields a credential, a flag, a stage change, or a chain link
# worth recording. Exit 2 surfaces the reminder to Claude at that moment.

input=$(cat)
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$cmd" ] && exit 0

# Strong signals only — keep the interrupt from firing on benign recon.
if printf '%s' "$cmd" | grep -qiE '\b(nxc|netexec|crackmapexec|evil-winrm|impacket-[a-z]+|secretsdump|getuserspns|getnpusers|certipy|kerbrute|mimikatz|rubeus|lsassy|gpp-decrypt|dpapi|psexec|wmiexec|smbexec|proxychains|ligolo|responder|ntlmrelayx)\b|\bssh +[a-z0-9._-]+@'; then
  cat >&2 <<'MSG'
[YHWACH SYNC — do this BEFORE your next attack step]
An offensive/loot command just ran. Fold the result into Yhwach NOW, then write the note:
  1. yhwach_cred    — any new credential (with --source and --host)
  2. yhwach_proof   — if you captured a flag/proof (with the screenshot path)
  3. yhwach_advance / yhwach_pivot — if a host stage changed or a tunnel came up
  4. Obsidian note  — append this step to the Attack Chain: the EXACT command (fenced),
                      captured output, and evidence path; update the host + Credentials notes.
Then re-call yhwach_next. Do not start the next target until state + notes are recorded —
a win you didn't capture is a win you lose on /clear.
MSG
  exit 2
fi
exit 0
