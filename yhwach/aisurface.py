"""AI-surface asset classification (I52).

Classifies an agent tool to the SINK it can reach from its name/description — the
signal that turns 'the model has tools' into 'excessive agency: a tool reaches a
shell'. The lexicon is a default the operator can override per call (pass
sink=... explicitly). Pure; no DB, no network.
"""
from __future__ import annotations

# sink type -> name/description keywords (checked most-dangerous first).
_SINK_LEXICON: list[tuple[str, tuple[str, ...]]] = [
    ("shell", ("shell", "exec", "command", "bash", "terminal", "system(", "subprocess",
               "os.system", "run_command")),
    ("code", ("eval", "python", "run_code", "interpreter", "sandbox", "execute script")),
    ("sql", ("sql", "query", "database", "db_query", "execute_sql", "psql", "select ")),
    ("email", ("email", "sendmail", "smtp", "send_mail", "mailto", "send message")),
    ("file", ("read_file", "write_file", "file system", "filesystem", "fs.", "upload",
              "download", "path", "read a file", "write to")),
    ("http", ("http", "fetch", "url", "web request", "webhook", "curl", "requests.get",
              "api call", "browse")),
]


def classify_sink(name: str, description: str | None = None) -> str:
    """The sink an agent tool can reach, or 'none'. Name weighs the same as
    description so a bare `run_shell` with no doc is still caught."""
    blob = f"{name} {description or ''}".lower()
    for sink, needles in _SINK_LEXICON:
        if any(n in blob for n in needles):
            return sink
    return "none"


# sinks whose mere presence is an excessive-agency concern worth a finding.
DANGEROUS_SINKS = {"shell", "code", "sql", "email"}
