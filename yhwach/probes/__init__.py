"""AI-surface probes. Turn 'this port is open' into 'this specific kind of AI thing is running here'.

Each probe is a pure function that takes an HTTP session, host, port and
returns a `ProbeResult` (kind + auth + meta) or `None` if the probe didn't fit.
Probes never raise on network errors — they return None. Timeouts are short by
default so a dead host doesn't stall an engagement.
"""
from yhwach.probes.ai import (
    PROBES_BY_PORT,
    ProbeResult,
    new_session,
    probe_chatbot,
    probe_gradio,
    probe_mcp,
    probe_ollama,
    probe_openai_compat,
    probes_for_port,
    run_probes,
)

__all__ = [
    "PROBES_BY_PORT",
    "ProbeResult",
    "new_session",
    "probe_chatbot",
    "probe_gradio",
    "probe_mcp",
    "probe_ollama",
    "probe_openai_compat",
    "probes_for_port",
    "run_probes",
]
