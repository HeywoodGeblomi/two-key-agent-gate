"""Python adapters for two-key-agent-gate.

The gate decides; these adapters only label context and move JSON lines to
the Rust binary. See adapters/python/README.md.
"""

from .client import Decision, GateClient, GateError, find_binary
from .session import ConfirmRequest, GateBlocked, Session, ask_on_terminal, deny_all
from .openai_tools import run_tool_calls

__all__ = [
    "ConfirmRequest",
    "Decision",
    "GateBlocked",
    "GateClient",
    "GateError",
    "Session",
    "ask_on_terminal",
    "deny_all",
    "find_binary",
    "run_tool_calls",
]
__version__ = "0.1.0"
