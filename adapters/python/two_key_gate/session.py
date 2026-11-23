"""Framework-agnostic wrapper: one Session per conversation.

The Session keeps the labeled context the gate needs:

- the system prompt and every user turn are trusted (``add_user``),
- every tool result that passes through ``Session.call`` is recorded as
  untrusted automatically,
- IDs your own tools generate can be added as ``system_id`` spans.

Every wrapped tool call goes: gate check, then (if CONFIRM) your confirm
callback, then a one-use permit is redeemed, then your real function runs.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .client import (
    LABEL_SYSTEM,
    LABEL_SYSTEM_ID,
    LABEL_TOOL,
    LABEL_USER,
    Decision,
    GateClient,
)


class GateBlocked(Exception):
    """The call did not run. ``decision`` says why."""

    def __init__(self, message: str, decision: Decision):
        super().__init__(message)
        self.decision = decision


@dataclass
class ConfirmRequest:
    """What the confirm callback sees. Show this to the person, not the model."""

    tool: str
    args: Dict[str, Any]
    reasons: List[str]

    def describe(self) -> str:
        return f"The agent wants to run {self.tool}({json.dumps(self.args, ensure_ascii=False)}). Why it is asking: " + "; ".join(self.reasons)


ConfirmCallback = Callable[[ConfirmRequest], bool]


def deny_all(_: ConfirmRequest) -> bool:
    """Default confirm callback: no one answered, so the answer is no."""
    return False


def ask_on_terminal(req: ConfirmRequest) -> bool:
    """Simple interactive callback for local experiments."""
    answer = input(req.describe() + "\nAllow? [y/N] ")
    return answer.strip().lower() in ("y", "yes")


def _to_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        return str(result)


class Session:
    def __init__(
        self,
        gate: GateClient,
        system_prompt: Optional[str] = None,
        confirm: ConfirmCallback = deny_all,
    ):
        self.gate = gate
        self.confirm = confirm
        self.context: List[Dict[str, str]] = []
        self.history: List[Decision] = []
        if system_prompt:
            self.context.append({"label": LABEL_SYSTEM, "text": system_prompt})

    # -- context ---------------------------------------------------------------

    def add_user(self, text: str) -> None:
        """Record a user turn. Only call this with text the person typed."""
        self.context.append({"label": LABEL_USER, "text": text})

    def add_untrusted(self, text: str) -> None:
        """Record any outside text the model saw that did not come through
        Session.call (retrieved documents, web pages, pasted files)."""
        self.context.append({"label": LABEL_TOOL, "text": text})

    def add_system_id(self, kind: str, value: str) -> None:
        """Record an ID your own system generated (from a structured field,
        never from free text). It can only fill an id slot of the same kind."""
        self.context.append({"label": LABEL_SYSTEM_ID, "kind": kind, "text": value})

    # -- gated execution -------------------------------------------------------

    def call(self, tool: str, fn: Callable[..., Any], args: Dict[str, Any]) -> Any:
        """Gate one call to ``fn(**args)`` registered under ``tool``.

        Returns the function's result, or raises GateBlocked.
        """
        args = dict(args)
        decision = self.gate.check(list(self.context), tool, args)
        self.history.append(decision)
        if decision.outcome == "refuse":
            raise GateBlocked(f"refused: {'; '.join(decision.reasons)}", decision)
        if decision.outcome == "allow":
            capability = decision.capability
        else:
            req = ConfirmRequest(tool=tool, args=args, reasons=decision.reasons)
            try:
                said_yes = bool(self.confirm(req))
            except Exception:
                said_yes = False
            capability = self.gate.approve(decision, said_yes)
            if capability is None:
                raise GateBlocked(f"needs confirmation, not approved: {'; '.join(decision.reasons)}", decision)
        if not capability or not self.gate.redeem(capability, decision.call):
            raise GateBlocked("permit could not be redeemed", decision)
        result = fn(**args)
        self.add_untrusted(_to_text(result))
        return result

    def tool(self, name: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator. The wrapped function takes keyword arguments only, and
        its name must match a tool in the policy (or pass ``name``)."""

        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            def gated(**kwargs: Any) -> Any:
                return self.call(tool_name, fn, kwargs)

            gated.tool_name = tool_name  # type: ignore[attr-defined]
            gated.raw = fn  # type: ignore[attr-defined]
            return gated

        return wrap
