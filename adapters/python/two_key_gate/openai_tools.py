"""OpenAI-style function calling: run a model's ``tool_calls`` through the gate.

Works with dicts in the Chat Completions shape
(``{"id", "type": "function", "function": {"name", "arguments"}}``) and
with SDK objects that have the same attributes. No OpenAI package needed.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Iterable, List

from .session import GateBlocked, Session


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key)


def run_tool_calls(
    session: Session,
    tool_calls: Iterable[Any],
    tools: Dict[str, Callable[..., Any]],
) -> List[Dict[str, str]]:
    """Execute each tool call through the gate and return ``role: tool``
    messages to append to the conversation. Blocked calls return a short
    message to the model instead of a result, so the agent loop continues."""
    messages = []
    for tc in tool_calls:
        fn_part = _get(tc, "function")
        name = _get(fn_part, "name")
        raw_args = _get(fn_part, "arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            if not isinstance(args, dict):
                raise ValueError("arguments must be a JSON object")
        except ValueError as e:
            content = f"Tool call not run: arguments were not valid JSON ({e})."
        else:
            fn = tools.get(name)
            if fn is None:
                content = f"Tool call not run: unknown tool {name}."
            else:
                try:
                    result = session.call(name, fn, args)
                    content = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
                except GateBlocked as e:
                    content = f"Tool call blocked by the safety gate ({e.decision.outcome}). It did not run."
        messages.append({"role": "tool", "tool_call_id": _get(tc, "id"), "content": content})
    return messages
