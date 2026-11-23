"""LangChain adapter: wrap existing tools so every call goes through the gate.

    from two_key_gate.langchain import gate_tools
    safe_tools = gate_tools(my_tools, session)

The wrapped tools keep their name, description and argument schema, so
models and agents bind them exactly as before. Requires ``langchain-core``.
"""

from __future__ import annotations

from typing import Any, List, Sequence

from langchain_core.tools import BaseTool, StructuredTool

from .session import GateBlocked, Session


def gate_tool(tool: BaseTool, session: Session) -> StructuredTool:
    """Return a StructuredTool that gates ``tool``. The tool name must be in
    the gate policy."""

    def run_inner(**kwargs: Any) -> Any:
        return tool.invoke(kwargs)

    def gated(**kwargs: Any) -> Any:
        # Drop LangChain's injected callback/config kwargs if any slipped in.
        args = {k: v for k, v in kwargs.items() if k not in ("callbacks", "run_manager", "config")}
        try:
            return session.call(tool.name, run_inner, args)
        except GateBlocked as e:
            return f"Tool call blocked by the safety gate ({e.decision.outcome}). It did not run."

    return StructuredTool.from_function(
        func=gated,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        infer_schema=False,
    )


def gate_tools(tools: Sequence[BaseTool], session: Session) -> List[StructuredTool]:
    return [gate_tool(t, session) for t in tools]
