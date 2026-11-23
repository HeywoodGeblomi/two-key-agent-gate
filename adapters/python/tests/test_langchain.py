import pytest

pytest.importorskip("langchain_core")

import fake_tools  # noqa: E402
import langchain_demo  # noqa: E402


def test_langchain_tools_behind_the_gate():
    langchain_demo.main()
    assert fake_tools.SENT == [{"to": "alice@example.com", "subject": "Summary", "body": "One newsletter."}]


def test_wrapped_tool_keeps_name_and_schema(gate):
    from two_key_gate import Session
    from two_key_gate.langchain import gate_tool

    s = Session(gate)
    wrapped = gate_tool(langchain_demo.send_email, s)
    assert wrapped.name == "send_email"
    assert set(wrapped.args) == {"to", "subject", "body"}
