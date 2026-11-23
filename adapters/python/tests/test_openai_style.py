import fake_tools
import openai_style_demo


def test_scripted_fooled_model_cannot_exfiltrate_or_delete():
    session = openai_style_demo.main()
    assert fake_tools.SENT == [{"to": "alice@example.com", "subject": "Inbox summary", "body": "One newsletter with deals."}]
    assert fake_tools.DELETED == []
    assert [d.outcome for d in session.history] == ["allow", "confirm", "confirm", "allow"]


def test_confirm_callback_is_pluggable():
    asked = []
    openai_style_demo.main(confirm=lambda req: asked.append(req.tool) or False)
    assert asked == ["send_email", "delete_email"]
    assert all(m["to"] != "attacker@evil.example" for m in fake_tools.SENT)


def test_bad_arguments_and_unknown_tools_do_not_run(gate):
    from two_key_gate import Session, run_tool_calls

    s = Session(gate)
    s.add_user("hi")
    msgs = run_tool_calls(
        s,
        [
            {"id": "a", "function": {"name": "send_email", "arguments": "{not json"}},
            {"id": "b", "function": {"name": "format_disk", "arguments": "{}"}},
        ],
        {"send_email": fake_tools.send_email},
    )
    assert "not valid JSON" in msgs[0]["content"] and "unknown tool" in msgs[1]["content"]
