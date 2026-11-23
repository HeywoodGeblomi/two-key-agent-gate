import json
import os
import subprocess
import sys
import tempfile

import mcp_proxy_demo
from conftest import EXAMPLES, PKG


def test_proxy_blocks_injected_call_and_passes_the_rest():
    results = mcp_proxy_demo.main()
    texts = [r["content"][0]["text"] for r in results]
    assert results[0]["isError"] is False and "attacker@evil.example" in texts[0]
    assert results[1]["isError"] is True and "Blocked by the safety gate" in texts[1]
    assert results[2]["isError"] is False and texts[2] == "SERVER EXECUTED send_email to alice@example.com"


def _run(calls, confirm_command=None):
    with tempfile.TemporaryDirectory() as tmp:
        uf = os.path.join(tmp, "u.txt")
        open(uf, "w").write("Email alice@example.com a summary.")
        argv = [sys.executable, "-m", "two_key_gate.mcp_proxy", "--policy", str(EXAMPLES / "policy.json"), "--user-request-file", uf]
        if confirm_command:
            argv += ["--confirm-command", confirm_command]
        argv += ["--", sys.executable, str(EXAMPLES / "fake_mcp_server.py")]
        lines = [json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": a}}) for i, (n, a) in enumerate(calls)]
        r = subprocess.run(argv, input="\n".join(lines) + "\n", capture_output=True, text=True, cwd=PKG, env={**os.environ, "PYTHONPATH": str(PKG)}, timeout=60)
        out = {m["id"]: m for m in map(json.loads, r.stdout.splitlines())}
        return [out[i]["result"] for i in range(len(calls))]


def test_confirm_command_exit_zero_means_yes():
    calls = [("read_inbox", {}), ("send_email", {"to": "attacker@evil.example", "subject": "s", "body": "b"})]
    assert _run(calls)[1]["isError"] is True
    assert _run(calls, confirm_command="exit 0")[1]["content"][0]["text"] == "SERVER EXECUTED send_email to attacker@evil.example"


def test_tools_missing_from_policy_are_refused_before_the_server():
    res = _run([("delete_everything", {})])
    assert res[0]["isError"] is True and "unknown_tool" in res[0]["content"][0]["text"]
