"""Stdio MCP proxy: put the gate in front of an existing MCP tool server.

    python -m two_key_gate.mcp_proxy --policy policy.json \\
        --user-request-file /path/to/user_turns.txt -- <server command...>

The MCP client (your agent host) launches this proxy instead of the server.
Every JSON-RPC message is passed through unchanged except ``tools/call``
requests, which are checked by the gate first:

- allow: forwarded to the server.
- confirm: ``--confirm-command`` is run with the request as JSON on stdin;
  exit code 0 means the person said yes. With no confirm command the answer
  is no.
- refuse, or confirm declined: the server never sees the call. The client
  gets a normal tool result with ``isError: true`` explaining the block.

Results of ``tools/call`` and ``resources/read`` coming back from the server
are recorded as untrusted context automatically.

Trusted text: MCP does not carry the user's request to tool servers, so the
host must write what the person typed to ``--user-request-file`` (plain text,
read fresh on every call). Anything in that file is treated as the user's own
words, so only the host should be able to write it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional

from .client import LABEL_SYSTEM, LABEL_TOOL, LABEL_USER, GateClient

MAX_UNTRUSTED_SPANS = 2000


class McpGateProxy:
    def __init__(
        self,
        gate: GateClient,
        server_argv: List[str],
        user_request_file: Optional[str],
        confirm_command: Optional[str] = None,
        system_prompt: Optional[str] = None,
        stdin: Any = None,
        stdout: Any = None,
    ):
        self.gate = gate
        self.user_request_file = user_request_file
        self.confirm_command = confirm_command
        self.system_prompt = system_prompt
        self.untrusted: List[str] = []
        self.watch_ids: Dict[str, str] = {}  # json id -> method whose result is untrusted
        self.lock = threading.Lock()
        self.out_lock = threading.Lock()
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.server = subprocess.Popen(
            server_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1
        )

    # -- helpers ---------------------------------------------------------------

    def _emit(self, obj_or_line: Any) -> None:
        line = obj_or_line if isinstance(obj_or_line, str) else json.dumps(obj_or_line, ensure_ascii=False)
        with self.out_lock:
            self.stdout.write(line.rstrip("\n") + "\n")
            self.stdout.flush()

    def _to_server(self, line: str) -> None:
        self.server.stdin.write(line.rstrip("\n") + "\n")
        self.server.stdin.flush()

    def _context(self) -> List[Dict[str, str]]:
        ctx: List[Dict[str, str]] = []
        if self.system_prompt:
            ctx.append({"label": LABEL_SYSTEM, "text": self.system_prompt})
        if self.user_request_file:
            try:
                with open(self.user_request_file, encoding="utf-8") as f:
                    text = f.read().strip()
            except OSError:
                text = ""
            if text:
                ctx.append({"label": LABEL_USER, "text": text})
        with self.lock:
            ctx.extend({"label": LABEL_TOOL, "text": t} for t in self.untrusted)
        return ctx

    def _confirm(self, tool: str, args: Dict[str, Any], reasons: List[str]) -> bool:
        if not self.confirm_command:
            return False
        payload = json.dumps({"tool": tool, "args": args, "reasons": reasons})
        try:
            r = subprocess.run(self.confirm_command, shell=True, input=payload, text=True, capture_output=True, timeout=300)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _blocked(msg_id: Any, outcome: str, reasons: List[str]) -> Dict[str, Any]:
        text = f"Blocked by the safety gate ({outcome}). The tool did not run. Reasons: " + "; ".join(reasons)
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": text}], "isError": True}}

    # -- the two pumps ---------------------------------------------------------

    def handle_client_line(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            self._to_server(line)
            return
        if not isinstance(msg, dict) or "id" not in msg:
            self._to_server(line)
            return
        method = msg.get("method")
        if method == "resources/read":
            with self.lock:
                self.watch_ids[json.dumps(msg["id"])] = method
            self._to_server(line)
            return
        if method != "tools/call":
            self._to_server(line)
            return
        params = msg.get("params") or {}
        tool = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(tool, str) or not isinstance(args, dict):
            self._emit(self._blocked(msg["id"], "refuse", ["malformed tools/call"]))
            return
        d = self.gate.check(self._context(), tool, args)
        if d.outcome == "allow":
            cap = d.capability
        elif d.outcome == "confirm":
            cap = self.gate.approve(d, self._confirm(tool, args, d.reasons))
            if cap is None:
                self._emit(self._blocked(msg["id"], "confirm declined", d.reasons))
                return
        else:
            self._emit(self._blocked(msg["id"], "refuse", d.reasons))
            return
        if not cap or not self.gate.redeem(cap, d.call):
            self._emit(self._blocked(msg["id"], "refuse", ["permit could not be redeemed"]))
            return
        with self.lock:
            self.watch_ids[json.dumps(msg["id"])] = method
        self._to_server(line)

    def handle_server_line(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            msg = None
        if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
            key = json.dumps(msg["id"])
            with self.lock:
                watched = self.watch_ids.pop(key, None)
            if watched:
                self._record_untrusted(msg.get("result"))
        self._emit(line)

    def _record_untrusted(self, result: Any) -> None:
        texts: List[str] = []
        if isinstance(result, dict):
            for block in result.get("content") or result.get("contents") or []:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    texts.append(block["text"])
            if "structuredContent" in result:
                texts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
        if not texts and result is not None:
            texts.append(json.dumps(result, ensure_ascii=False))
        with self.lock:
            self.untrusted.extend(t for t in texts if t)
            del self.untrusted[:-MAX_UNTRUSTED_SPANS]

    def serve(self) -> int:
        def pump_server() -> None:
            for line in self.server.stdout:
                if line.strip():
                    self.handle_server_line(line)

        t = threading.Thread(target=pump_server, daemon=True)
        t.start()
        for line in self.stdin:
            if line.strip():
                self.handle_client_line(line)
        self.server.stdin.close()
        t.join(timeout=10)
        self.server.wait(timeout=10)
        return self.server.returncode or 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True, help="gate policy JSON (every server tool must be listed)")
    ap.add_argument("--user-request-file", help="file the host writes the user's own words to")
    ap.add_argument("--confirm-command", help="shell command; gets the request JSON on stdin; exit 0 = yes")
    ap.add_argument("--system-prompt", help="optional trusted system text")
    ap.add_argument("--log", help="hash-chained decision log path")
    ap.add_argument("--binary", help="path to the two-key-gate binary")
    ap.add_argument("server", nargs=argparse.REMAINDER, help="-- then the MCP server command")
    a = ap.parse_args(argv)
    server = a.server[1:] if a.server[:1] == ["--"] else a.server
    if not server:
        ap.error("give the MCP server command after --")
    with GateClient(a.policy, binary=a.binary, log_path=a.log) as gate:
        return McpGateProxy(gate, server, a.user_request_file, a.confirm_command, a.system_prompt).serve()


if __name__ == "__main__":
    sys.exit(main())
