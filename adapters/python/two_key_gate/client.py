"""Low-level client for the two-key-gate binary.

Runs three long-lived child processes that share one HMAC key:

- ``eval``: the gate. One JSON request line in, one decision line out.
- ``approve``: the user's yes/no desk. Turns a pending CONFIRM into a
  one-use capability, only when the confirm callback says yes.
- ``redeem``: the executor check. A capability is spent exactly once.

The key lives in a private temp file (mode 0600) created with
``two-key-gate keygen`` and is never passed to the model or returned to
callers. The gate logic itself is entirely in the Rust binary; this module
only moves JSON lines.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

LABEL_SYSTEM = "trusted_system"
LABEL_USER = "trusted_user"
LABEL_TOOL = "untrusted_tool"
LABEL_SYSTEM_ID = "system_id"


class GateError(RuntimeError):
    """The gate process failed or returned something unexpected (fail closed)."""


def find_binary(explicit: Optional[str] = None) -> str:
    """Locate the two-key-gate binary.

    Order: explicit path, $TWO_KEY_GATE_BIN, PATH, then this repo's
    target/release and target/debug folders.
    """
    candidates = [explicit, os.environ.get("TWO_KEY_GATE_BIN"), shutil.which("two-key-gate")]
    repo_root = Path(__file__).resolve().parents[3]
    for profile in ("release", "debug"):
        candidates.append(str(repo_root / "target" / profile / "two-key-gate"))
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise GateError(
        "two-key-gate binary not found. Run `cargo build --release` in the repo root, "
        "or set TWO_KEY_GATE_BIN."
    )


@dataclass
class Decision:
    """One gate decision, as returned by ``two-key-gate eval``."""

    outcome: str  # "allow", "confirm" or "refuse"
    tool: str
    args: Dict[str, Any]
    reasons: List[str]
    capability: Optional[Dict[str, Any]] = field(default=None, repr=False)
    pending: Optional[Dict[str, Any]] = field(default=None, repr=False)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def call(self) -> Dict[str, Any]:
        return {"tool": self.tool, "args": self.args}


class _LineProcess:
    """A child process that answers one JSON line with one JSON line."""

    def __init__(self, argv: List[str]):
        self._lock = threading.Lock()
        self._p = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    def ask(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        line = json.dumps(obj, ensure_ascii=False, allow_nan=False)
        with self._lock:
            if self._p.poll() is not None:
                raise GateError("gate process has exited: " + (self._p.stderr.read() or "").strip())
            try:
                self._p.stdin.write(line + "\n")
                self._p.stdin.flush()
                out = self._p.stdout.readline()
            except (BrokenPipeError, OSError) as e:
                raise GateError(f"gate process I/O failed: {e}") from e
        if not out:
            err = self._p.stderr.read() if self._p.poll() is not None else ""
            raise GateError("gate process returned nothing: " + (err or "").strip())
        return json.loads(out)

    def close(self) -> None:
        try:
            if self._p.stdin:
                self._p.stdin.close()
            self._p.wait(timeout=5)
        except Exception:
            self._p.kill()
        for s in (self._p.stdout, self._p.stderr):
            try:
                s.close()
            except Exception:
                pass


class GateClient:
    """Talks to the two-key-gate binary. One client per agent process.

    ``policy`` is a path to a policy JSON file or the policy as a dict
    (same format as examples/policy_template.json in the repo root).
    """

    def __init__(
        self,
        policy: Union[str, os.PathLike, Dict[str, Any]],
        binary: Optional[str] = None,
        log_path: Optional[str] = None,
    ):
        self.binary = find_binary(binary)
        self._tmp = tempfile.TemporaryDirectory(prefix="two-key-gate-")
        if isinstance(policy, dict):
            policy_path = os.path.join(self._tmp.name, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump(policy, f)
        else:
            policy_path = os.fspath(policy)
        key_path = os.path.join(self._tmp.name, "gate.key")
        r = subprocess.run([self.binary, "keygen", "--out", key_path], capture_output=True, text=True)
        if r.returncode != 0:
            raise GateError("keygen failed: " + r.stderr.strip())
        eval_argv = [self.binary, "eval", "--policy", policy_path, "--key-file", key_path]
        if log_path:
            eval_argv += ["--log", os.fspath(log_path)]
        self._eval = _LineProcess(eval_argv)
        self._approve = _LineProcess([self.binary, "approve", "--key-file", key_path])
        self._redeem = _LineProcess([self.binary, "redeem", "--key-file", key_path])

    # -- the three operations -------------------------------------------------

    def check(self, context: List[Dict[str, str]], tool: str, args: Dict[str, Any]) -> Decision:
        """Ask the gate about one tool call. Never raises for a bad call:
        malformed input comes back as a refuse decision."""
        out = self._eval.ask({"context": context, "call": {"tool": tool, "args": args}})
        outcome = out.get("decision")
        if outcome not in ("allow", "confirm", "refuse"):
            raise GateError(f"unexpected gate output: {out!r}")
        return Decision(
            outcome=outcome,
            tool=tool,
            args=args,
            reasons=list(out.get("reasons") or []),
            capability=out.get("capability"),
            pending=out.get("pending"),
            raw=out,
        )

    def approve(self, decision: Decision, user_said_yes: bool) -> Optional[Dict[str, Any]]:
        """Resolve a CONFIRM. Returns a one-use capability on yes, else None.
        Each pending item can be resolved once."""
        if decision.outcome != "confirm" or not decision.pending:
            return None
        out = self._approve.ask(
            {
                "seq": decision.pending["seq"],
                "token": decision.pending["token"],
                "call": decision.call,
                "approved": bool(user_said_yes),
            }
        )
        return out.get("capability") if out.get("ok") else None

    def redeem(self, capability: Dict[str, Any], call: Dict[str, Any]) -> bool:
        """Spend a capability for exactly this call. False if forged,
        for a different call, or already spent."""
        out = self._redeem.ask({"seq": capability["seq"], "token": capability["token"], "call": call})
        return bool(out.get("ok"))

    def close(self) -> None:
        for p in (self._eval, self._approve, self._redeem):
            p.close()
        self._tmp.cleanup()

    def __enter__(self) -> "GateClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
