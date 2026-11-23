import os
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
EXAMPLES = PKG / "examples"
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(EXAMPLES))


def pytest_sessionstart(session):
    # Build the gate binary once if it is not there yet (no network needed).
    if not os.environ.get("TWO_KEY_GATE_BIN") and not (REPO / "target" / "release" / "two-key-gate").exists():
        subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=REPO, check=True)


@pytest.fixture
def policy_path():
    return str(EXAMPLES / "policy.json")


@pytest.fixture
def gate(policy_path):
    from two_key_gate import GateClient

    g = GateClient(policy_path)
    yield g
    g.close()
