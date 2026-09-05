from __future__ import annotations

import subprocess
import sys


def test_gorgon_is_canonical_and_warden_forwards_compatibly() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import agent_gorgon
from agent_gorgon import warden as canonical_warden
import agent_warden
from agent_warden import warden as legacy_warden
assert agent_gorgon.__version__ == '0.2.0'
assert agent_warden.__version__ == agent_gorgon.__version__
assert legacy_warden.Scope is canonical_warden.Scope
assert legacy_warden.Verdict is canonical_warden.Verdict
""",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_canonical_module_cli_resolves() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "agent_gorgon.warden", "--help"],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout
