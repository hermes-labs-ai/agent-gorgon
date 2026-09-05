"""End-to-end check: owned-child-process fixtures produce the expected verdict
under --audit-only, run through the real CLI entrypoint (not internal APIs).

This is the regression test for examples/harness/: every process involved is
spawned by this test, no signal is ever sent (audit-only), and the scope's
allowed_paths is rendered against the *resolved* workspace path -- the
confirmed macOS false-trigger documented in docs/EVIDENCE.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HARNESS_DIR = Path(__file__).resolve().parent.parent / "examples" / "harness"
sys.path.insert(0, str(HARNESS_DIR))

from run_audit_workload import run_scenario  # noqa: E402
from workload_fixtures import (  # noqa: E402
    forbidden_extension_write,
    safe_workspace_write,
    suspicious_child_name,
)


@pytest.mark.parametrize(
    "factory",
    [safe_workspace_write, suspicious_child_name, forbidden_extension_write],
    ids=["safe_workspace_write", "suspicious_child_name", "forbidden_extension_write"],
)
def test_owned_workload_matches_ground_truth(factory):
    result = run_scenario(factory, keep=False)
    assert result["match"], (
        f"{result['scenario']}: expected {result['expected_verdict']!r}, "
        f"observed {result['observed_verdict']!r} ({result['rationale']})"
    )
    assert result["attribution"]["attributed"] >= 1
    assert result["warden_exit_code"] == 0
