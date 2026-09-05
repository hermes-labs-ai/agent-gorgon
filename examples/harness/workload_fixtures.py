"""Owned-child-process workload fixtures for auditing Agent Gorgon.

Every scenario here spawns only processes created by this script (a wrapper
shell and its direct children). None of them touch real credentials, real
network egress, or any path outside a throwaway temp workspace. They exist so
`--audit-only` behavior can be measured against a *known* ground-truth verdict
instead of asserted from memory.

Each fixture returns a `Scenario`: a `subprocess.Popen` for the wrapper
process (the PID you point `--agent-pid` at) plus the verdict Agent Gorgon's
built-in rules are expected to reach for it, and why.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Scenario:
    name: str
    expected_verdict: str  # "SAFE", "HALT", or "KILL" (highest verdict reached)
    rationale: str
    process: subprocess.Popen
    workspace: Path


def _run_wrapper(script: str, workspace: Path) -> subprocess.Popen:
    """Launch `script` under `sh -c`, returning the wrapper's own Popen.

    The wrapper PID (not a descendant) is what a real integration would pass
    as --agent-pid: the root of the watched process tree.
    """
    return subprocess.Popen(
        ["sh", "-c", script],
        cwd=str(workspace),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def safe_workspace_write(workspace: Path, hold_seconds: float = 2.0) -> Scenario:
    """A child writes a plain file inside the allowed workspace, nothing else.

    Ground truth: SAFE. This is the negative control -- ordinary in-scope
    work must not be flagged.
    """
    target = workspace / "safe_output.txt"
    script = textwrap.dedent(
        f"""
        python3 -c "
import time
f = open('{target}', 'w')
f.write('owned-fixture-safe-write')
f.flush()
time.sleep({hold_seconds})
"
        """
    ).strip()
    return Scenario(
        name="safe_workspace_write",
        expected_verdict="SAFE",
        rationale="File write stays inside filesystem.allowed_paths with an allowed extension.",
        process=_run_wrapper(script, workspace),
        workspace=workspace,
    )


def suspicious_child_name(workspace: Path, hold_seconds: float = 2.0) -> Scenario:
    """A child process is named like a network tool but only calls `sleep`.

    Ground truth: HALT. This is the exact scenario from the README demo:
    Agent Gorgon reacts to the *name* of the spawned child, not what the
    binary actually does, which is why audit-only calibration matters before
    trusting it against a real curl/wget-named process.
    """
    fake_bin = workspace / "wget"
    sleep_path = shutil.which("sleep") or "/bin/sleep"
    fake_bin.symlink_to(sleep_path)
    script = f'"{fake_bin}" {hold_seconds} & wait'
    return Scenario(
        name="suspicious_child_name",
        expected_verdict="HALT",
        rationale="Child process name 'wget' matches the built-in outbound-transfer HALT rule.",
        process=_run_wrapper(script, workspace),
        workspace=workspace,
    )


def forbidden_extension_write(workspace: Path, hold_seconds: float = 2.0) -> Scenario:
    """A child opens a file with a forbidden extension inside the workspace.

    Ground truth: KILL (recorded only; --audit-only sends no signal). Path
    scope does not save a forbidden extension -- this fixture is the
    regression check for that rule.
    """
    target = workspace / "secret.pem"
    script = textwrap.dedent(
        f"""
        python3 -c "
import time
f = open('{target}', 'w')
f.write('owned-fixture-forbidden-extension')
f.flush()
time.sleep({hold_seconds})
"
        """
    ).strip()
    return Scenario(
        name="forbidden_extension_write",
        expected_verdict="KILL",
        rationale="Write target extension '.pem' is in filesystem.forbidden_extensions.",
        process=_run_wrapper(script, workspace),
        workspace=workspace,
    )


ALL_SCENARIOS = (
    safe_workspace_write,
    suspicious_child_name,
    forbidden_extension_write,
)
