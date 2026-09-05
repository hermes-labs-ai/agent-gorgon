"""Packaged, one-command owned-process audit demo.

`agent-gorgon-audit-demo` (installed via `pip install agent-gorgon`) runs the same
owned-child-process fixtures as `examples/harness/` through the real `agent-gorgon`
CLI entrypoint in `--audit-only` mode, and prints a machine-readable JSON receipt
comparing observed verdicts against a declared ground truth, plus attribution
counts and watcher-overhead evidence.

Every process spawned here is created and owned by this module (a wrapper shell
and its direct children); no signal is ever sent to any process this module did
not create, and `--audit-only` additionally disables SIGSTOP and SIGKILL for the
whole run. Active enforcement remains opt-in and is never exercised by this demo.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

SCOPE_TEMPLATE_PATH = Path(__file__).with_name("audit_demo_scope.yaml")
VERDICT_RANK = {"SAFE": 0, "FLAG": 1, "HALT": 2, "KILL": 3}


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


def _make_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="agent-gorgon-workload."))


def _render_scope(workspace: Path, dest_dir: Path) -> Path:
    """Fill WORKSPACE_GLOB with the workspace's *resolved* path.

    psutil.open_files() reports resolved paths (e.g. macOS /tmp -> /private/
    var/folders/...); a scope written against the un-resolved workspace path
    produces a confirmed false "Path outside allowed scope" FLAG. See the
    warning in audit_demo_scope.yaml and docs/EVIDENCE.md.
    """
    real = Path(workspace).resolve()
    template = SCOPE_TEMPLATE_PATH.read_text()
    rendered = template.replace("WORKSPACE_GLOB", f"{real}/**")
    out_path = dest_dir / "scope.rendered.yaml"
    out_path.write_text(rendered)
    return out_path


def _read_actions(log_dir: Path) -> list[dict]:
    actions: list[dict] = []
    for path in sorted(log_dir.glob("actions_*.jsonl")):
        with path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    actions.append(json.loads(line))
    return actions


def _highest_verdict(actions: list[dict]) -> str:
    best = "SAFE"
    for entry in actions:
        v = entry.get("verdict", "SAFE")
        if VERDICT_RANK.get(v, 0) > VERDICT_RANK.get(best, 0):
            best = v
    return best


def _attribution_counts(actions: list[dict]) -> dict[str, int]:
    attributed = 0
    unattributed = 0
    for entry in actions:
        action = entry.get("action", {})
        details = action.get("details", {}) or {}
        if details.get("attribution") == "unattributed" and action.get("source_pid") is None:
            unattributed += 1
        else:
            attributed += 1
    return {"attributed": attributed, "unattributed": unattributed}


def _warden_command(scope_path: Path, agent_pid: int, log_dir: Path, poll: float) -> list[str]:
    return [
        sys.executable,
        "-m",
        "agent_gorgon.warden",
        "--scope",
        str(scope_path),
        "--agent-pid",
        str(agent_pid),
        "--poll",
        str(poll),
        "--no-llm",
        "--audit-only",
        "--log-dir",
        str(log_dir),
    ]


def run_scenario(factory, keep: bool) -> dict:
    workspace = _make_workspace()
    scenario = factory(workspace)
    log_dir = Path(tempfile.mkdtemp(prefix="agent-gorgon-evidence."))
    scope_path = _render_scope(workspace, log_dir)

    start = time.monotonic()
    warden = subprocess.run(
        _warden_command(scope_path, scenario.process.pid, log_dir, poll=0.05),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        text=True,
    )
    elapsed = time.monotonic() - start
    scenario.process.wait(timeout=5)

    actions = _read_actions(log_dir)
    observed = _highest_verdict(actions)
    attribution = _attribution_counts(actions)
    observation_complete = attribution["attributed"] >= 1 and warden.returncode == 0
    result = {
        "scenario": scenario.name,
        "expected_verdict": scenario.expected_verdict,
        "observed_verdict": observed,
        "match": observed == scenario.expected_verdict and observation_complete,
        "observation_complete": observation_complete,
        "rationale": scenario.rationale,
        "elapsed_seconds": round(elapsed, 3),
        "total_actions": len(actions),
        "attribution": attribution,
        "warden_exit_code": warden.returncode,
    }

    if not keep:
        shutil.rmtree(workspace, ignore_errors=True)
        shutil.rmtree(log_dir, ignore_errors=True)
    else:
        result["workspace"] = str(workspace)
        result["log_dir"] = str(log_dir)

    return result


def measure_overhead() -> dict:
    """Honest overhead evidence for the watcher itself.

    Agent Gorgon does not instrument the target process; it polls it from a
    separate process. So the number that matters is NOT "how much slower did
    the target run" (a correctly implemented watcher adds ~0 to that) -- it's
    how much CPU/RSS the watcher process itself consumes while polling. This
    measures both, honestly, rather than asserting a number.
    """
    workspace = _make_workspace()
    baseline_start = time.monotonic()
    baseline = subprocess.Popen(
        ["sh", "-c", "sleep 2"],
        cwd=str(workspace),
    )
    baseline.wait()
    baseline_elapsed = time.monotonic() - baseline_start
    shutil.rmtree(workspace, ignore_errors=True)

    workspace = _make_workspace()
    scenario = safe_workspace_write(workspace, hold_seconds=2.0)
    log_dir = Path(tempfile.mkdtemp(prefix="agent-gorgon-evidence."))
    scope_path = _render_scope(workspace, log_dir)
    watched_start = time.monotonic()
    warden_proc = subprocess.Popen(
        _warden_command(scope_path, scenario.process.pid, log_dir, poll=0.05),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    watcher_ps = psutil.Process(warden_proc.pid)
    cpu_samples = []
    try:
        while warden_proc.poll() is None:
            try:
                cpu_samples.append(watcher_ps.cpu_percent(interval=0.1))
            except psutil.NoSuchProcess:
                break
    finally:
        warden_proc.wait(timeout=10)
    watched_elapsed = time.monotonic() - watched_start
    scenario.process.wait(timeout=5)
    shutil.rmtree(workspace, ignore_errors=True)
    shutil.rmtree(log_dir, ignore_errors=True)

    return {
        "target_baseline_seconds": round(baseline_elapsed, 3),
        "target_watched_wallclock_seconds": round(watched_elapsed, 3),
        "note": (
            "target_watched_wallclock_seconds includes the watcher's own "
            "startup and shutdown, not just the 2s target sleep -- it is "
            "NOT a measurement of target slowdown, since the watcher runs "
            "as a separate process and never blocks the target."
        ),
        "watcher_cpu_percent_samples": [round(s, 1) for s in cpu_samples],
        "watcher_cpu_percent_avg": (
            round(sum(cpu_samples) / len(cpu_samples), 1) if cpu_samples else None
        ),
        "poll_interval_seconds": 0.05,
    }


def build_report(keep: bool = False) -> dict:
    results = [run_scenario(factory, keep) for factory in ALL_SCENARIOS]
    overhead = measure_overhead()
    mismatches = [r for r in results if not r["match"]]
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenarios": results,
        "false_trigger_or_miss_count": len(mismatches),
        "overhead": overhead,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=str, help="Write JSON report to this path")
    parser.add_argument("--keep", action="store_true", help="Keep workspaces/evidence dirs")
    args = parser.parse_args()

    report = build_report(keep=args.keep)

    print(json.dumps(report, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")

    return 1 if report["false_trigger_or_miss_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
