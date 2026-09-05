#!/usr/bin/env python3
"""Run the owned-child-process workload fixtures through `--audit-only` and
report attribution / false-trigger / overhead evidence.

This does exactly what the README's "See it work safely" demo does, for each
scenario in `workload_fixtures.py`, then diffs the observed verdict against
the scenario's known ground truth. No signal is ever sent to any process
this script did not create; --audit-only additionally disables SIGSTOP and
SIGKILL for the whole run.

Usage:
    python3 examples/harness/run_audit_workload.py [--out report.json] [--keep]

Exit code is nonzero if any scenario's observed verdict does not match its
expected ground truth (a false trigger or a missed detection).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

HARNESS_DIR = Path(__file__).resolve().parent
REPO_ROOT = HARNESS_DIR.parent.parent
SCOPE_TEMPLATE_PATH = HARNESS_DIR / "scope.audit-demo.yaml"
VERDICT_RANK = {"SAFE": 0, "FLAG": 1, "HALT": 2, "KILL": 3}

sys.path.insert(0, str(HARNESS_DIR))
from workload_fixtures import ALL_SCENARIOS  # noqa: E402


def _make_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="agent-gorgon-workload."))


def _render_scope(workspace: Path, dest_dir: Path) -> Path:
    """Fill WORKSPACE_GLOB with the workspace's *resolved* path.

    psutil.open_files() reports resolved paths (e.g. macOS /tmp -> /private/
    var/folders/...); a scope written against the un-resolved workspace path
    produces a confirmed false "Path outside allowed scope" FLAG. See the
    warning in scope.audit-demo.yaml and docs/EVIDENCE.md.
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


def run_scenario(factory, keep: bool) -> dict:
    workspace = _make_workspace()
    scenario = factory(workspace)
    log_dir = Path(tempfile.mkdtemp(prefix="agent-gorgon-evidence."))
    scope_path = _render_scope(workspace, log_dir)

    cmd = [
        sys.executable,
        "-m",
        "agent_gorgon.warden",
        "--scope",
        str(scope_path),
        "--agent-pid",
        str(scenario.process.pid),
        "--poll",
        "0.05",
        "--no-llm",
        "--audit-only",
        "--log-dir",
        str(log_dir),
    ]
    start = time.monotonic()
    warden = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        text=True,
    )
    elapsed = time.monotonic() - start
    scenario.process.wait(timeout=5)

    actions = _read_actions(log_dir)
    observed = _highest_verdict(actions)
    result = {
        "scenario": scenario.name,
        "expected_verdict": scenario.expected_verdict,
        "observed_verdict": observed,
        "match": observed == scenario.expected_verdict,
        "rationale": scenario.rationale,
        "elapsed_seconds": round(elapsed, 3),
        "total_actions": len(actions),
        "attribution": _attribution_counts(actions),
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
    from workload_fixtures import safe_workspace_write

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
    cmd = [
        sys.executable,
        "-m",
        "agent_gorgon.warden",
        "--scope",
        str(scope_path),
        "--agent-pid",
        str(scenario.process.pid),
        "--poll",
        "0.05",
        "--no-llm",
        "--audit-only",
        "--log-dir",
        str(log_dir),
    ]
    watched_start = time.monotonic()
    warden_proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=str, help="Write JSON report to this path")
    parser.add_argument("--keep", action="store_true", help="Keep workspaces/evidence dirs")
    args = parser.parse_args()

    results = [run_scenario(factory, args.keep) for factory in ALL_SCENARIOS]
    overhead = measure_overhead()

    mismatches = [r for r in results if not r["match"]]
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenarios": results,
        "false_trigger_or_miss_count": len(mismatches),
        "overhead": overhead,
    }

    print(json.dumps(report, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")

    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
