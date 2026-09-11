"""Tests for `agent-gorgon run` -- launch a command and watch its own tree.

Platform note: the wrapper is POSIX-oriented and its observation fidelity
(process groups, signal relay, psutil.open_files visibility) is what CI
exercises on Linux. These tests are skipped elsewhere, matching the support
boundary in README.md.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import psutil
import pytest

from agent_warden.run_command import split_argv, summary_line

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="process-group relay and open_files attribution are validated on Linux CI only",
)

RUN_TIMEOUT = 60


def _scope(tmp_path: Path) -> Path:
    """A scope that allows only `tmp_path/work`, so reads elsewhere FLAG."""
    workspace = tmp_path / "work"
    workspace.mkdir(exist_ok=True)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        textwrap.dedent(
            f"""
            agent:
              name: "run-wrapper-test"
            filesystem:
              allowed_paths:
                - "{workspace.resolve()}/**"
              forbidden_paths:
                - "{(tmp_path / 'forbidden').resolve()}/**"
              forbidden_extensions:
                - ".pem"
            network:
              allowed_domains:
                - "localhost"
              allowed_ports:
                - 443
            process:
              allowed_commands:
                - "python3"
            behavior:
              flag_threshold: 50
              max_actions_per_minute: 500
            """
        ).strip()
        + "\n"
    )
    return scope_path


def _run(
    tmp_path: Path,
    command: list[str],
    *,
    extra: list[str] | None = None,
    scope: Path | None = None,
    timeout: int = RUN_TIMEOUT,
) -> subprocess.CompletedProcess:
    evidence = tmp_path / "evidence.jsonl"
    argv = [
        sys.executable,
        "-m",
        "agent_gorgon.warden",
        "run",
        "--scope",
        str(scope if scope is not None else _scope(tmp_path)),
        "--no-llm",
        "--poll",
        "0.05",
        "--log-dir",
        str(tmp_path / "logdir"),
        "--out",
        str(evidence),
        *(extra or []),
        "--",
        *command,
    ]
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )


def _entries(tmp_path: Path) -> list[dict]:
    evidence = tmp_path / "evidence.jsonl"
    if not evidence.exists():
        return []
    return [json.loads(line) for line in evidence.read_text().splitlines() if line.strip()]


def test_split_argv_separates_watcher_options_from_the_command() -> None:
    assert split_argv(["--poll", "1", "--", "claude", "--verbose"]) == (
        ["--poll", "1"],
        ["claude", "--verbose"],
    )
    assert split_argv(["--audit-only"]) == (["--audit-only"], [])
    # An empty command after `--` stays empty so main() can reject it.
    assert split_argv(["--"]) == ([], [])


def test_exit_code_is_forwarded(tmp_path: Path) -> None:
    result = _run(tmp_path, [sys.executable, "-c", "raise SystemExit(7)"])
    assert result.returncode == 7, result.stderr
    assert "agent-gorgon run: " in result.stderr


def test_zero_exit_and_summary_line(tmp_path: Path) -> None:
    result = _run(tmp_path, [sys.executable, "-c", "pass"])
    assert result.returncode == 0, result.stderr
    summary = [line for line in result.stderr.splitlines() if line.startswith("agent-gorgon run: ")]
    assert summary, result.stderr
    assert "mode=audit-only" in summary[-1]
    assert "would-halt=" in summary[-1]
    assert "would-kill=" in summary[-1]
    assert str(tmp_path / "evidence.jsonl") in summary[-1]


def test_child_stdout_reaches_the_terminal(tmp_path: Path) -> None:
    result = _run(tmp_path, [sys.executable, "-c", "print('from-the-agent')"])
    assert result.returncode == 0, result.stderr
    # The watcher's own output goes to stderr so the command owns stdout.
    assert result.stdout.strip() == "from-the-agent"


def test_out_of_workspace_read_is_flagged_in_audit_only(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "notes.txt"
    secret.write_text("out of scope\n")
    script = textwrap.dedent(
        f"""
        import time
        handle = open({str(secret)!r})
        handle.read()
        time.sleep(1.0)
        handle.close()
        """
    )
    result = _run(tmp_path, [sys.executable, "-c", script])
    assert result.returncode == 0, result.stderr

    entries = _entries(tmp_path)
    reads = [
        entry
        for entry in entries
        if entry["action"]["action_type"] == "file_read"
        and entry["action"]["target"] == str(secret)
    ]
    assert reads, entries
    assert reads[0]["verdict"] == "FLAG"
    # Audit-only is the default: every entry is recorded without signalling.
    assert {entry["control_mode"] for entry in entries} == {"audit_only"}


def test_in_workspace_work_is_not_flagged(tmp_path: Path) -> None:
    target = tmp_path / "work" / "ok.txt"
    script = textwrap.dedent(
        f"""
        import time
        handle = open({str(target)!r}, "w")
        handle.write("in scope")
        handle.flush()
        time.sleep(1.0)
        handle.close()
        """
    )
    result = _run(tmp_path, [sys.executable, "-c", script])
    assert result.returncode == 0, result.stderr
    noisy = [
        entry
        for entry in _entries(tmp_path)
        if entry["verdict"] != "SAFE" and entry["action"]["target"] == str(target)
    ]
    assert noisy == []


def test_inherited_stdio_is_not_attributed_to_the_command(tmp_path: Path) -> None:
    """`agent-gorgon run ... > log.txt` must not report the operator's own log."""
    log_path = tmp_path / "outside-log.txt"
    scope = _scope(tmp_path)
    evidence = tmp_path / "evidence.jsonl"
    argv = [
        sys.executable,
        "-m",
        "agent_gorgon.warden",
        "run",
        "--scope",
        str(scope),
        "--no-llm",
        "--poll",
        "0.05",
        "--log-dir",
        str(tmp_path / "logdir"),
        "--out",
        str(evidence),
        "--",
        sys.executable,
        "-c",
        "import time; print('working'); time.sleep(1.0)",
    ]
    with open(log_path, "w") as handle:
        result = subprocess.run(
            argv, stdout=handle, stderr=subprocess.PIPE, text=True,
            timeout=RUN_TIMEOUT, check=False,
        )
    assert result.returncode == 0, result.stderr
    blamed = [
        entry
        for entry in _entries(tmp_path)
        if entry["action"]["target"] == str(log_path)
    ]
    assert blamed == [], blamed


def test_sigterm_is_relayed_and_leaves_no_stopped_child(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    argv = [
        sys.executable,
        "-m",
        "agent_gorgon.warden",
        "run",
        "--scope",
        str(scope),
        "--no-llm",
        "--poll",
        "0.05",
        "--log-dir",
        str(tmp_path / "logdir"),
        "--shutdown-grace",
        "15",
        "--",
        sys.executable,
        "-c",
        "import time; time.sleep(120)",
    ]
    wrapper = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        watched_pid = _watched_pid(wrapper)
        assert watched_pid is not None
        wrapper.send_signal(signal.SIGTERM)
        stdout, stderr = wrapper.communicate(timeout=RUN_TIMEOUT)
    finally:
        if wrapper.poll() is None:  # pragma: no cover - only on an unexpected hang
            wrapper.kill()
            wrapper.communicate()

    assert "relaying to the watched command" in stderr, stderr
    # 128 + SIGTERM: the command died from the relayed signal, not from the watcher.
    assert wrapper.returncode == 128 + int(signal.SIGTERM), stderr
    assert not _process_alive(watched_pid), "the watched command outlived the relay"
    assert stdout is not None


def test_missing_command_reports_127(tmp_path: Path) -> None:
    result = _run(tmp_path, ["definitely-not-a-real-binary-9f3a"])
    assert result.returncode == 127, result.stderr
    assert "command not found" in result.stderr


def test_command_is_required_after_the_separator(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable, "-m", "agent_gorgon.warden", "run",
            "--scope", str(_scope(tmp_path)), "--no-llm",
        ],
        capture_output=True, text=True, timeout=RUN_TIMEOUT, check=False,
    )
    assert result.returncode == 2
    assert "after '--'" in result.stderr


def test_invalid_scope_is_rejected_before_the_command_runs(tmp_path: Path) -> None:
    bad_scope = tmp_path / "bad.yaml"
    bad_scope.write_text("allow_read:\n  - \"/tmp/**\"\n")
    marker = tmp_path / "the-command-ran"
    result = _run(
        tmp_path,
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ran')"],
        scope=bad_scope,
    )
    assert result.returncode == 2, result.stderr
    assert not marker.exists(), "the command must not run when the scope is unusable"


def test_run_help_is_reachable() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "agent_gorgon.warden", "run", "--help"],
        capture_output=True, text=True, timeout=RUN_TIMEOUT, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "agent-gorgon run" in result.stdout
    assert "--enforce" in result.stdout


def test_summary_line_labels_enforce_mode_without_the_would_prefix() -> None:
    class _Recorded:
        def __init__(self, verdict: object) -> None:
            self.verdict = verdict

    from agent_warden.warden import Verdict

    class _FakeWarden:
        audit_only = False
        all_verdicts = [_Recorded(Verdict.FLAG), _Recorded(Verdict.KILL)]

    line = summary_line(_FakeWarden(), Path("/tmp/evidence.jsonl"), 0)  # type: ignore[arg-type]
    assert "mode=enforce" in line
    assert " halt=0 " in line
    assert " kill=1 " in line
    assert "would-" not in line


def _watched_pid(wrapper: subprocess.Popen, timeout: float = 30.0) -> int | None:
    """Read the watched PID out of the watcher's startup log on stderr."""
    deadline = time.monotonic() + timeout
    assert wrapper.stderr is not None
    while time.monotonic() < deadline:
        line = wrapper.stderr.readline()
        if not line:
            if wrapper.poll() is not None:
                return None
            continue
        if "   PID: " in line:
            return int(line.rsplit("PID: ", 1)[1].strip())
    return None


def _process_alive(pid: int) -> bool:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            process = psutil.Process(pid)
            if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                return False
            if process.status() == psutil.STATUS_STOPPED:
                return True
        except psutil.NoSuchProcess:
            return False
        time.sleep(0.1)
    return True


def test_os_setpgrp_is_available_for_the_wrapper() -> None:
    """The relay depends on the command owning its own process group."""
    assert hasattr(os, "setpgrp")
    assert hasattr(os, "killpg")
