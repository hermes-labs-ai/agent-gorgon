"""Publication-blocking safety regressions for the runtime guard."""

from __future__ import annotations

import argparse
import asyncio
import os
import stat
from datetime import datetime, timezone

import psutil
import pytest

from agent_warden.warden import (
    ActionType,
    AgentAction,
    IncidentLogger,
    Killswitch,
    Scope,
    Verdict,
    Warden,
    WardenVerdict,
    _positive_finite_float,
    find_process_by_name,
    resolve_scope_path,
)


VALID_SCOPE = """
filesystem:
  allowed_paths: ["/tmp/safe/**"]
  forbidden_paths: ["/tmp/secret/**"]
  forbidden_extensions: [".key"]
network:
  allowed_domains: ["example.com"]
  forbidden_domains: ["evil.example"]
  allowed_ports: [443]
process:
  allowed_commands: ["python3"]
  forbidden_commands: ["wget"]
behavior:
  flag_threshold: 5
  flag_window: 60
  max_actions_per_minute: 120
  credential_exfil_window: 15
"""


def _scope_file(tmp_path, text: str = VALID_SCOPE) -> str:
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    "replacement, message",
    [
        ('forbidden_extensions: [".key"]', "forbidden_extensions"),
        ("allowed_ports: 443", "allowed_ports"),
        ("flag_window: .inf", "flag_window"),
    ],
)
def test_scope_rejects_ambiguous_or_unbounded_values(tmp_path, replacement, message):
    text = VALID_SCOPE
    if replacement.startswith("forbidden_extensions"):
        text = text.replace('forbidden_extensions: [".key"]', "forbidden_extensions: .key")
    elif replacement.startswith("allowed_ports"):
        text = text.replace("allowed_ports: [443]", replacement)
    else:
        text = text.replace("flag_window: 60", replacement)
    with pytest.raises(ValueError, match=message):
        Scope(_scope_file(tmp_path, text))


def test_scope_rejects_unknown_keys(tmp_path):
    with pytest.raises(ValueError, match="Unknown"):
        Scope(_scope_file(tmp_path, VALID_SCOPE + "\nbehavior_extra: true\n"))


class _ListedProcess:
    def __init__(self, pid: int, name: str, exe: str, argv0: str | None = None):
        self.info = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": [argv0 or exe],
        }


def test_process_name_resolution_is_exact_unique_and_excludes_monitor(monkeypatch):
    class Current:
        def parents(self):
            return [type("Parent", (), {"pid": 50})()]

    monkeypatch.setattr(psutil, "Process", lambda _pid: Current())
    monkeypatch.setattr(
        psutil,
        "process_iter",
        lambda _attrs: iter([
            _ListedProcess(os.getpid(), "agent", "/bin/agent"),
            _ListedProcess(50, "agent", "/bin/agent"),
            _ListedProcess(101, "agent-helper", "/opt/agent-helper"),
            _ListedProcess(102, "agent", "/opt/agent"),
        ]),
    )
    assert find_process_by_name("agent") == 102
    with pytest.raises(ValueError, match="No process"):
        find_process_by_name("gent")

    monkeypatch.setattr(
        psutil,
        "process_iter",
        lambda _attrs: iter([
            _ListedProcess(102, "agent", "/opt/agent"),
            _ListedProcess(103, "other", "/usr/local/bin/agent"),
        ]),
    )
    with pytest.raises(ValueError, match="ambiguous"):
        find_process_by_name("agent")


def test_rollback_receipt_never_mutates_observed_file(tmp_path):
    target = tmp_path / "operator-data.txt"
    target.write_text("keep", encoding="utf-8")
    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_WRITE,
        target=str(target),
    )
    result = Killswitch(os.getpid()).attempt_rollback(action)
    assert result["attempted"] is False
    assert result["success"] is False
    assert target.read_text(encoding="utf-8") == "keep"


class _ControllableProcess:
    pid = 4000

    def __init__(self, create_time: float):
        self._create_time = create_time
        self.kill_calls = 0
        self.suspend_calls = 0
        self.status_value = psutil.STATUS_RUNNING
        self.wait_error = None

    def create_time(self):
        return self._create_time

    def children(self, recursive=True):
        assert recursive is True
        return []

    def kill(self):
        self.kill_calls += 1

    def wait(self, timeout):
        if self.wait_error:
            raise self.wait_error
        return 0

    def suspend(self):
        self.suspend_calls += 1

    def status(self):
        return self.status_value


def test_root_signal_refuses_pid_reuse(monkeypatch):
    original = _ControllableProcess(10.0)
    replacement = _ControllableProcess(20.0)
    current = {"proc": original}
    monkeypatch.setattr(psutil, "Process", lambda _pid: current["proc"])
    switch = Killswitch(4000)
    current["proc"] = replacement

    result = switch.kill_agent()

    assert result["killed"] is False
    assert replacement.kill_calls == 0
    assert "identity changed" in result["errors"][0]


def test_kill_and_suspend_report_only_confirmed_state(monkeypatch):
    proc = _ControllableProcess(10.0)
    monkeypatch.setattr(psutil, "Process", lambda _pid: proc)
    switch = Killswitch(4000)
    switch.CONTROL_CONFIRM_TIMEOUT = 0.01

    proc.wait_error = psutil.TimeoutExpired(0.01, pid=proc.pid)
    kill_result = switch.kill_agent()
    assert kill_result["killed"] is False
    assert kill_result["pids_terminated"] == []

    proc.wait_error = None
    suspend_result = switch.suspend_agent()
    assert suspend_result["suspended"] is False
    assert suspend_result["pids_suspended"] == []


def test_hard_ssh_rule_is_key_specific(tmp_path):
    warden = Warden(
        scope_path=_scope_file(tmp_path),
        agent_pid=os.getpid(),
        log_dir=str(tmp_path / "evidence"),
        enable_llm=False,
    )
    known_hosts = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_READ,
        target=os.path.expanduser("~/.ssh/known_hosts"),
    )
    authorized_keys = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_WRITE,
        target=os.path.expanduser("~/.ssh/authorized_keys"),
    )
    pem_key = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_READ,
        target="~/.ssh/deploy.pem",
    )
    workspace_pem = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_READ,
        target="/tmp/safe/server.pem",
    )
    unresolved_home_pem = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_READ,
        target="$HOME/.ssh/deploy.pem",
    )
    assert asyncio.run(warden.evaluate_action(known_hosts)).verdict != Verdict.KILL
    assert asyncio.run(warden.evaluate_action(authorized_keys)).verdict == Verdict.KILL
    assert asyncio.run(warden.evaluate_action(pem_key)).verdict == Verdict.KILL
    assert asyncio.run(warden.evaluate_action(workspace_pem)).verdict != Verdict.KILL
    assert asyncio.run(warden.evaluate_action(unresolved_home_pem)).verdict != Verdict.KILL


def test_evidence_directories_and_files_are_owner_only(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o755)
    logger = IncidentLogger(str(evidence))
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o700
    assert stat.S_IMODE(logger.incident_dir.stat().st_mode) == 0o700

    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.UNKNOWN,
        target="test",
    )
    verdict = WardenVerdict(Verdict.FLAG, "test", action, "test")
    logger.log_action(verdict)
    assert stat.S_IMODE(logger.action_log_path.stat().st_mode) == 0o600

    report = logger.generate_incident_report(verdict, [verdict])
    assert stat.S_IMODE(os.stat(report).st_mode) == 0o600

    warden = Warden(
        scope_path=_scope_file(tmp_path),
        agent_pid=os.getpid(),
        log_dir=str(evidence),
        enable_llm=False,
    )
    assert stat.S_IMODE(warden.runtime_log_path.stat().st_mode) == 0o600


def test_starter_scope_and_poll_validation():
    starter = resolve_scope_path("starter")
    assert starter.endswith("agent_warden/scopes/low-disruption.yaml")
    assert os.path.isfile(starter)
    assert _positive_finite_float("0.05") == 0.05
    for value in ("0", "-1", "nan", "inf"):
        with pytest.raises(argparse.ArgumentTypeError):
            _positive_finite_float(value)
