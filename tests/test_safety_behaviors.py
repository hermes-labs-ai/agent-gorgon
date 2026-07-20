import asyncio
import logging
import os
import tempfile
from datetime import datetime, timezone

from agent_warden.warden import (
    ActionType,
    AgentAction,
    IncidentLogger,
    Verdict,
    Warden,
    WardenVerdict,
)


SCOPE_YAML = """
filesystem:
  allowed_paths:
    - "/tmp/safe/**"
  forbidden_paths:
    - "/tmp/secret/**"
  forbidden_extensions:
    - ".pem"
network:
  allowed_domains:
    - "example.com"
  forbidden_domains:
    - "evil.com"
  allowed_ports: [443]
process:
  allowed_commands: ["python3"]
  forbidden_commands: ["curl"]
behavior:
  flag_threshold: 3
  flag_window: 60
  max_actions_per_minute: 200
"""


def _scope_file() -> str:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(SCOPE_YAML)
        return f.name


def _warden() -> Warden:
    return Warden(scope_path=_scope_file(), agent_pid=os.getpid(), poll_interval=0.01)


def _flag_verdict() -> WardenVerdict:
    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.UNKNOWN,
        target="x",
    )
    return WardenVerdict(verdict=Verdict.FLAG, reason="flag", action=action, evaluator="test")


def test_flag_escalation_disabled_by_default(monkeypatch):
    monkeypatch.delenv("WARDEN_KILL_ON_FLAGS", raising=False)
    w = _warden()
    w.flag_timestamps = [1.0, 2.0, 3.0]
    assert w._check_flag_accumulation() is None


def test_flag_escalation_kills_when_enabled(monkeypatch):
    monkeypatch.setenv("WARDEN_KILL_ON_FLAGS", "1")
    w = _warden()
    now = 1000.0
    w.flag_timestamps = [now - 10, now - 5, now - 1]
    monkeypatch.setattr("time.time", lambda: now)
    v = w._check_flag_accumulation()
    assert v is not None
    assert v.verdict == Verdict.KILL
    assert "Flag accumulation" in v.reason


def test_kill_trigger_on_forbidden_path():
    w = _warden()
    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_READ,
        target="/tmp/secret/token.txt",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.KILL
    assert "forbidden path" in v.reason.lower()


def test_execute_kill_path_without_real_kill(monkeypatch, tmp_path):
    w = Warden(scope_path=_scope_file(), agent_pid=os.getpid(), log_dir=str(tmp_path / "logs"))
    v = _flag_verdict()
    v.verdict = Verdict.KILL
    v.reason = "test kill"

    monkeypatch.setattr(w.killswitch, "kill_agent", lambda: {"killed": True, "pids_terminated": [123], "errors": []})
    monkeypatch.setattr(w.killswitch, "attempt_rollback", lambda action: {"attempted": True, "success": True, "details": "mock"})

    asyncio.run(w.execute_kill(v))
    assert w.killed is True
    incidents = list((tmp_path / "logs" / "incidents").glob("*.json"))
    assert incidents, "incident report should be generated"


def test_custom_log_dir_contains_runtime_and_evidence_logs(tmp_path):
    custom = tmp_path / "private-evidence"
    w = Warden(scope_path=_scope_file(), agent_pid=os.getpid(), log_dir=str(custom))

    assert w.runtime_log_path == custom / "warden.log"
    assert w.logger.action_log_path.parent == custom
    assert w.logger.incident_dir == custom / "incidents"


def test_runtime_log_routing_ignores_root_handlers_and_isolates_wardens(tmp_path):
    """Each Warden owns the requested runtime log even in an embedding process."""
    root_logger = logging.getLogger()
    embedding_handler = logging.NullHandler()
    root_logger.addHandler(embedding_handler)
    wardens = []
    try:
        for name in ("first", "second"):
            wardens.append(
                Warden(
                    scope_path=_scope_file(),
                    agent_pid=os.getpid(),
                    log_dir=str(tmp_path / name),
                )
            )

        wardens[0].log.info("first-runtime-marker")
        wardens[1].log.info("second-runtime-marker")
        for warden in wardens:
            for handler in warden.log.handlers:
                handler.flush()

        first_log = wardens[0].runtime_log_path.read_text(encoding="utf-8")
        second_log = wardens[1].runtime_log_path.read_text(encoding="utf-8")
        assert "first-runtime-marker" in first_log
        assert "second-runtime-marker" not in first_log
        assert "second-runtime-marker" in second_log
        assert "first-runtime-marker" not in second_log
    finally:
        root_logger.removeHandler(embedding_handler)
        for warden in wardens:
            for handler in list(warden.log.handlers):
                handler.close()
                warden.log.removeHandler(handler)


def test_failed_kill_attempt_remains_retryable_and_report_is_truthful(monkeypatch, tmp_path):
    w = Warden(scope_path=_scope_file(), agent_pid=os.getpid(), log_dir=str(tmp_path / "logs"))
    v = _flag_verdict()
    v.verdict = Verdict.KILL
    v.reason = "test failed kill"

    monkeypatch.setattr(
        w.killswitch,
        "kill_agent",
        lambda: {"killed": False, "pids_terminated": [], "errors": ["denied"]},
    )
    monkeypatch.setattr(
        w.killswitch,
        "attempt_rollback",
        lambda action: {"attempted": False, "success": False, "details": "not applicable"},
    )

    asyncio.run(w.execute_kill(v))

    assert w.killed is False
    incidents = list((tmp_path / "logs" / "incidents").glob("*.json"))
    assert len(incidents) == 1

    import json

    report = json.loads(incidents[0].read_text(encoding="utf-8"))
    assert report["incident_report"]["status"] == "TERMINATION_FAILED"
    assert report["liability_statement"]["agent_process_terminated"] is False
    assert report["liability_statement"]["termination_method"] == "SIGKILL_ATTEMPTED"
    assert report["liability_statement"]["rollback_attempted"] is False
    assert report["kill_execution"]["errors"] == ["denied"]


def test_llm_unavailable_fallback_path():
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.NETWORK_OUT,
        target="8.8.8.8:443",
        details={"remote_ip": "8.8.8.8", "remote_port": 443},
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.FLAG
    assert "LLM unavailable" in v.reason


def test_incident_report_schema_core_fields(tmp_path):
    logger = IncidentLogger(log_dir=str(tmp_path))
    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.FILE_WRITE,
        target="/tmp/demo.txt",
    )
    kill_v = WardenVerdict(verdict=Verdict.KILL, reason="x", action=action, evaluator="rule_engine")
    report_path = logger.generate_incident_report(
        kill_v,
        [kill_v, _flag_verdict()],
        {"killed": True, "pids_terminated": [123], "errors": []},
    )

    import json

    report = json.loads(open(report_path, "r", encoding="utf-8").read())
    assert "incident_report" in report
    assert "kill_trigger" in report
    assert "session_summary" in report
    assert "liability_statement" in report
    assert report["kill_trigger"]["action_type"] == ActionType.FILE_WRITE.value
    assert report["incident_report"]["generator"] == "Agent Warden v0.1.5"
    assert report["incident_report"]["status"] == "AGENT_TERMINATED"


def test_rate_limit_flags_not_kills_when_exceeded(monkeypatch):
    # A rate spike is a signal, not proof of harm: FLAG (record + raise posture),
    # never SIGKILL. Ordinary builds routinely open >max_actions_per_minute files.
    w = _warden()
    now = 100.0
    monkeypatch.setattr("time.time", lambda: now)
    w.action_timestamps = [now - 1] * (w.scope.max_actions_per_minute + 1)
    v = w._check_rate_limit()
    assert v is not None
    assert v.verdict == Verdict.FLAG
    assert v.verdict != Verdict.KILL


def test_rate_limit_flag_never_arms_opt_in_kill_accumulator(monkeypatch):
    """Exercise the behavioral-check loop, not only the rate check in isolation."""
    monkeypatch.setenv("WARDEN_KILL_ON_FLAGS", "1")
    w = _warden()
    now = 100.0
    monkeypatch.setattr("time.time", lambda: now)
    w.scope.flag_threshold = 1
    w.action_timestamps = [now - 1] * (w.scope.max_actions_per_minute + 1)

    alive = iter((True, False))
    monkeypatch.setattr(w.observer, "is_agent_alive", lambda: next(alive))
    monkeypatch.setattr(w.observer, "observe", lambda: [])
    kill_calls = []

    async def fake_execute_kill(verdict):
        kill_calls.append(verdict)
        w.killed = True

    monkeypatch.setattr(w, "execute_kill", fake_execute_kill)

    asyncio.run(w.run())

    assert kill_calls == []
    assert w.flag_timestamps == []


def test_llm_unavailable_for_unknown_command_flags():
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type=ActionType.PROCESS_EXEC,
        target="unknowncmd --x",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.FLAG
    assert "Unknown command" in v.reason
