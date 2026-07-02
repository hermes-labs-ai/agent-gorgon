"""Regression tests: the warden must not SIGKILL ordinary developer work.

Two trigger-happy spots were fixed:
  1. Rate-limit exceeded → FLAG (record + raise posture), never KILL.
  2. `rm -rf` → KILL only when targeting a PROTECTED root (/, home, or a scope
     forbidden_path). Recursive deletes of project dirs (node_modules, build/,
     dist, .venv, __pycache__) must NOT be killed.

Genuinely-critical kills (`rm -rf /`, `rm -rf ~`, forbidden-path rm) must survive.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import datetime, timezone

from suy_sideguy.warden import (
    ActionType,
    AgentAction,
    Verdict,
    Warden,
)


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
  flag_window: 300
  max_actions_per_minute: 60
"""


def _scope_file() -> str:
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        f.write(SCOPE_YAML)
        return f.name


def _warden() -> Warden:
    return Warden(scope_path=_scope_file(), agent_pid=os.getpid(), poll_interval=0.01)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exec(cmd: str) -> AgentAction:
    return AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target=cmd,
    )


# ── (a) rate-limit burst does NOT kill ───────────────────────────────────────

def test_burst_of_file_opens_over_limit_does_not_kill(monkeypatch):
    """A burst of >max_actions_per_minute opens (a normal compile/test/install)
    must FLAG, never KILL."""
    w = _warden()
    now = 500.0
    monkeypatch.setattr("time.time", lambda: now)
    # 90 opens in the last minute against a 60/min limit — an ordinary build.
    w.action_timestamps = [now - 0.1] * (w.scope.max_actions_per_minute + 30)
    v = w._check_rate_limit()
    assert v is not None
    assert v.verdict == Verdict.FLAG
    assert w.killed is False


def test_rate_within_limit_returns_none():
    w = _warden()
    w.action_timestamps = [0.0] * (w.scope.max_actions_per_minute)  # exactly at limit
    assert w._check_rate_limit() is None


# ── (b) recursive rm of non-protected project dirs does NOT kill ──────────────

def test_rm_rf_project_dirs_do_not_kill():
    w = _warden()
    w.judge.available = False
    for cmd in (
        "rm -rf node_modules",
        "rm -rf build/",
        "rm -rf dist",
        "rm -rf .venv",
        "rm -rf __pycache__",
        "rm -rf ./build ./dist",
        "rm -fr target",
    ):
        assert w._check_hardcoded_kill(_exec(cmd)) is None, cmd
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict != Verdict.KILL, cmd


# ── (c) protected-root recursive rm STILL kills ───────────────────────────────

def test_rm_rf_filesystem_root_kills():
    w = _warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_exec("rm -rf /")))
    assert v.verdict == Verdict.KILL
    assert "protected root" in v.reason.lower()


def test_rm_rf_home_kills():
    w = _warden()
    w.judge.available = False
    for cmd in ("rm -rf ~", "rm -rf $HOME", "rm -rf ~/"):
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict == Verdict.KILL, cmd


def test_rm_rf_forbidden_scope_path_kills():
    w = _warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_exec("rm -rf /tmp/secret/token.txt")))
    assert v.verdict == Verdict.KILL


def test_non_recursive_rm_of_protected_root_is_not_this_kill():
    """The heuristic is scoped to RECURSIVE rm. A non-recursive `rm /file`
    is not caught by this rule (it is not a recursive-tree wipe)."""
    w = _warden()
    assert w._rm_rf_protected_target("rm /some/file") is None


def test_word_containing_rm_is_not_treated_as_rm():
    """Tokenized, not substring-matched: 'confirm -rf x' is not an rm."""
    w = _warden()
    assert w._rm_rf_protected_target("confirm -rf /") is None
