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

from agent_warden.warden import (
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


# A realistic scope whose forbidden_paths are CONTENTS globs of credential dirs,
# mirroring examples/scope.*.yaml. Regression guard: deleting the credential
# DIRECTORY itself (or an ancestor of it) must KILL, even though the glob only
# literally matches the dir's *contents*.
CRED_SCOPE_YAML = """
filesystem:
  allowed_paths:
    - "/tmp/safe/**"
  forbidden_paths:
    - "~/.ssh/**"
    - "~/.gnupg/**"
    - "~/.aws/**"
process:
  allowed_commands: ["python3"]
behavior:
  max_actions_per_minute: 60
"""


def _cred_warden() -> Warden:
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        f.write(CRED_SCOPE_YAML)
        path = f.name
    w = Warden(scope_path=path, agent_pid=os.getpid(), poll_interval=0.01)
    w.judge.available = False
    return w


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


def test_shell_wrapped_rm_rf_protected_roots_kill():
    w = _warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf /'",
        "sh -c 'rm -rf /*'",
        "/bin/sh -c 'rm -rf /'",
        "bash -lc 'rm -rf ~'",
        "bash -lc 'rm -rf ~/*'",
        "zsh -c 'rm -rf /tmp/secret/token.txt'",
    ):
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict == Verdict.KILL, cmd


def test_shell_wrapped_home_parameter_and_dot_glob_kill():
    """Shell-expanded home-root forms cannot bypass the protected-root rule."""
    w = _warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf ${HOME:?}/'",
        "sh -c 'rm -rf ${HOME:-/}'",
        "sh -c 'rm -rf ${HOME-/}'",
        "sh -c 'rm -rf ${HOME:-/tmp/project}'",
        "sh -c 'rm -rf ~/.*'",
    ):
        assert w._rm_rf_protected_target(cmd) is not None, cmd
        assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict == Verdict.KILL, cmd


def test_shell_prefixes_and_home_descendants_cannot_hide_protected_delete():
    """Exact material acceptance-review reproducers must all KILL."""
    w = _cred_warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'VAR=1 rm -rf --no-preserve-root /'",
        "sh -c 'exec rm -rf ~/.ssh'",
        "sh -c 'rm -rf ${HOME:?}/.ssh'",
        "sh -c 'rm -rf \"${HOME:?}\"/.ssh'",
    ):
        assert w._rm_rf_protected_target(cmd) is not None, cmd
        assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict == Verdict.KILL, cmd


def test_shell_compound_commands_cannot_hide_protected_root_delete():
    """Unquoted shell operators terminate commands; they are not path bytes."""
    w = _warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf --no-preserve-root /; echo ok'",
        "bash -lc 'echo start && rm -fr ~/* || true'",
        "zsh -c 'printf ok | rm -Rf /*'",
        "sh -c 'echo start\nrm -rf /'",
    ):
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict == Verdict.KILL, cmd


def test_shell_control_structures_with_protected_rm_halt_reversibly():
    """Unreduced control syntax must HALT, never fall SAFE or speculate KILL."""
    w = _cred_warden()
    w.scope.allowed_commands.extend(["bash", "sh", "zsh"])
    w.judge.available = False
    for cmd in (
        "sh -c 'if true; then rm -rf /; fi'",
        "bash -c 'while true; do rm -rf /; done'",
        "zsh -c 'if true; then rm -rf ~/.ssh; fi'",
    ):
        assert w._rm_rf_protected_target(cmd) is None, cmd
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "uncertain compound shell recursive rm" in verdict.reason.lower(), cmd


def test_shell_control_structures_with_benign_cleanup_do_not_halt():
    """Matched compound cleanup of literal project paths stays confidently benign."""
    w = _warden()
    w.scope.allowed_commands.extend(["bash", "sh", "zsh"])
    w.judge.available = False
    for cmd in (
        "sh -c 'if true; then rm -rf build; fi'",
        "bash -c 'while false; do rm -rf .venv; done'",
        "zsh -c 'if true; then rm -rf ~/project; fi'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.SAFE, cmd
        assert "uncertain compound" not in verdict.reason.lower(), cmd


def test_quoted_and_echoed_rm_text_is_not_enforcement_evidence():
    """Rendered rm text is data, not a destructive command."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False
    for cmd in (
        "sh -c 'echo rm -rf /'",
        "sh -c 'echo \"rm -rf /\"'",
        "sh -c 'printf \"%s\\n\" \"rm -rf /\"'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.SAFE, cmd
        assert "uncertain compound" not in verdict.reason.lower(), cmd


def test_dynamic_recursive_rm_in_shell_payload_halts_reversibly():
    """An unresolved target cannot silently acquire either SAFE or KILL."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False
    verdict = asyncio.run(w.evaluate_action(_exec("sh -c 'rm -rf \"$TARGET\"'")))
    assert verdict.verdict == Verdict.HALT
    assert "unresolved shell expansion" in verdict.reason.lower()


def test_quoted_shell_operator_byte_remains_part_of_path():
    """A quoted semicolon is data, not a command separator or filesystem root."""
    w = _warden()
    w.judge.available = False
    cmd = 'sh -c "rm -rf \'/;\'"'
    assert w._rm_rf_protected_target(cmd) is None
    assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict != Verdict.KILL


def test_shell_wrapped_rm_rf_project_dirs_do_not_kill():
    w = _warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf build'",
        "bash -lc 'rm -rf .venv'",
        "sh -c 'rm -rf build/*'",
        "bash -lc 'rm -rf ~/project/*'",
    ):
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict != Verdict.KILL, cmd


def test_shell_home_lookalikes_remain_project_scoped():
    """The shell-form protection must not turn ordinary project cleanup fatal."""
    w = _warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf ~/project/.*'",
        "sh -c 'rm -rf ${HOME_DIR:?}/'",
    ):
        assert w._rm_rf_protected_target(cmd) is None, cmd
        assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict != Verdict.KILL, cmd


def test_shell_prefix_and_home_descendant_project_controls_do_not_kill():
    """Prefix normalization must preserve ordinary project cleanup behavior."""
    w = _cred_warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'VAR=1 rm -rf build'",
        "sh -c 'exec rm -rf ~/project'",
        "sh -c 'command rm -rf ~/project'",
        "sh -c 'rm -rf ${HOME:?}/project'",
        "sh -c 'BAD-NAME=1 rm -rf /'",
        "sh -c 'command -v rm'",
    ):
        assert w._rm_rf_protected_target(cmd) is None, cmd
        assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict != Verdict.KILL, cmd


def test_shell_positional_args_are_not_reinterpreted_as_rm_targets():
    """Only the one argv item after -c is executable shell text.

    A later '/' is shell $0/$1 data, not an rm operand, and must not create a
    false-positive SIGKILL for a benign project cleanup.
    """
    w = _warden()
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf build' /",
        "bash -lc 'rm -rf .venv' / --extra",
        "sh -c rm -rf /",
    ):
        assert w._rm_rf_protected_target(cmd) is None, cmd
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict != Verdict.KILL, cmd


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


# ── (c') recursive rm of a credential DIRECTORY still kills ────────────────────
# Regression: a `~/.ssh/**` contents-glob must also protect the ~/.ssh directory
# itself and any ancestor that contains it. Deleting the whole dir is at least as
# dangerous as deleting its contents. (Introduced-and-fixed in this branch.)

def test_rm_rf_credential_directories_kill():
    w = _cred_warden()
    for cmd in ("rm -rf ~/.ssh", "rm -rf ~/.aws", "rm -rf ~/.gnupg",
                "rm -rf ~/.ssh/"):
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict == Verdict.KILL, cmd
        assert w._rm_rf_protected_target(cmd) is not None, cmd


def test_rm_rf_home_ancestor_of_credentials_kills():
    """`rm -rf ~` deletes a directory that CONTAINS ~/.ssh — must KILL."""
    w = _cred_warden()
    v = asyncio.run(w.evaluate_action(_exec("rm -rf ~")))
    assert v.verdict == Verdict.KILL


def test_rm_rf_project_dirs_still_survive_under_credential_scope():
    """The ancestor/descendant match must NOT over-fire on unrelated project
    dirs when credential globs are present."""
    w = _cred_warden()
    for cmd in ("rm -rf node_modules", "rm -rf build/", "rm -rf dist",
                "rm -rf .venv", "rm -rf __pycache__"):
        assert w._rm_rf_protected_target(cmd) is None, cmd
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict != Verdict.KILL, cmd


def test_shell_home_prefix_glob_intersects_credential_root():
    """A shell operand glob that includes ~/.ssh cannot evade protection."""
    w = _cred_warden()
    cmd = "sh -c 'rm -rf ~/.ssh*'"
    assert w._rm_rf_protected_target(cmd) is not None
    assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict == Verdict.KILL


def test_internal_forbidden_glob_does_not_collapse_to_literal_prefix(tmp_path):
    """An internal wildcard protects its matches, not every prefix sibling."""
    w = _warden()
    w.judge.available = False
    w.scope.forbidden_paths = [str(tmp_path / "*" / "secret" / "**")]
    unrelated = tmp_path / "build"
    unrelated.mkdir()

    cmd = f"rm -rf {unrelated}"
    assert w._rm_rf_protected_target(cmd) is None
    assert asyncio.run(w.evaluate_action(_exec(cmd))).verdict != Verdict.KILL


def test_internal_forbidden_glob_intersection_table(tmp_path):
    """Table-driven controls cover exact, descendant, ancestor, and siblings."""
    w = _warden()
    w.judge.available = False
    w.scope.forbidden_paths = [str(tmp_path / "*" / "secret" / "**")]

    protected = tmp_path / "job" / "secret"
    protected.mkdir(parents=True)
    (protected / "token").write_text("secret", encoding="utf-8")
    unrelated = tmp_path / "build"
    unrelated.mkdir()
    nested_but_not_matched = tmp_path / "nested" / "job" / "secret"
    nested_but_not_matched.mkdir(parents=True)

    cases = (
        (protected, True),
        (protected / "token", True),
        (protected.parent, True),
        (tmp_path / "*" / "secret*", True),
        (unrelated, False),
        (tmp_path / "job" / "public", False),
        (nested_but_not_matched, False),
    )
    for target, should_kill in cases:
        cmd = f"rm -rf {target}"
        matched = w._rm_rf_protected_target(cmd) is not None
        assert matched is should_kill, cmd
        verdict = asyncio.run(w.evaluate_action(_exec(cmd))).verdict
        assert (verdict == Verdict.KILL) is should_kill, cmd
