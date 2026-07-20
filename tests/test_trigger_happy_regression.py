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

import agent_warden.warden as warden_module
from agent_warden.warden import (
    ActionType,
    AgentAction,
    ProcessObserver,
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
    w = Warden(scope_path=_scope_file(), agent_pid=os.getpid(), poll_interval=0.01)
    project_cwd = os.getcwd()
    home_project = os.path.expanduser("~/project")
    w.scope.allowed_paths.extend([
        project_cwd,
        f"{project_cwd}/**",
        home_project,
        f"{home_project}/**",
    ])
    return w


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
    project_cwd = os.getcwd()
    home_project = os.path.expanduser("~/project")
    w.scope.allowed_paths.extend([
        project_cwd,
        f"{project_cwd}/**",
        home_project,
        f"{home_project}/**",
    ])
    w.judge.available = False
    return w


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exec(cmd: str) -> AgentAction:
    return AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target=cmd,
        details={"cwd": os.getcwd()},
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


def test_forbidden_wrapper_kill_preempts_recursive_rm_uncertainty_halt():
    """An explicit scope KILL must outrank the parser's reversible HALT."""
    w = _warden()
    w.scope.forbidden_commands = ["sudo"]
    w.judge.available = False

    verdict = asyncio.run(w.evaluate_action(_exec("sudo rm -rf /")))

    assert verdict.verdict == Verdict.KILL
    assert verdict.reason == "Forbidden command: sudo rm -rf /"


def test_unconfigured_wrapper_recursive_rm_uncertainty_still_halts():
    """The precedence rule must not promote unknown wrappers or weaken HALT."""
    w = _warden()
    w.scope.forbidden_commands = []
    w.judge.available = False

    verdict = asyncio.run(w.evaluate_action(_exec("sudo rm -rf /")))

    assert verdict.verdict == Verdict.HALT
    assert "uncertain compound shell recursive rm" in verdict.reason.lower()


def test_allowed_shell_cannot_delete_forbidden_extension_in_allowed_scope():
    """A process allowlist must not erase configured filesystem KILL rules."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.scope.forbidden_extensions = [".pem"]
    w.judge.available = False
    project = os.path.expanduser("~/project")

    forbidden = asyncio.run(
        w.evaluate_action(_exec(f"sh -c 'rm -rf {project}/key.pem'"))
    )
    benign = asyncio.run(
        w.evaluate_action(_exec(f"sh -c 'rm -rf {project}/cache.txt'"))
    )

    assert forbidden.verdict == Verdict.KILL
    assert "forbidden file type" in forbidden.reason.lower()
    assert benign.verdict == Verdict.SAFE


def test_allowed_shell_halts_out_of_scope_recursive_delete(
    monkeypatch, tmp_path
):
    """An allowed shell must not make an arbitrary filesystem target SAFE."""
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    documents = home / "Documents"
    home.mkdir()
    workspace.mkdir()
    documents.mkdir()
    monkeypatch.setenv("HOME", str(home))

    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.scope.allowed_paths = [f"{workspace}/**"]
    w.judge.available = False

    for cmd in (
        "sh -c 'rm -rf ~/Documents'",
        "sh -c 'rm -rf ~/Documents/build'",
        "sh -c 'rm -rf /etc/build'",
        "sh -c 'rm -rf /etc/project'",
    ):
        outside = AgentAction(
            timestamp=_now_iso(),
            action_type=ActionType.PROCESS_EXEC,
            target=cmd,
            details={"cwd": str(workspace)},
        )
        verdict = asyncio.run(w.evaluate_action(outside))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "outside allowed filesystem scope" in verdict.reason.lower(), cmd

    relative_outside = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c 'rm -rf build'",
        details={"cwd": "/etc"},
    )
    verdict = asyncio.run(w.evaluate_action(relative_outside))
    assert verdict.verdict == Verdict.HALT
    assert "outside allowed filesystem scope" in verdict.reason.lower()

    for cmd in (
        f"sh -c 'rm -rf {workspace}/cache'",
        "sh -c 'rm -rf build .venv node_modules'",
    ):
        action = AgentAction(
            timestamp=_now_iso(),
            action_type=ActionType.PROCESS_EXEC,
            target=cmd,
            details={"cwd": str(workspace)},
        )
        assert asyncio.run(w.evaluate_action(action)).verdict == Verdict.SAFE, cmd


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


def test_env_wrapped_protected_recursive_delete_cannot_bypass_kill():
    """An executable env wrapper must expose the command it launches."""
    w = _warden()
    w.judge.available = False
    for cmd in (
        "env rm -rf /",
        "env -- rm -rf /",
        "env FOO=bar rm -rf /",
        "env sh -c 'rm -rf /'",
        "sh -c 'env rm -rf /'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.KILL, cmd


def test_env_chdir_preserves_relative_delete_safety_and_project_cleanup(
    monkeypatch, tmp_path
):
    """env -C changes the effective cwd without making project cleanup fatal."""
    home = tmp_path / "home"
    project = tmp_path / "project"
    (home / ".ssh").mkdir(parents=True)
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    w = _cred_warden()
    w.scope.allowed_commands.extend(["env", "sh"])
    w.scope.allowed_paths.extend([str(project), f"{project}/**"])
    w.judge.available = False

    protected = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target=f"env -C {home} sh -c 'rm -rf .ssh'",
        details={"cwd": str(project)},
    )
    benign = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target=f"env --chdir={project} sh -c 'rm -rf build .venv'",
        details={"cwd": str(home)},
    )

    assert asyncio.run(w.evaluate_action(protected)).verdict == Verdict.KILL
    assert asyncio.run(w.evaluate_action(benign)).verdict == Verdict.SAFE


def test_uncertain_env_wrapper_halts_recursive_delete_reversibly():
    """Unsupported env option semantics cannot turn recursive rm SAFE or KILL."""
    w = _warden()
    w.scope.allowed_commands.extend(["env"])
    w.judge.available = False
    verdict = asyncio.run(w.evaluate_action(_exec("env --unknown rm -rf /")))
    assert verdict.verdict == Verdict.HALT
    assert "unsupported env wrapper option" in verdict.reason.lower()

    split_verdict = asyncio.run(w.evaluate_action(_exec("env -S 'rm -rf /'")))
    assert split_verdict.verdict == Verdict.HALT
    assert "split-string" in split_verdict.reason.lower()


def test_env_home_wrapper_preserves_home_independent_rm_decisions():
    """Exact HOME mutation cannot downgrade literal root or benign cleanup."""
    w = _warden()
    w.scope.allowed_commands.extend(["env", "sh"])
    w.judge.available = False

    for cmd in (
        "env HOME=/tmp rm -rf /",
        "env -u HOME rm -rf /",
        "env --unset=HOME sh -c 'rm -rf /'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.KILL, cmd

    for cmd in (
        "env HOME=/tmp rm -rf build",
        "env -u HOME sh -c 'rm -rf .venv'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.SAFE, cmd


def test_env_home_wrapper_keeps_home_dependent_target_reversible():
    """A changed HOME plus a HOME-derived operand remains uncertain, not KILL."""
    w = _cred_warden()
    w.scope.allowed_commands.extend(["env", "sh"])
    w.judge.available = False

    for cmd in (
        "env HOME=/tmp sh -c 'rm -rf $HOME/.ssh'",
        "env -u HOME sh -c 'rm -rf ${HOME:-/}'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "env wrapper" in verdict.reason.lower(), cmd


def test_unknown_execution_wrapper_with_recursive_rm_halts_not_flags():
    """A wrapper observed before exec cannot suppress all process control."""
    w = _warden()
    w.scope.allowed_commands.extend(["nice", "nohup"])
    w.judge.available = False
    for cmd in ("nice rm -rf /", "nohup rm -rf build"):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "execution wrapper" in verdict.reason.lower(), cmd


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


def test_shell_comments_do_not_become_recursive_delete_evidence():
    """Only unquoted, unescaped ``#`` at a shell token boundary starts a comment."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False

    safe_commands = (
        "sh -c '# rm -fr /'",
        "sh -c 'echo ok # rm -rf /'",
        "sh -c 'echo start\n# rm -rf /\necho end'",
        "sh -c 'rm -rf build # routine cleanup'",
    )
    for cmd in safe_commands:
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.SAFE, cmd
        assert "uncertain compound" not in verdict.reason.lower(), cmd

    # Quoted and escaped '#' bytes are real path data rather than comments.
    # Because these exact operands are outside the filesystem allowlist, they
    # pause reversibly instead of being confused with comment-only evidence.
    for cmd in (
        "sh -c \"rm -rf '/#'\"",
        r"sh -c 'rm -rf /\#'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "outside allowed filesystem scope" in verdict.reason.lower(), cmd

    kill_commands = (
        "sh -c 'rm -rf / # destructive command before comment'",
        "sh -c '# harmless comment\nrm -rf /'",
        "sh -c 'rm -rf /\n# trailing comment'",
        "sh -c \"echo '#'; rm -rf /\"",
        r"sh -c 'echo \#; rm -rf /'",
    )
    for cmd in kill_commands:
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.KILL, cmd


def test_nested_shell_and_eval_payloads_preserve_recursive_delete_enforcement():
    """Literal execution wrappers cannot hide rm, while data and cleanup stay benign."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False

    for cmd in (
        "sh -c 'eval \"rm -rf /\"'",
        "sh -c 'sh -c \"rm -rf /\"'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.KILL, cmd

    cred_warden = _cred_warden()
    cred_warden.scope.allowed_commands.extend(["sh"])
    for cmd in (
        "sh -c 'eval \"rm -rf $HOME/.ssh\"'",
        "sh -c 'sh -c \"rm -rf $HOME/.ssh\"'",
    ):
        verdict = asyncio.run(cred_warden.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.KILL, cmd

    dynamic = asyncio.run(
        w.evaluate_action(_exec("sh -c 'eval \"rm -rf \\\"$TARGET\\\"\"'"))
    )
    assert dynamic.verdict == Verdict.HALT

    assigned_dynamic = asyncio.run(
        w.evaluate_action(
            _exec("sh -c 'CMD=\"rm -rf /\"; eval \"$CMD\"'")
        )
    )
    assert assigned_dynamic.verdict == Verdict.HALT

    assigned_cleanup = asyncio.run(
        w.evaluate_action(
            _exec("sh -c 'CMD=\"rm -rf build\"; eval \"$CMD\"'")
        )
    )
    assert assigned_cleanup.verdict == Verdict.SAFE

    inert_assignment = asyncio.run(
        w.evaluate_action(
            _exec("sh -c 'CMD=\"rm -rf /\"; echo \"$CMD\"'")
        )
    )
    assert inert_assignment.verdict == Verdict.SAFE

    for cmd in (
        "sh -c 'eval \"rm -rf build\"'",
        "sh -c 'sh -c \"rm -rf build\"'",
        "sh -c 'eval \"echo rm -rf /\"'",
        "sh -c 'sh -c \"echo rm -rf /\"'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.SAFE, cmd


def test_assignment_prefixed_eval_cannot_hide_recursive_delete():
    """An eval-local assignment must be visible when eval parses its text."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False

    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c payload",
        details={
            "cwd": os.getcwd(),
            "argv": ["sh", "-c", 'CMD="rm -rf /" eval \'$CMD\''],
        },
    )

    decision = w._recursive_rm_decision(
        action.target,
        action.details["cwd"],
        observed_argv=action.details["argv"],
    )
    verdict = asyncio.run(w.evaluate_action(action))

    assert decision.state.value == "uncertain"
    assert verdict.verdict == Verdict.HALT
    assert "assigned recursive-rm" in verdict.reason.lower()

    benign = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c payload",
        details={
            "cwd": os.getcwd(),
            "argv": ["sh", "-c", 'CMD="rm -rf build" eval \'$CMD\''],
        },
    )
    assert asyncio.run(w.evaluate_action(benign)).verdict == Verdict.SAFE

    inert = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c payload",
        details={
            "cwd": os.getcwd(),
            "argv": ["sh", "-c", 'CMD="rm -rf /" printf "%s\\n" \'$CMD\''],
        },
    )
    assert asyncio.run(w.evaluate_action(inert)).verdict == Verdict.SAFE


def test_assigned_variable_command_word_cannot_hide_recursive_delete():
    """A known unquoted command expansion cannot turn recursive rm into SAFE."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False

    def shell_action(payload: str) -> AgentAction:
        return AgentAction(
            timestamp=_now_iso(),
            action_type=ActionType.PROCESS_EXEC,
            target="sh -c payload",
            details={"cwd": os.getcwd(), "argv": ["sh", "-c", payload]},
        )

    protected = shell_action(
        'CMD="rm -rf /tmp/secret/token.txt"; $CMD'
    )
    decision = w._recursive_rm_decision(
        protected.target,
        protected.details["cwd"],
        observed_argv=protected.details["argv"],
    )
    verdict = asyncio.run(w.evaluate_action(protected))

    assert decision.state.value == "uncertain"
    assert verdict.verdict == Verdict.HALT
    assert "assigned recursive-rm" in verdict.reason.lower()

    benign = shell_action('CMD="rm -rf build"; $CMD')
    assert asyncio.run(w.evaluate_action(benign)).verdict == Verdict.SAFE

    # Quotes suppress field splitting, so this attempts one executable whose
    # name contains spaces; it does not execute rm with recursive operands.
    quoted = shell_action('CMD="rm -rf /tmp/secret/token.txt"; "$CMD"')
    assert asyncio.run(w.evaluate_action(quoted)).verdict == Verdict.SAFE


def test_dynamic_recursive_rm_in_shell_payload_halts_reversibly():
    """An unresolved target cannot silently acquire either SAFE or KILL."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf \"$TARGET\"'",
        "sh -c 'BAD=.ssh rm -rf $HOME/${BAD}'",
        "sh -c 'rm -rf ${HOME}/${TARGET}'",
        "sh -c 'rm -rf ${HOME:?}/${TARGET}'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "unresolved shell expansion" in verdict.reason.lower(), cmd


def test_dynamic_rm_option_cannot_synthesize_recursive_delete_as_safe():
    """An expanded rm argv item may become ``-rf`` even without a literal flag."""
    w = _cred_warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False

    verdict = asyncio.run(
        w.evaluate_action(_exec("sh -c 'F=-rf; rm $F ~/.ssh'"))
    )

    assert verdict.verdict == Verdict.HALT
    assert "synthesize recursive options" in verdict.reason.lower()


def test_recursive_rm_inside_command_substitution_halts_reversibly():
    """echo/printf arguments can execute substitutions before rendering data."""
    w = _cred_warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False

    for cmd in (
        "sh -c 'echo `rm -rf ~/.ssh`'",
        'sh -c \'printf "%s\\n" "$(rm -rf ~/.ssh)"\'',
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "command substitution" in verdict.reason.lower(), cmd

    # Single quotes suppress shell substitution; the text remains data.
    quoted = asyncio.run(
        w.evaluate_action(_exec("sh -c \"echo '\u0024(rm -rf ~/.ssh)'\""))
    )
    assert quoted.verdict == Verdict.SAFE


def test_literal_home_project_cleanup_remains_benign():
    """Known HOME plus a literal project suffix stays routine cleanup."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf $HOME/project'",
        "sh -c 'rm -rf ${HOME}/project'",
        "sh -c 'rm -rf ${HOME:?}/project'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.SAFE, cmd
        assert "uncertain" not in verdict.reason.lower(), cmd


def test_shell_expansion_in_rm_command_or_option_halts_reversibly():
    """IFS expansion cannot hide root as a token produced after observation."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.judge.available = False
    for cmd in (
        "sh -c 'rm -rf$IFS/'",
        "sh -c 'rm$IFS-rf$IFS/'",
        "sh -c '$CMD -rf /'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "unresolved shell expansion" in verdict.reason.lower(), cmd


def test_shell_brace_expansion_in_recursive_rm_halts_reversibly():
    """Bash/zsh brace expansion cannot synthesize a protected operand unseen."""
    w = _cred_warden()
    w.scope.allowed_commands.extend(["bash", "zsh"])
    w.judge.available = False
    for cmd in (
        "bash -c 'rm -rf {/,/tmp/x}'",
        "bash -c 'rm -rf ~/{.ssh,.aws}'",
        "zsh -c 'rm -rf ~/.{ssh,aws}'",
        "bash -c 'rm -rf /tmp/item-{1..3}'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.HALT, cmd
        assert "unresolved shell expansion" in verdict.reason.lower(), cmd


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


def test_direct_env_chdir_preserves_literal_tilde_argv(tmp_path):
    """Direct argv `env -C ~` names a literal child of cwd, not HOME."""
    literal_tilde = tmp_path / "~"
    literal_tilde.mkdir()
    w = _cred_warden()
    w.scope.allowed_paths = [str(tmp_path), f"{tmp_path}/**"]
    w.scope.allowed_commands.extend(["env"])
    w.judge.available = False
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="env -C '~' rm -rf .ssh",
        details={
            "cwd": str(tmp_path),
            "argv": ["env", "-C", "~", "rm", "-rf", ".ssh"],
        },
    )

    verdict = asyncio.run(w.evaluate_action(action))

    assert verdict.verdict == Verdict.SAFE


def test_rm_rf_home_kills():
    w = _warden()
    w.judge.available = False
    for cmd in ("rm -rf ~", "rm -rf $HOME", "rm -rf ~/"):
        v = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert v.verdict == Verdict.KILL, cmd


def test_recursive_delete_root_and_home_glob_variants_kill(monkeypatch, tmp_path):
    """Root/home ancestors and first-level globs cannot classify benign."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    w = _warden()
    w.scope.forbidden_paths = []
    w.scope.allowed_commands.extend(["rm", "sh"])
    w.judge.available = False

    for cmd in (
        "rm -rf /**",
        "rm -rf /.*",
        "rm -rf ~/**",
        "rm -rf $HOME*",
        "rm -rf ~/..",
        "sh -c 'rm -rf /**'",
    ):
        verdict = asyncio.run(w.evaluate_action(_exec(cmd)))
        assert verdict.verdict == Verdict.KILL, cmd


def test_root_home_glob_protection_preserves_project_countercontrols(
    monkeypatch, tmp_path
):
    """A literal project component before the wildcard remains benign."""
    home = tmp_path / "home"
    project = home / "project"
    project.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    w = _warden()
    w.scope.forbidden_paths = []
    w.scope.allowed_commands.extend(["rm", "sh"])
    w.judge.available = False

    cases = (
        ("rm -rf ~/project/*", str(home)),
        (f"rm -rf {project}/*", str(home)),
        ("sh -c 'rm -rf build/* .venv/*'", str(project)),
        ("rm -rf *", str(project)),
    )
    for cmd, cwd in cases:
        action = AgentAction(
            timestamp=_now_iso(),
            action_type=ActionType.PROCESS_EXEC,
            target=cmd,
            details={"cwd": cwd},
        )
        assert asyncio.run(w.evaluate_action(action)).verdict == Verdict.SAFE, cmd


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


def test_observer_records_child_cwd_for_process_exec(monkeypatch, tmp_path):
    """The destructive-command evaluator must receive the observed child cwd."""

    class FakeChild:
        pid = 2468

        @staticmethod
        def cmdline():
            return ["sh", "-c", "rm -rf .ssh"]

        @staticmethod
        def cwd():
            return str(tmp_path)

    child = FakeChild()

    class FakeParent:
        @staticmethod
        def open_files():
            return []

        @staticmethod
        def net_connections():
            return []

        @staticmethod
        def children():
            return [child]

    observer = ProcessObserver(agent_pid=1357)
    monkeypatch.setattr(observer, "get_agent_pids", lambda: [1357])
    monkeypatch.setattr(warden_module.psutil, "Process", lambda _pid: FakeParent())

    actions = observer.observe()

    assert len(actions) == 1
    assert actions[0].target == "sh -c 'rm -rf .ssh'"
    assert actions[0].details == {
        "argv": ["sh", "-c", "rm -rf .ssh"],
        "child_pid": 2468,
        "cwd": str(tmp_path),
    }


def test_observer_marks_child_cwd_unavailable(monkeypatch):
    """Access-denied cwd capture is explicit evidence, not a Warden-cwd guess."""

    class FakeChild:
        pid = 2468

        @staticmethod
        def cmdline():
            return ["sh", "-c", "rm -rf .ssh"]

        @staticmethod
        def cwd():
            raise warden_module.psutil.AccessDenied(pid=2468)

    child = FakeChild()

    class FakeParent:
        @staticmethod
        def open_files():
            return []

        @staticmethod
        def net_connections():
            return []

        @staticmethod
        def children():
            return [child]

    observer = ProcessObserver(agent_pid=1357)
    monkeypatch.setattr(observer, "get_agent_pids", lambda: [1357])
    monkeypatch.setattr(warden_module.psutil, "Process", lambda _pid: FakeParent())

    actions = observer.observe()

    assert len(actions) == 1
    assert actions[0].details == {
        "argv": ["sh", "-c", "rm -rf .ssh"],
        "child_pid": 2468,
        "cwd_unavailable": True,
    }


def test_direct_argv_literal_shell_metacharacters_do_not_kill(tmp_path):
    """Direct exec argv does not expand literal ``~`` or ``$HOME`` operands."""
    project = tmp_path / "project"
    project.mkdir()
    w = _cred_warden()
    w.scope.allowed_commands.append("rm")
    w.scope.allowed_paths.extend([str(project), f"{project}/**"])

    for literal in ("~", "$HOME", "*"):
        argv = ["rm", "-rf", literal]
        action = AgentAction(
            timestamp=_now_iso(),
            action_type=ActionType.PROCESS_EXEC,
            target=warden_module.shlex.join(argv),
            details={"argv": argv, "cwd": str(project)},
        )
        verdict = asyncio.run(w.evaluate_action(action))
        assert verdict.verdict != Verdict.KILL, literal

    shell = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c 'rm -rf ~'",
        details={"argv": ["sh", "-c", "rm -rf ~"], "cwd": str(project)},
    )
    assert asyncio.run(w.evaluate_action(shell)).verdict == Verdict.KILL


def test_observer_refreshes_current_established_connections(monkeypatch):
    """Active socket state is current-poll truth, not the de-duplication history."""

    class Address:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class Connection:
        status = warden_module.psutil.CONN_ESTABLISHED
        raddr = Address("8.8.8.8", 443)
        laddr = Address("127.0.0.1", 50000)

    class FakeParent:
        connections = [Connection()]

        @staticmethod
        def open_files():
            return []

        @classmethod
        def net_connections(cls):
            return cls.connections

        @staticmethod
        def children():
            return []

    observer = ProcessObserver(agent_pid=1357)
    monkeypatch.setattr(observer, "get_agent_pids", lambda: [1357])
    monkeypatch.setattr(warden_module.psutil, "Process", lambda _pid: FakeParent())

    first = observer.observe()
    assert observer._active_connections == {(1357, "8.8.8.8", 443)}
    assert [action.action_type for action in first] == [ActionType.NETWORK_OUT]

    FakeParent.connections = []
    second = observer.observe()
    assert observer._active_connections == set()
    assert second == []


def test_observer_reemits_file_and_connection_after_close_then_reopen(monkeypatch):
    """De-duplication applies only while an observed resource remains open."""

    class Address:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class OpenFile:
        path = "/tmp/secret/token.txt"
        mode = "r"
        fd = 7

    class Connection:
        status = warden_module.psutil.CONN_ESTABLISHED
        raddr = Address("8.8.8.8", 443)
        laddr = Address("127.0.0.1", 50000)

    class FakeParent:
        files = [OpenFile()]
        connections = [Connection()]

        @classmethod
        def open_files(cls):
            return cls.files

        @classmethod
        def net_connections(cls):
            return cls.connections

        @staticmethod
        def children():
            return []

    observer = ProcessObserver(agent_pid=1357)
    monkeypatch.setattr(observer, "get_agent_pids", lambda: [1357])
    monkeypatch.setattr(warden_module.psutil, "Process", lambda _pid: FakeParent())

    first = observer.observe()
    assert [action.action_type for action in first] == [
        ActionType.FILE_READ,
        ActionType.NETWORK_OUT,
    ]

    FakeParent.files = []
    FakeParent.connections = []
    assert observer.observe() == []

    FakeParent.files = [OpenFile()]
    FakeParent.connections = [Connection()]
    reopened = observer.observe()
    assert [action.action_type for action in reopened] == [
        ActionType.FILE_READ,
        ActionType.NETWORK_OUT,
    ]


def test_relative_credential_delete_resolves_against_child_cwd(monkeypatch, tmp_path):
    """Exact blocker: HOME child + `rm -rf .ssh` must never classify SAFE."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    w = _cred_warden()
    w.scope.allowed_commands.extend(["sh"])

    protected = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c 'rm -rf .ssh'",
        details={"child_pid": 2468, "cwd": str(home)},
    )
    verdict = asyncio.run(w.evaluate_action(protected))

    assert verdict.verdict == Verdict.KILL
    assert "protected root" in verdict.reason.lower()


def test_relative_project_cleanup_with_known_child_cwd_stays_safe(tmp_path):
    """Known project cwd preserves confidently benign cleanup behavior."""
    project = tmp_path / "project"
    project.mkdir()
    w = _cred_warden()
    w.scope.allowed_commands.extend(["sh"])
    w.scope.allowed_paths.extend([str(project), f"{project}/**"])
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c 'rm -rf build .venv'",
        details={"child_pid": 2468, "cwd": str(project)},
    )

    verdict = asyncio.run(w.evaluate_action(action))

    assert verdict.verdict == Verdict.SAFE


def test_relative_recursive_delete_without_child_cwd_halts():
    """A denied/vanished cwd is reversible uncertainty, never a SAFE guess."""
    w = _cred_warden()
    w.scope.allowed_commands.extend(["sh"])
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target="sh -c 'rm -rf .ssh'",
        details={"child_pid": 2468, "cwd_unavailable": True},
    )

    verdict = asyncio.run(w.evaluate_action(action))

    assert verdict.verdict == Verdict.HALT
    assert "no observed child cwd" in verdict.reason.lower()


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


def test_recursive_rm_glob_intersection_never_expands_filesystem(
    monkeypatch, tmp_path
):
    """Process-event classification is symbolic and cannot start a glob walk."""
    w = _warden()
    w.scope.allowed_commands.extend(["sh"])
    w.scope.forbidden_paths = [str(tmp_path / "*" / "secret" / "**")]
    w.judge.available = False

    def fail_iglob(*_args, **_kwargs):
        raise AssertionError("process recursive-rm classifier called glob.iglob")

    monkeypatch.setattr(warden_module.glob, "iglob", fail_iglob)
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.PROCESS_EXEC,
        target=f"sh -c 'rm -rf {tmp_path}/**/build'",
        details={"cwd": str(tmp_path)},
    )

    verdict = asyncio.run(w.evaluate_action(action))
    assert verdict.verdict in {Verdict.SAFE, Verdict.HALT}
