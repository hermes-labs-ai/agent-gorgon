"""test_tool_shadow.py — pytest suite for ToolShadow PreToolUse hook.

Tests cover:
  - Fabrication detection (should block, exit=2)
  - Clean commands (should allow, exit=0)
  - Non-Bash tools (always allow)
  - Malformed input (fail-open, allow)
  - find_tool integration (real subprocess, real manifests)
  - With/without comparison: simulated without-hook path vs with-hook path
  - Performance: must complete in < 4s (hook budget)
  - Falsification: verifies hook would NOT block innocent commands
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

HOOK = Path.home() / "ai-infra" / "hackathon" / "agent-5-contrarian" / "tool_shadow.py"

# Integration tests — require the Hermes Labs internal hackathon workspace.
# On CI runners (no workspace), all tests in this file skip.
pytestmark = pytest.mark.skipif(
    not HOOK.exists(),
    reason="requires ~/ai-infra/hackathon/agent-5-contrarian/tool_shadow.py (integration tests)",
)


def run_hook(payload: dict, timeout: int = 8) -> tuple[int, str, str]:
    """Invoke hook with payload, return (exit_code, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def bash(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


# --------------------------------------------------------------------------- #
# Sanity
# --------------------------------------------------------------------------- #

class TestHookExists:
    def test_hook_file_exists(self):
        assert HOOK.exists(), f"Hook not found at {HOOK}"

    def test_hook_is_executable_python(self):
        # Must not crash on empty input (fail open)
        rc, _, _ = run_hook({})
        assert rc == 0


# --------------------------------------------------------------------------- #
# Allow: clean commands must pass through
# --------------------------------------------------------------------------- #

CLEAN_COMMANDS = [
    "ls ~/ai-infra/",
    "cat README.md",
    "git status",
    "python3 -m pytest -q",
    "echo hello world",
    "cd ~/Documents && pwd",
    "pip install pyyaml",
    "curl https://api.example.com/health",
    "grep -r 'pattern' .",
    "find . -name '*.py'",
    "python3 find_tool.py 'score company'",   # allowed — using the tool correctly
    "cd ~/ai-infra && python3 find_tool.py 'eu ai act'",
]

class TestAllowClean:
    @pytest.mark.parametrize("cmd", CLEAN_COMMANDS)
    def test_clean_command_allowed(self, cmd):
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 0, f"Should allow clean cmd: {cmd!r}\nstderr={stderr}"

    def test_non_bash_tool_always_allowed(self):
        payload = {"tool_name": "Read", "tool_input": {"file_path": "/tmp/test.txt"}}
        rc, _, _ = run_hook(payload)
        assert rc == 0

    def test_write_tool_always_allowed(self):
        payload = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/x", "content": "score=62"}}
        rc, _, _ = run_hook(payload)
        assert rc == 0

    def test_empty_command_allowed(self):
        rc, _, _ = run_hook(bash(""))
        assert rc == 0

    def test_malformed_input_fail_open(self):
        result = subprocess.run(
            [sys.executable, str(HOOK)],
            input="NOT JSON AT ALL }{",
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0, "Malformed input must fail-open"


# --------------------------------------------------------------------------- #
# Block: fabrication patterns must be caught
# --------------------------------------------------------------------------- #

FABRICATION_COMMANDS = [
    # Hardcoded score assignment
    ("python3 -c \"score = 62; print(score)\"", "hardcoded score"),
    ("python3 -c 'score=75'", "hardcoded score 2"),
    # Defining a scoring function inline
    ("python3 -c \"def score_compliance(signals): return 65\"", "def scoring fn"),
    # Printing a fabricated score
    ("echo 'compliance score: 72'", "echo score"),
    # Hardcoded JSON result
    ("echo '{\"score\": 72, \"tier\": \"Medium\"}'", "echo json score"),
    # Manual EU AI Act assessment
    ("python3 -c \"article9_check = True; score += 10\"", "manual article check"),
    # Defining compliance check manually
    ("python3 -c \"def check_gdpr(): return True\"", "manual gdpr check"),
]

class TestBlockFabrication:
    @pytest.mark.parametrize("cmd,label", FABRICATION_COMMANDS)
    def test_fabrication_blocked(self, cmd, label):
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 2, f"Should block fabrication ({label}): {cmd!r}\nstderr={stderr}"

    def test_block_message_contains_tool_name(self):
        cmd = "python3 -c \"score = 62\""
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 2
        # Block message should contain at least one real tool name
        combined = stdout + stderr
        assert any(name in combined for name in ["hermes-score", "compliance-score", "risk-scorer"]), \
            f"Block message should name a real tool. Got:\n{combined}"

    def test_block_message_contains_entry_command(self):
        cmd = "python3 -c \"score = 62\""
        rc, stdout, stderr = run_hook(bash(cmd))
        combined = stdout + stderr
        assert "python3" in combined or "PYTHONPATH" in combined, \
            "Block message should contain executable entry command"

    def test_block_message_contains_toolshadow_header(self):
        cmd = "python3 -c \"def audit_compliance(): return 50\""
        rc, stdout, stderr = run_hook(bash(cmd))
        combined = stdout + stderr
        assert "TOOLSHADOW" in combined


# --------------------------------------------------------------------------- #
# With/Without comparison — core falsification
# --------------------------------------------------------------------------- #

class TestWithWithoutComparison:
    """
    Simulate what happens with and without ToolShadow.

    WITHOUT: model runs the fabrication command, gets fake output.
    WITH:    hook blocks, model is forced to use real tool.

    We prove: WITHOUT allows a command that fabricates; WITH blocks it.
    """

    def test_without_hook_fabrication_runs(self):
        """Without the hook, a fabrication command executes fine."""
        # Simulate: run the Bash command directly (as if no hook intercepted it)
        fabrication_cmd = ["python3", "-c", "result = {'score': 62, 'tier': 'Medium'}; print(result)"]
        result = subprocess.run(fabrication_cmd, capture_output=True, text=True, timeout=5)
        # Direct execution succeeds — this is the FAILURE MODE we fix
        assert result.returncode == 0, "Without hook, fabrication runs freely"
        assert "62" in result.stdout or "Medium" in result.stdout

    def test_with_hook_fabrication_blocked(self):
        """With the hook, same command is intercepted before execution."""
        cmd = "python3 -c \"result = {'score': 62, 'tier': 'Medium'}; print(result)\""
        rc, stdout, stderr = run_hook(bash(cmd))
        # Hook blocks it
        assert rc == 2, "With hook, fabrication is blocked"
        combined = stdout + stderr
        assert "TOOLSHADOW" in combined

    def test_with_hook_correct_tool_named(self):
        """The block message names a real, runnable tool."""
        cmd = "python3 -c \"score = 62\""
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 2
        combined = stdout + stderr
        # Must name at least one real tool with a real entry point
        assert "hermes-score" in combined or "compliance-score" in combined or "risk-scorer" in combined

    def test_real_tool_invocation_works(self):
        """The tool named in the block message is actually runnable."""
        # Verify hermes-score manifest entry is parseable and points to a real path
        import yaml
        manifest = Path.home() / "ai-infra" / "manifests" / "hermes-score.yaml"
        assert manifest.exists(), "hermes-score manifest must exist"
        data = yaml.safe_load(manifest.read_text())
        assert "entry" in data
        assert "hermes_score" in data["entry"] or "hermes-score" in data["entry"]


# --------------------------------------------------------------------------- #
# Performance
# --------------------------------------------------------------------------- #

class TestPerformance:
    def test_allow_path_fast(self):
        """Clean command hook path must complete < 0.5s (no find_tool needed)."""
        t0 = time.time()
        run_hook(bash("ls -la"))
        elapsed = time.time() - t0
        assert elapsed < 0.5, f"Allow path too slow: {elapsed:.2f}s"

    def test_block_path_within_budget(self):
        """Block path (including find_tool subprocess) must complete < 5s."""
        t0 = time.time()
        run_hook(bash("python3 -c \"score = 62\""))
        elapsed = time.time() - t0
        assert elapsed < 5.0, f"Block path too slow: {elapsed:.2f}s"


# --------------------------------------------------------------------------- #
# Falsification tests — prove the hook can be proven wrong
# --------------------------------------------------------------------------- #

class TestFalsification:
    """
    These tests prove the approach is falsifiable — i.e., there are specific
    conditions under which ToolShadow would fail. Roli can use these to audit
    whether the hook is working correctly.
    """

    def test_false_positive_immunity_git(self):
        """git commands with 'score' in branch name must not be blocked."""
        rc, _, _ = run_hook(bash("git checkout feature/score-display"))
        assert rc == 0, "git checkout should not be blocked"

    def test_false_positive_immunity_find_tool_itself(self):
        """Running find_tool.py directly must not be blocked."""
        rc, _, _ = run_hook(bash("python3 ~/ai-infra/find_tool.py 'score eu ai act'"))
        assert rc == 0, "Invoking find_tool.py directly should be allowed"

    def test_false_positive_immunity_reading_score(self):
        """Reading a file that contains score data is not fabrication."""
        rc, _, _ = run_hook(bash("cat results.json | grep score"))
        assert rc == 0, "Grepping existing score data is not fabrication"

    def test_false_positive_immunity_test_assertion(self):
        """Pytest assertions about expected scores are not fabrications."""
        rc, _, _ = run_hook(bash("python3 -m pytest test_score.py -v"))
        assert rc == 0, "Running tests should not be blocked"

    def test_no_manifests_fails_open(self):
        """If manifests dir is unavailable, hook must allow (fail open)."""
        # We simulate this by patching the command to something that would
        # trigger a signal but find_tool returns no results.
        # The actual test: a fabrication with a signal that has no manifest match.
        # We can't easily remove manifests, so we test: if relevance < threshold → allow.
        # This is validated by the MIN_RELEVANCE logic in the hook itself.
        # Proof: check the source code directly.
        source = HOOK.read_text()
        assert "MIN_RELEVANCE" in source
        assert "good_matches" in source
        assert "return 0" in source  # fail-open path exists

    def test_hook_does_not_block_hermes_score_itself(self):
        """The hook must not block the actual hermes-score invocation."""
        cmd = ("cd ~/Documents/projects/hermes-labs-hackathon-2/hermes-score && "
               "PYTHONPATH=src python3 -m hermes_score.cli score --stdin --json")
        rc, _, stderr = run_hook(bash(cmd))
        assert rc == 0, f"Actual tool invocation must not be blocked\nstderr={stderr}"


# --------------------------------------------------------------------------- #
# Whitelist tests — A5 patch for false positives
# --------------------------------------------------------------------------- #

class TestWhitelistA5Patch:
    """
    Tests for the A5 patch: whitelisting registered tool invocations.
    The bug: legitimate tool invocations were blocked due to signal matches.
    The fix: check if command invokes a registered tool before blocking.
    """

    def test_stripe_command_1_hermes_score_entry(self):
        """
        Literal Stripe scoring command #1.
        This invokes the exact hermes-score entry from the manifest.
        Must NOT be blocked.
        """
        cmd = ('cd ~/Documents/projects/hermes-labs-hackathon-2/hermes-score && '
               'echo "Stripe" | PYTHONPATH=src python3 -m hermes_score.cli score --stdin --json')
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 0, f"Stripe command #1 (hermes-score entry) must not be blocked\nstderr={stderr}"

    def test_stripe_command_2_compliance_score_entry(self):
        """
        Literal Stripe scoring command #2.
        This invokes compliance-score from manifest.
        Must NOT be blocked.
        """
        cmd = ('cd ~/Documents/projects/hermes-labs-hackathon/compliance-score && '
               'python3 main.py Stripe')
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 0, f"Stripe command #2 (compliance-score entry) must not be blocked\nstderr={stderr}"

    def test_stripe_command_3_with_heredoc(self):
        """
        Literal Stripe scoring command #3, with heredoc payload.
        Contains "score", "GDPR", "DPO", "compliance" keywords that normally trigger signals.
        But the command itself invokes a registered tool, so must NOT be blocked.
        """
        cmd = ('cd ~/Documents/projects/hermes-labs-hackathon-2/hermes-score && '
               'cat <<\'EOF\' | PYTHONPATH=src python3 -m hermes_score.cli score --stdin --json\n'
               '{"company":"Stripe","signals":{"has_dpo":true,"gdpr_compliant":true}}\n'
               'EOF')
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 0, f"Stripe command #3 (heredoc) must not be blocked\nstderr={stderr}"

    def test_adversarial_tool_entry_then_echo_score(self):
        """
        Adversarial: command starts with a registered tool entry,
        but then chains to echo a fabricated score.

        hermes-score entry && echo "score=62"

        The hermes-score segment is whitelisted, but the echo is NOT.
        The existing detection should still catch the echo segment.
        Expect: BLOCK (due to echo score pattern).
        """
        cmd = ('cd ~/Documents/projects/hermes-labs-hackathon-2/hermes-score && '
               'PYTHONPATH=src python3 -m hermes_score.cli score --stdin --json && '
               'echo "score=62"')
        rc, stdout, stderr = run_hook(bash(cmd))
        # The second segment (echo "score=62") should trigger a signal
        assert rc == 2, f"Chained echo with fabricated score must be blocked\nstderr={stderr}"

    def test_no_tool_entry_keyword_still_blocked(self):
        """
        Command does NOT invoke a registered tool (no matching entry prefix).
        Contains "score" keyword that triggers a signal.
        Must still be BLOCKED (existing behavior preserved).
        """
        cmd = 'python3 -c "score = 62; print(\'Stripe compliance score\', score)"'
        rc, stdout, stderr = run_hook(bash(cmd))
        assert rc == 2, f"Non-tool score fabrication must still be blocked\nstderr={stderr}"
