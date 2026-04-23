#!/usr/bin/env python3
"""Synthesis test suite — agent-7-synthesis.

Tests the full 3-layer defense:
  Layer 1: UserPromptSubmit hook (agent-1 reused) — pre-generation injection
  Layer 2: Stop hook (NEW) — post-generation fabrication interception
  Layer 3: PreToolUse Bash hook (agent-5 reused) — execution-time interception

MUST include:
  (a) Literal Stripe failure -> caught/prevented
  (b) Legitimate tool invocation -> must not interfere
  (c) Chitchat -> no false positives
  (d) End-to-end smoke test of install

All tests pass pytest -q.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SYNTHESIS_DIR = Path.home() / "ai-infra" / "hackathon" / "agent-7-synthesis"
STOP_HOOK = SYNTHESIS_DIR / "stop_hook.py"
AGENT1_HOOK = Path.home() / "ai-infra" / "hackathon" / "agent-1-hook" / "hook.py"
AGENT5_HOOK = Path.home() / "ai-infra" / "hackathon" / "agent-5-contrarian" / "tool_shadow.py"

# Integration tests — require the Hermes Labs internal hackathon workspace
# at ~/ai-infra/hackathon/agent-{1,5,7}-*. These tests exercise hooks that
# live outside the agent-gorgon package. On CI runners (no workspace) the
# whole module skips cleanly. On Roli's machine (workspace present) all
# tests run normally.
pytestmark = pytest.mark.skipif(
    not (SYNTHESIS_DIR.exists() and AGENT1_HOOK.exists() and AGENT5_HOOK.exists()),
    reason="requires ~/ai-infra/hackathon/agent-{1,5,7}/ workspace (integration tests)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_stop_hook(payload: dict) -> tuple[int, dict | None, str]:
    """Run stop_hook.py with the given payload. Returns (exit_code, stdout_json, stderr)."""
    result = subprocess.run(
        [sys.executable, str(STOP_HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    stdout_data = None
    if result.stdout.strip():
        try:
            stdout_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return result.returncode, stdout_data, result.stderr


def run_a1_hook(payload: dict) -> tuple[int, dict | None]:
    """Run agent-1 hook with the given payload."""
    result = subprocess.run(
        [sys.executable, str(AGENT1_HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    stdout_data = None
    if result.stdout.strip():
        try:
            stdout_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return result.returncode, stdout_data


def run_a5_hook(payload: dict) -> tuple[int, str]:
    """Run agent-5 tool_shadow hook. Returns (exit_code, stderr)."""
    result = subprocess.run(
        [sys.executable, str(AGENT5_HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode, result.stderr


def make_transcript(assistant_text: str) -> list[dict]:
    """Build a minimal transcript with the given assistant message."""
    return [
        {"role": "user", "content": "Score Stripe on EU AI Act compliance. Output JSON."},
        {"role": "assistant", "content": assistant_text},
    ]


# ---------------------------------------------------------------------------
# THE LITERAL STRIPE FAILURE — exact JSON the model emitted
# ---------------------------------------------------------------------------

STRIPE_FABRICATED_JSON = '''
{
  "company": "Stripe",
  "overall_score": 62,
  "grade": "C+",
  "tier": "Medium Risk",
  "article_scores": {
    "article_9": {"score": 70, "status": "Partial", "gaps": ["bias testing incomplete"]},
    "article_14": {"score": 55, "status": "Gap", "gaps": ["human oversight limited"]},
    "article_29": {"score": 65, "status": "Partial", "gaps": ["provider obligations partial"]}
  },
  "top_3_gaps": [
    "No formal model registry",
    "Human oversight limited for automated decisions",
    "Bias testing pipeline not documented"
  ],
  "recommendations": [
    "Establish model registry with version tracking",
    "Add human review checkpoints for high-risk AI decisions",
    "Document bias testing per Annex C"
  ]
}
'''


# ---------------------------------------------------------------------------
# (a) THE STRIPE FAILURE — LAYER 2 (Stop hook) MUST catch this
# ---------------------------------------------------------------------------

class TestStripeFailureStopHook:
    """The exact Stripe failure: model emitted fabricated JSON as plain text."""

    def test_stripe_fabricated_json_is_blocked(self):
        """Core test: fabricated compliance JSON triggers exit code 2 (block)."""
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(STRIPE_FABRICATED_JSON),
            "session_id": "test-stripe-001",
        }
        exit_code, stdout_data, stderr = run_stop_hook(payload)
        assert exit_code == 2, (
            f"Stop hook must return exit code 2 (block) for Stripe fabrication. "
            f"Got {exit_code}. stdout={stdout_data}, stderr={stderr}"
        )

    def test_stripe_block_response_has_decision(self):
        """Block response must contain decision=block."""
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(STRIPE_FABRICATED_JSON),
        }
        exit_code, stdout_data, stderr = run_stop_hook(payload)
        assert stdout_data is not None, "Stop hook must write JSON to stdout when blocking"
        assert stdout_data.get("decision") == "block"

    def test_stripe_block_reason_mentions_tool(self):
        """Block reason must reference a registered tool (hermes-score)."""
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(STRIPE_FABRICATED_JSON),
        }
        _, stdout_data, _ = run_stop_hook(payload)
        reason = (stdout_data or {}).get("reason", "")
        # Either names hermes-score directly or tells model to invoke find_tool
        assert "hermes-score" in reason or "find_tool" in reason or "tool" in reason.lower(), (
            f"Block reason must mention a registered tool. Got: {reason[:200]}"
        )

    def test_stripe_block_reason_tells_model_to_invoke(self):
        """Block reason must explicitly instruct the model to invoke the tool."""
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(STRIPE_FABRICATED_JSON),
        }
        _, stdout_data, _ = run_stop_hook(payload)
        reason = (stdout_data or {}).get("reason", "").upper()
        assert any(kw in reason for kw in ["INVOKE", "RUN THE TOOL", "RUN", "ENTRY"]), (
            f"Block reason must instruct model to invoke/run the tool. Got: {reason[:200]}"
        )

    def test_stripe_partial_fabrication_caught(self):
        """Even partial fabricated output with score + compliance is caught."""
        partial = 'The overall_score: 62 for EU AI Act compliance looks like this: {"tier": "Medium Risk"}'
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(partial),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 2, "Partial fabrication must also be blocked"


# ---------------------------------------------------------------------------
# (b) LEGITIMATE TOOL INVOCATION — must not interfere
# ---------------------------------------------------------------------------

class TestLegitimateInvocation:
    """Legitimate Bash tool invocations must pass through without interference."""

    def test_legitimate_hermes_score_bash_not_blocked(self):
        """Running hermes-score entry command directly must not trigger agent-5 ToolShadow.

        The entry command is a cd + PYTHONPATH invocation — no fabrication signals.
        Agent-5 catches reimplementation patterns (def score(), hardcoded score=62);
        it must not block the canonical tool entry command itself.
        """
        payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": (
                    "cd ~/Documents/projects/hermes-labs-hackathon-2/hermes-score && "
                    "PYTHONPATH=src python3 -m hermes_score.cli score --stdin --json"
                )
            },
        }
        exit_code, stderr = run_a5_hook(payload)
        assert exit_code == 0, (
            f"Legitimate hermes-score entry command must not be blocked. "
            f"Got exit_code={exit_code}, stderr={stderr}"
        )

    def test_git_command_not_blocked(self):
        """Common git commands must pass through agent-5 without interference."""
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }
        exit_code, _ = run_a5_hook(payload)
        assert exit_code == 0

    def test_find_tool_invocation_not_blocked(self):
        """Running find_tool.py itself must not be blocked."""
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "python3 ~/ai-infra/find_tool.py 'score company'"},
        }
        exit_code, _ = run_a5_hook(payload)
        assert exit_code == 0

    def test_clean_assistant_message_allowed(self):
        """Assistant message with no fabrication signals must pass Stop hook."""
        clean_text = (
            "I'll invoke hermes-score now. Running the tool via Bash to get "
            "the EU AI Act compliance score for Stripe."
        )
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(clean_text),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 0, (
            "Clean message announcing tool invocation must not be blocked"
        )

    def test_tool_result_message_allowed(self):
        """Assistant message reporting tool output (not fabricating) must pass."""
        tool_report = (
            "I ran hermes-score and got the following result from the tool:\n"
            "The score is 34 out of 100 (Critical Gap tier). "
            "Top gaps: model registry missing, bias testing absent."
        )
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(tool_report),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 0, (
            "Message reporting tool output (no JSON structure) must not be blocked"
        )


# ---------------------------------------------------------------------------
# (c) CHITCHAT — no false positives
# ---------------------------------------------------------------------------

class TestChitchatNoFalsePositives:
    """Chitchat and normal prose must not trigger any layer."""

    def test_hello_not_blocked_by_stop_hook(self):
        """Chitchat 'hello' must not be blocked by Stop hook."""
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript("Hello! How can I help you today?"),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 0

    def test_code_explanation_not_blocked(self):
        """Code explanation without compliance context must not be blocked."""
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(
                "Here's how to write a Python function:\n"
                "def score(x):\n    return x * 2\n"
                "This scores values by doubling them."
            ),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 0

    def test_thanks_not_blocked_by_a1(self):
        """UserPromptSubmit hook must not inject on chitchat."""
        payload = {"prompt": "Thanks, that's helpful!"}
        exit_code, stdout_data = run_a1_hook(payload)
        assert exit_code == 0
        # Should produce no additionalContext injection for chitchat
        if stdout_data:
            context = (
                stdout_data.get("hookSpecificOutput", {})
                .get("additionalContext", "")
            )
            # If context injected, it should be soft nudge, not MUST instruction
            assert "MUST" not in context or context == ""

    def test_empty_assistant_message_passes_stop_hook(self):
        """Empty transcript must not crash or block."""
        payload = {"stop_hook_active": True, "transcript": []}
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 0

    def test_prose_with_article_mention_no_score(self):
        """Mentioning Article 9 in prose without a score field must not block."""
        prose = (
            "Article 9 of the EU AI Act requires risk management systems "
            "for high-risk AI. Companies should document their approach."
        )
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(prose),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 0, (
            "Prose mentioning EU AI Act without numeric scores must not be blocked"
        )


# ---------------------------------------------------------------------------
# (d) END-TO-END SMOKE TEST
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """Smoke tests for the full install."""

    def test_stop_hook_exists_and_is_executable(self):
        """stop_hook.py must exist in synthesis dir."""
        assert STOP_HOOK.exists(), f"stop_hook.py missing at {STOP_HOOK}"

    def test_agent1_hook_exists(self):
        """Agent-1 hook must exist (reused by synthesis)."""
        assert AGENT1_HOOK.exists(), f"agent-1 hook missing at {AGENT1_HOOK}"

    def test_agent5_hook_exists(self):
        """Agent-5 hook must exist (reused by synthesis)."""
        assert AGENT5_HOOK.exists(), f"agent-5 hook missing at {AGENT5_HOOK}"

    def test_stop_hook_syntax_valid(self):
        """stop_hook.py must be syntactically valid Python."""
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(STOP_HOOK)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"Syntax error in stop_hook.py: {result.stderr}"

    def test_stop_hook_handles_malformed_input_gracefully(self):
        """Malformed JSON input must not crash stop_hook.py."""
        result = subprocess.run(
            [sys.executable, str(STOP_HOOK)],
            input="NOT JSON {{{",
            capture_output=True, text=True, timeout=5,
        )
        # Must not exit with anything except 0 or 2; must not crash (exit code 1)
        assert result.returncode in (0, 2), (
            f"Malformed input caused unexpected exit code {result.returncode}"
        )

    def test_stop_hook_handles_empty_input_gracefully(self):
        """Empty stdin must not crash stop_hook.py."""
        result = subprocess.run(
            [sys.executable, str(STOP_HOOK)],
            input="",
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0, "Empty input should allow stop (exit 0)"

    def test_settings_json_is_valid(self):
        """settings.json must be valid JSON after install."""
        settings_path = Path.home() / ".claude" / "settings.json"
        if not settings_path.exists():
            pytest.skip("settings.json does not exist yet — run install.sh first")
        content = settings_path.read_text()
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            pytest.fail(f"settings.json is invalid JSON after install: {e}")
        assert isinstance(data, dict)

    def test_grade_field_signal_isolated(self):
        """Grade field alone with compliance context triggers block."""
        text = 'Stripe compliance assessment: "grade": "C+" for EU AI Act readiness.'
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(text),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 2, "Grade field + compliance must trigger block"

    def test_article_score_signal_isolated(self):
        """Article-by-article scoring structure with compliance context triggers block.

        The Stripe failure had article_scores with EU AI Act context in the same blob.
        Compliance context (eu ai act / compliance keyword) must co-occur with the
        article score structure to trigger the block — compound detection prevents
        false positives on non-compliance article scores.
        """
        text = (
            'EU AI Act compliance assessment:\n'
            '{"article_9": {"score": 70, "gaps": ["missing bias tests"]}}'
        )
        payload = {
            "stop_hook_active": True,
            "transcript": make_transcript(text),
        }
        exit_code, _, _ = run_stop_hook(payload)
        assert exit_code == 2, "Article score structure + EU AI Act context must trigger block"
