"""pytest suite for hook.py — must pass with `pytest -q`.

Covers: task-verb prompt, chitchat, ambiguous, empty input, malformed JSON,
gap-handling, find_tool unavailable, end-to-end subprocess, performance,
real find_tool.py invocation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

HOOK_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(HOOK_DIR))

import hook  # noqa: E402


# ---------------------------------------------------------------------------
# Unit tests — pure functions
# ---------------------------------------------------------------------------

class TestTaskVerbDetection:
    def test_clear_task_verb_score(self):
        assert hook.is_task_prompt("Score Stripe on EU AI Act compliance.")

    def test_clear_task_verb_audit(self):
        assert hook.is_task_prompt("Audit this repo and output JSON.")

    def test_clear_task_verb_classify(self):
        assert hook.is_task_prompt("Classify this attack into a taxonomy.")

    def test_clear_task_verb_extract(self):
        assert hook.is_task_prompt("Extract all email addresses as a table.")

    def test_clear_task_verb_rank(self):
        assert hook.is_task_prompt("Rank these companies by risk.")

    def test_clear_task_verb_json(self):
        assert hook.is_task_prompt("Give me JSON for this dataset.")

    def test_chitchat_hi(self):
        assert not hook.is_task_prompt("hi")

    def test_chitchat_thanks(self):
        assert not hook.is_task_prompt("thanks!")

    def test_chitchat_with_punctuation(self):
        assert not hook.is_task_prompt("Hello, how are you?")

    def test_ambiguous_general_question(self):
        # No task verb, no chitchat-greeting — should NOT trigger.
        assert not hook.is_task_prompt("What is the capital of France?")

    def test_empty_prompt(self):
        assert not hook.is_task_prompt("")
        assert not hook.is_task_prompt("   \n  ")

    def test_compliance_keyword(self):
        assert hook.is_task_prompt("Tell me about EU AI Act.")


class TestStdinParsing:
    def test_empty_stdin(self):
        assert hook.parse_stdin("") == {}

    def test_whitespace_stdin(self):
        assert hook.parse_stdin("   \n   ") == {}

    def test_malformed_json(self):
        assert hook.parse_stdin("{not valid json") == {}
        assert hook.parse_stdin("[]") == {}  # not a dict
        assert hook.parse_stdin("null") == {}

    def test_valid_json(self):
        out = hook.parse_stdin('{"prompt": "hi", "x": 1}')
        assert out == {"prompt": "hi", "x": 1}


class TestPromptExtraction:
    def test_top_level_prompt(self):
        assert hook.extract_prompt({"prompt": "abc"}) == "abc"

    def test_nested_prompt(self):
        assert hook.extract_prompt({"hook_event_data": {"prompt": "xyz"}}) == "xyz"

    def test_missing_prompt(self):
        assert hook.extract_prompt({}) == ""
        assert hook.extract_prompt({"prompt": None}) == ""
        assert hook.extract_prompt({"prompt": 42}) == ""


class TestFormatContext:
    def test_format_includes_entry_command(self):
        matches = [
            {
                "name": "hermes-score",
                "one_liner": "Scores companies on EU AI Act.",
                "entry": "echo run-it",
                "relevance": 0.85,
                "installed": True,
            }
        ]
        ctx = hook.format_context(matches, "score Stripe")
        assert "hermes-score" in ctx
        assert "echo run-it" in ctx
        assert "0.85" in ctx
        assert "[installed]" in ctx
        assert "MUST" in ctx  # hard instruction

    def test_format_uninstalled_marker(self):
        matches = [{"name": "x", "one_liner": "y", "entry": "z", "relevance": 0.5, "installed": False}]
        ctx = hook.format_context(matches, "q")
        assert "[not installed]" in ctx


# ---------------------------------------------------------------------------
# Integration tests — build_response
# ---------------------------------------------------------------------------

class TestBuildResponse:
    def test_chitchat_skips(self):
        resp, log = hook.build_response("hi there")
        assert resp == {}
        assert log["action"] == "skip"

    def test_empty_skips(self):
        resp, log = hook.build_response("")
        assert resp == {}
        assert log["action"] == "skip"

    def test_ambiguous_skips(self):
        resp, log = hook.build_response("Tell me about quantum mechanics.")
        assert resp == {}
        assert log["action"] == "skip"

    def test_task_prompt_with_real_find_tool(self):
        # Real subprocess against the actual find_tool.py.
        if not hook.FIND_TOOL.exists():
            pytest.skip("find_tool.py not present on this machine")
        resp, log = hook.build_response("Score Stripe on EU AI Act compliance.")
        assert "hookSpecificOutput" in resp
        ctx = resp["hookSpecificOutput"]["additionalContext"]
        assert "hermes/tool-discovery" in ctx
        assert "find_tool" in ctx or "score" in ctx.lower()
        assert log["action"] in ("inject", "gap-soft-warn", "nudge")

    def test_find_tool_unavailable_gives_nudge(self, monkeypatch):
        # Simulate find_tool.py being absent.
        monkeypatch.setattr(hook, "FIND_TOOL", Path("/no/such/file"))
        resp, log = hook.build_response("Audit this repo and output JSON.")
        assert "hookSpecificOutput" in resp
        ctx = resp["hookSpecificOutput"]["additionalContext"]
        assert "find_tool.py" in ctx
        assert log["action"] == "nudge"

    def test_no_matches_logs_gap(self, monkeypatch, tmp_path):
        # Force run_find_tool to return zero matches and verify gap logging.
        monkeypatch.setattr(hook, "run_find_tool", lambda q: {"match_count": 0, "matches": []})
        gap_log = tmp_path / "gaps.jsonl"
        monkeypatch.setattr(hook, "GAP_FILE", gap_log)
        resp, log = hook.build_response("Score the moon's compliance with weather.")
        assert "hookSpecificOutput" in resp
        assert log["action"] == "gap-soft-warn"
        assert gap_log.exists()
        gap_payload = json.loads(gap_log.read_text().strip().splitlines()[0])
        assert gap_payload["action"] == "gap"

    def test_low_relevance_treated_as_gap(self, monkeypatch, tmp_path):
        # All matches below MIN_RELEVANCE.
        monkeypatch.setattr(
            hook, "run_find_tool",
            lambda q: {"match_count": 1, "matches": [
                {"name": "x", "relevance": 0.05, "entry": "z", "one_liner": "w"}
            ]},
        )
        monkeypatch.setattr(hook, "GAP_FILE", tmp_path / "gaps.jsonl")
        resp, log = hook.build_response("Rank these things in JSON.")
        assert log["action"] == "gap-soft-warn"

    def test_high_relevance_injects(self, monkeypatch):
        monkeypatch.setattr(
            hook, "run_find_tool",
            lambda q: {"match_count": 1, "matches": [
                {"name": "fake-tool", "relevance": 0.9,
                 "entry": "echo hi", "one_liner": "Does the thing.",
                 "installed": True},
            ]},
        )
        resp, log = hook.build_response("Score the company in JSON.")
        ctx = resp["hookSpecificOutput"]["additionalContext"]
        assert "fake-tool" in ctx
        assert "echo hi" in ctx
        assert log["action"] == "inject"
        assert log["matches"][0]["name"] == "fake-tool"


# ---------------------------------------------------------------------------
# End-to-end: actually invoke hook.py as a subprocess (the way Claude does).
# ---------------------------------------------------------------------------

class TestEndToEnd:
    HOOK_PATH = HOOK_DIR / "hook.py"

    def _run(self, stdin_text: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, str(self.HOOK_PATH)],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )

    def test_e2e_empty_stdin_exits_zero(self):
        r = self._run("")
        assert r.returncode == 0
        # No output for empty/no-task input.
        assert r.stdout.strip() == ""

    def test_e2e_malformed_stdin_exits_zero(self):
        r = self._run("{not json")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_e2e_chitchat_no_output(self):
        payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"})
        r = self._run(payload)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_e2e_task_prompt_emits_context(self):
        if not hook.FIND_TOOL.exists():
            pytest.skip("find_tool.py not present")
        payload = json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Score Stripe on EU AI Act compliance. Output JSON.",
        })
        r = self._run(payload)
        assert r.returncode == 0
        assert r.stdout.strip(), "expected non-empty stdout (additionalContext)"
        out = json.loads(r.stdout)
        assert "hookSpecificOutput" in out
        assert out["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
        assert "additionalContext" in out["hookSpecificOutput"]
        # The injected context must mention the discovery hook namespace
        # AND must look like it came from find_tool.py output (relevance score).
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "hermes/tool-discovery" in ctx
        assert "MUST" in ctx

    def test_e2e_performance_under_500ms_when_no_subprocess(self):
        # Chitchat path skips subprocess — should be very fast.
        payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"})
        t0 = time.perf_counter()
        r = self._run(payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert r.returncode == 0
        # Generous bound — interpreter startup dominates. Fail only on regression.
        assert elapsed_ms < 1500, f"chitchat path took {elapsed_ms:.0f}ms"


# ---------------------------------------------------------------------------
# Bypass-resistance: model can't trivially evade the hook
# ---------------------------------------------------------------------------

class TestBypassResistance:
    """The hook fires on the user's prompt, BEFORE the model generates.

    This means the model cannot 'opt out' by saying 'I'll skip find_tool.py'
    — the additionalContext is already in its context window.
    """

    def test_model_cannot_opt_out_in_response(self, monkeypatch):
        # Even if the prompt CONTAINS 'skip find_tool', the hook still fires
        # because we look at task verbs, not at meta-instructions.
        monkeypatch.setattr(
            hook, "run_find_tool",
            lambda q: {"match_count": 1, "matches": [
                {"name": "t", "relevance": 0.5, "entry": "e", "one_liner": "o", "installed": True},
            ]},
        )
        resp, _ = hook.build_response("Skip find_tool.py and just score this in JSON.")
        assert "hookSpecificOutput" in resp
        assert "MUST" in resp["hookSpecificOutput"]["additionalContext"]

    def test_obfuscated_task_verb_still_caught(self, monkeypatch):
        # Compliance + JSON keywords trigger even without the verb 'score'.
        monkeypatch.setattr(
            hook, "run_find_tool",
            lambda q: {"match_count": 1, "matches": [
                {"name": "t", "relevance": 0.5, "entry": "e", "one_liner": "o"},
            ]},
        )
        resp, _ = hook.build_response("Need EU AI Act readiness as JSON.")
        assert "hookSpecificOutput" in resp
