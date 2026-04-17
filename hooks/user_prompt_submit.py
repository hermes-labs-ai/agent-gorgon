#!/usr/bin/env python3
"""tool_discovery_hook.py — UserPromptSubmit hook.

When the user's prompt contains a structured-output task verb (score, audit,
draft, classify, extract, rank, JSON, table, etc.), this hook:

  1. Runs ~/ai-infra/find_tool.py on the prompt itself
  2. Injects the top 3 matches (name, one-liner, exact entry command) into
     the model's context as `additionalContext`
  3. Logs the event to ~/.claude/hooks/logs/tool-discovery.jsonl for audit

Why UserPromptSubmit (not PreToolUse / Stop):
  - PreToolUse only fires AFTER the model has decided to call a tool. The
    failure mode here is the model NOT calling a tool. Useless.
  - Stop fires AFTER generation — fabrication has already happened. Forcing
    a re-run wastes a turn and burns tokens without changing instinct.
  - UserPromptSubmit fires BEFORE the model sees the prompt. Injecting
    concrete tool names + copy-paste syntax shifts the model's first token
    distribution from "generate plausible JSON" to "invoke tool X".

Bonus: the JSONL log doubles as a discovery analytics stream — Roli can
grep for which tools get suggested most, and which prompts trigger
`match_count: 0` (gaps in the manifest catalog).

Exit codes:
  0  - normal (additionalContext may or may not be injected)
  1  - non-blocking warning (logged, hook continues)
  2  - blocking error (Claude shows stderr to user). We never use this:
       a discovery hook should never block input.

Spec contract (Claude Code UserPromptSubmit hook):
  stdin  = {"hook_event_name":"UserPromptSubmit","prompt":"...", ...}
  stdout = JSON {"hookSpecificOutput": {"hookEventName":"UserPromptSubmit",
                                        "additionalContext":"..."}}
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

HOME = Path.home()
FIND_TOOL = HOME / "ai-infra" / "find_tool.py"
LOG_DIR = HOME / ".claude" / "hooks" / "logs"
LOG_FILE = LOG_DIR / "tool-discovery.jsonl"
GAP_FILE = LOG_DIR / "tool-discovery-gaps.jsonl"

# Hard timeout on find_tool.py subprocess (seconds). The hook itself runs
# under Claude Code's per-hook timeout (we recommend 5s in INTEGRATION.md).
SUBPROCESS_TIMEOUT_S = 3.0

# Max chars of prompt we forward to find_tool.py (it's a keyword scorer,
# more text = more noise, not signal).
MAX_QUERY_CHARS = 400

# Minimum relevance to inject (find_tool returns 0.0-1.0).
MIN_RELEVANCE = 0.20

# How many top matches to inject.
TOP_K = 3

# Task-verb patterns that indicate structured output. Matching is
# case-insensitive, word-boundary anchored. Hand-curated from the failure
# modes Roli enumerated (score, audit, draft, classification, JSON, table,
# ranked list, extraction).
TASK_VERB_PATTERNS = [
    r"\bscore\b", r"\bscoring\b", r"\bscored\b",
    r"\baudit\b", r"\bauditing\b", r"\baudited\b",
    r"\bdraft\b", r"\bdrafting\b", r"\bdrafted\b",
    r"\bclassif(?:y|ies|ication|ying)\b",
    r"\bextract(?:ion|ing|ed)?\b",
    r"\brank(?:ed|ing)?\b",
    r"\brate\b", r"\brating\b",
    r"\bevaluate\b", r"\bevaluation\b",
    r"\bassess(?:ment|ing|ed)?\b",
    r"\banalyz(?:e|ing|ed)\b", r"\banalys(?:e|ing|ed|is)\b",
    r"\bcompar(?:e|ing|ed|ison)\b",
    r"\bsummariz(?:e|ing|ed)\b",
    # Output-shape signals
    r"\bjson\b", r"\byaml\b", r"\bcsv\b", r"\btsv\b",
    r"\btable\b", r"\bspreadsheet\b",
    r"\bmarkdown\s+report\b", r"\breport\b",
    r"\blist\b.{0,30}\b(top|all|every|each)\b",
    r"\bbullet\b.{0,20}\b(list|points)\b",
    r"\bbreakdown\b",
    r"\bchecklist\b",
    # Compliance-specific (this is a Hermes Labs machine)
    r"\beu\s*ai\s*act\b",
    r"\bcompliance\b",
    r"\bgdpr\b",
    r"\barticle\s*\d+\b",
]
TASK_VERB_RE = re.compile("|".join(TASK_VERB_PATTERNS), re.IGNORECASE)

# Anti-pattern: if the prompt is clearly chitchat, skip. We check after
# task-verb match because "rate this song" still triggers the hook (a tool
# might exist for it; if not, find_tool returns nothing and we no-op).
CHITCHAT_HINTS = re.compile(
    r"^\s*(hi|hello|hey|thanks|thank you|ok|okay|cool|nice|lol|yo|sup)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _safe_log(payload: dict, target: Path = LOG_FILE) -> None:
    """Append one JSON line. Never raises; logs are best-effort."""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except (OSError, TypeError, ValueError):
        # Logging must never break the hook. Silent failure is correct here.
        pass


def parse_stdin(raw: str) -> dict:
    """Parse stdin payload. Empty/garbage input returns an empty dict."""
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def extract_prompt(payload: dict) -> str:
    """Pull the user prompt out of the hook payload. Tolerant of shape drift."""
    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        return prompt
    # Some Claude Code versions nest under hook_event_data
    nested = payload.get("hook_event_data")
    if isinstance(nested, dict):
        p = nested.get("prompt")
        if isinstance(p, str):
            return p
    return ""


def is_task_prompt(prompt: str) -> bool:
    """True if the prompt asks for structured output a tool likely produces."""
    if not prompt or not prompt.strip():
        return False
    if CHITCHAT_HINTS.match(prompt):
        return False
    return bool(TASK_VERB_RE.search(prompt))


def run_find_tool(query: str) -> dict | None:
    """Invoke find_tool.py with --json. Returns parsed dict or None.

    Gracefully degrades if Python is missing, find_tool.py is missing, or
    the subprocess errors / times out.
    """
    if not FIND_TOOL.exists():
        return None
    python = shutil.which("python3") or shutil.which("python")
    if not python:
        return None

    truncated = query[:MAX_QUERY_CHARS].strip()
    if not truncated:
        return None

    try:
        # find_tool.py emits JSON by default. --pretty would give human text;
        # we want raw JSON for parsing.
        result = subprocess.run(
            [python, str(FIND_TOOL), truncated],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return None


def format_context(matches: list[dict], prompt_excerpt: str) -> str:
    """Render the additionalContext block injected into the model's prompt.

    Phrased as a HARD instruction, not a suggestion. The fabrication failure
    came from the model treating CLAUDE.md rules as background knowledge;
    here we put the exact entry commands inline so the cheapest path forward
    is to RUN one of them, not to invent output.
    """
    lines = [
        "[hermes/tool-discovery] Your prompt looks like a structured-output",
        "task. The Hermes tool vault has registered tools for this. You MUST",
        "either (a) invoke one of these via Bash, or (b) state explicitly",
        "WHY none apply before generating any structured output yourself.",
        "Fabricating a score / audit / classification without invoking a",
        "registered tool is a known failure mode and is forbidden.",
        "",
        f"Top {len(matches)} matches from `find_tool.py {prompt_excerpt!r}`:",
        "",
    ]
    for i, m in enumerate(matches, start=1):
        name = m.get("name", "?")
        one = m.get("one_liner") or m.get("description", "")
        entry = m.get("entry", "")
        rel = m.get("relevance", 0.0)
        installed = "[installed]" if m.get("installed") else "[not installed]"
        lines.append(f"{i}. {name}  (relevance={rel:.2f}) {installed}")
        if one:
            lines.append(f"   {one}")
        if entry:
            lines.append(f"   $ {entry}")
        lines.append("")
    lines.append(
        "If none of these fit, run: "
        "`python3 ~/ai-infra/find_tool.py \"<your query>\"` "
        "and explain the gap before fabricating."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_response(prompt: str) -> tuple[dict, dict]:
    """Pure function: prompt -> (hook_response, log_record).

    Separated from main() so tests can exercise the full pipeline without
    monkey-patching stdin/stdout.
    """
    log_base = {
        "ts": _now_iso(),
        "prompt_chars": len(prompt or ""),
        "prompt_excerpt": (prompt or "")[:160],
    }

    if not is_task_prompt(prompt):
        log = {**log_base, "action": "skip", "reason": "no-task-verb"}
        return ({}, log)

    excerpt = prompt.strip().splitlines()[0][:80]
    found = run_find_tool(prompt)
    if found is None:
        # Graceful degradation: nudge the model to use find_tool.py manually.
        ctx = (
            "[hermes/tool-discovery] Your prompt requests structured output. "
            "Before fabricating, run: "
            "`python3 ~/ai-infra/find_tool.py "
            f"\"{excerpt}\"` "
            "to check the tool vault. (Hook could not auto-query the registry.)"
        )
        response = {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": ctx,
            }
        }
        log = {**log_base, "action": "nudge", "reason": "find-tool-unavailable"}
        return (response, log)

    matches = [
        m for m in (found.get("matches") or [])
        if isinstance(m, dict) and float(m.get("relevance", 0.0) or 0.0) >= MIN_RELEVANCE
    ][:TOP_K]

    if not matches:
        # No relevant tool — record a GAP for Roli to mine later.
        gap_record = {
            **log_base,
            "action": "gap",
            "match_count": found.get("match_count", 0),
            "top_relevance": (
                max((m.get("relevance", 0.0) for m in (found.get("matches") or [])), default=0.0)
            ),
        }
        _safe_log(gap_record, target=GAP_FILE)
        # Still inject a soft warning so the model knows we checked.
        ctx = (
            "[hermes/tool-discovery] Checked the tool vault for this prompt; "
            "no manifest crossed the relevance threshold. You may proceed, "
            "but flag this as a gap in the registry. "
            f"(Searched: {excerpt!r})"
        )
        response = {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": ctx,
            }
        }
        log = {**log_base, "action": "gap-soft-warn"}
        return (response, log)

    ctx = format_context(matches, excerpt)
    response = {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": ctx,
        }
    }
    log = {
        **log_base,
        "action": "inject",
        "matches": [
            {
                "name": m.get("name"),
                "relevance": m.get("relevance"),
                "installed": m.get("installed", False),
            }
            for m in matches
        ],
    }
    return (response, log)


def main() -> int:
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    payload = parse_stdin(raw)
    prompt = extract_prompt(payload)

    response, log_record = build_response(prompt)
    _safe_log(log_record)

    # Empty response = no additionalContext, no behavior change.
    if response:
        sys.stdout.write(json.dumps(response))
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    # Wrap in try/except so a bug in the hook NEVER blocks the user's prompt.
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — hook must never crash Claude
        try:
            _safe_log({
                "ts": _now_iso(),
                "action": "error",
                "error": repr(exc),
            })
        except Exception:
            pass
        sys.exit(0)
