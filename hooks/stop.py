#!/usr/bin/env python3
"""FabGuard Stop Hook — intercepts fabricated structured output before the model stops.

This is the ONLY hook layer that catches the exact Stripe failure:
  - Model was prompted: "Score Stripe on EU AI Act compliance. Output JSON."
  - Model emitted ~50 lines of structured JSON (overall_score: 62, grade: "C+") in plain text
  - ZERO tool calls made
  - Model admitted: "I had the rules but didn't act on them."

None of the prior 5 agents caught this because:
  - Agent-1 (UserPromptSubmit): Fired, injected context. Model ignored it.
  - Agent-2 (MCP): Discoverability. Model still chose to fabricate.
  - Agent-3 (Skills): Discoverability. Model still chose to fabricate.
  - Agent-4 (Slash): Human-only. No effect on autonomous generation.
  - Agent-5 (PreToolUse/Bash): NEVER FIRED — the Stripe model emitted plain text, no Bash call.

The Stop hook fires AFTER the model's final response is assembled, BEFORE it is
shown to the user. If fabricated structured output is detected AND a registered
tool exists for it, exit code 2 blocks the stop and injects a system message
telling the model to retry using the tool.

Hook contract (Claude Code Stop hook):
  stdin:  JSON with stop_hook_active, transcript, session_id, etc.
  stdout: JSON with decision and reason (if blocking)
  exit 0: allow stop (response shown to user)
  exit 2: block stop (model MUST continue; system message injected)

Spec reference: Claude Code hook docs — Stop hook, exit 2 blocks stop.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FIND_TOOL = Path.home() / "ai-infra" / "find_tool.py"
LOG_FILE = Path.home() / ".claude" / "hooks" / "logs" / "fabguard.jsonl"
MIN_RELEVANCE = 0.25

# Patterns that signal the assistant message contains fabricated structured output.
# We look for combinations: a scoring/compliance keyword PLUS a numeric score or
# JSON structure present in the same message. Single patterns create false positives.
#
# Design: match on the ASSISTANT message (last non-human turn in transcript).
# We extract it and scan for compound signals.

# Signal 1: explicit numeric score fields (JSON-style or prose)
SCORE_FIELD_RE = re.compile(
    r'(?:'
    r'"(?:overall_score|score|readiness_score|compliance_score|risk_score)"\s*:\s*\d+'
    r'|'
    r'\b(?:overall_score|score|readiness_score)\s*[=:]\s*\d+'
    r')',
    re.IGNORECASE,
)

# Signal 2: EU AI Act / compliance framing in the same message
COMPLIANCE_RE = re.compile(
    r'\b(?:eu\s*ai\s*act|gdpr|compliance|article\s*\d+|readiness|tier|gap)\b',
    re.IGNORECASE,
)

# Signal 3: JSON structure present (model emitted raw JSON, not a tool call)
JSON_STRUCTURE_RE = re.compile(
    r'\{[^}]{20,}(?:score|grade|tier|compliance|gap)[^}]{0,200}\}',
    re.IGNORECASE | re.DOTALL,
)

# Signal 4: grade field (the Stripe failure had grade: "C+")
GRADE_FIELD_RE = re.compile(
    r'"grade"\s*:\s*"[A-F][+-]?"',
    re.IGNORECASE,
)

# Signal 5: article-by-article scores (the Stripe failure had these)
ARTICLE_SCORE_RE = re.compile(
    r'"article_\d+"\s*:\s*\{[^}]{0,200}"score"',
    re.IGNORECASE | re.DOTALL,
)

# Query to pass to find_tool when fabrication is detected
COMPLIANCE_SCORE_QUERY = "eu ai act compliance scoring"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(record: dict) -> None:
    """Append a JSON record to fabguard.jsonl. Best-effort, never raises."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def extract_assistant_message(payload: dict) -> str:
    """Pull the last assistant message from the transcript in the hook payload."""
    transcript = payload.get("transcript") or []
    if not isinstance(transcript, list):
        return ""
    # Walk backwards to find the last assistant turn
    for turn in reversed(transcript):
        if not isinstance(turn, dict):
            continue
        role = turn.get("role", "")
        if role != "assistant":
            continue
        content = turn.get("content", "")
        if isinstance(content, str):
            return content
        # Content can be a list of blocks
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "")
                    if text:
                        parts.append(text)
                elif isinstance(block, str):
                    parts.append(block)
            return "\n".join(parts)
    return ""


def is_fabricated_output(text: str) -> tuple[bool, str]:
    """Return (is_fabricated, signal_description).

    Fabrication is detected when the assistant message contains BOTH:
      - A scoring/compliance keyword (Signal 2), AND
      - At least ONE of: numeric score field, JSON structure, grade field,
        article-by-article scoring

    This compound test minimises false positives on legitimate prose.
    """
    if not text or len(text) < 20:
        return False, ""

    has_compliance = bool(COMPLIANCE_RE.search(text))
    if not has_compliance:
        return False, ""

    if SCORE_FIELD_RE.search(text):
        return True, "numeric score field + compliance context"
    if GRADE_FIELD_RE.search(text):
        return True, "grade field + compliance context"
    if ARTICLE_SCORE_RE.search(text):
        return True, "article-by-article scores + compliance context"
    if JSON_STRUCTURE_RE.search(text):
        return True, "JSON compliance structure in plain text"

    return False, ""


def run_find_tool(query: str) -> list[dict]:
    """Call find_tool.py and return matches. Returns [] on any failure."""
    if not FIND_TOOL.exists():
        return []
    try:
        result = subprocess.run(
            [sys.executable, str(FIND_TOOL), query, "--limit=3"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        return [m for m in (data.get("matches") or [])
                if (m.get("relevance") or 0) >= MIN_RELEVANCE]
    except Exception:
        return []


def format_block_reason(signal: str, matches: list[dict]) -> str:
    """Format the block reason injected as system message to the model."""
    lines = [
        "=== FABGUARD BLOCKED: FABRICATED STRUCTURED OUTPUT ===",
        "",
        f"Signal: {signal}",
        "",
        "Your previous response contains what appears to be fabricated",
        "compliance/scoring output (structured JSON or numeric scores)",
        "generated WITHOUT invoking any registered tool.",
        "",
        "This is the exact failure mode this system is built to prevent.",
        "Registered tools exist for this task:",
        "",
    ]
    if matches:
        for m in matches:
            name = m.get("name", "?")
            one_liner = m.get("one_liner") or m.get("description", "")
            entry = m.get("entry", "")
            rel = m.get("relevance", 0)
            lines.append(f"  [{name}] (relevance={rel:.2f})")
            if one_liner:
                lines.append(f"    {one_liner}")
            if entry:
                lines.append(f"    Entry: $ {entry}")
            lines.append("")
    else:
        lines.append("  Run: python3 ~/ai-infra/find_tool.py \"compliance scoring\"")
        lines.append("")
    lines.extend([
        "REQUIRED ACTION: Invoke the tool above via Bash.",
        "Do NOT regenerate the JSON from memory.",
        "Do NOT explain why you cannot invoke the tool.",
        "Just run the tool.",
    ])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        # Cannot parse — fail open (allow stop)
        return 0

    ts = datetime.datetime.now().isoformat()

    # Extract assistant message from transcript
    assistant_text = extract_assistant_message(payload)

    if not assistant_text:
        log({"ts": ts, "action": "skip", "reason": "no-assistant-text"})
        return 0

    # Detect fabrication
    fabricated, signal = is_fabricated_output(assistant_text)

    if not fabricated:
        log({"ts": ts, "action": "allow", "chars": len(assistant_text)})
        return 0

    log({"ts": ts, "action": "detected", "signal": signal, "chars": len(assistant_text)})

    # Find real tools
    matches = run_find_tool(COMPLIANCE_SCORE_QUERY)

    log({"ts": ts, "action": "block", "signal": signal,
         "matches": [m.get("name") for m in matches]})

    # Build block response
    reason = format_block_reason(signal, matches)
    response = {
        "decision": "block",
        "reason": reason,
    }
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Hook must NEVER crash Claude Code
        sys.exit(0)
