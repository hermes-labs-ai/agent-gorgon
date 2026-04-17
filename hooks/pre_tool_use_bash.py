#!/usr/bin/env python3
"""ToolShadow — PreToolUse hook that intercepts Bash commands shadowed by registered tools.

When Claude Code is about to execute a Bash command that reimplements something
a registered tool already does, this hook blocks the execution and returns the
correct tool invocation.

Unlike prompt injection (Agent-1) or MCP registration (Agent-2), this hook
operates at execution time — the model CANNOT bypass it by ignoring CLAUDE.md.
If the agent writes Python to fabricate a compliance score, ToolShadow catches
it here.

Hook contract (Claude Code PreToolUse):
  - stdin: JSON with tool_name, tool_input, session_id, etc.
  - stdout: JSON with systemMessage (optional context injection)
  - stderr: message shown to model as block reason
  - exit 0: allow
  - exit 2: block

Usage (in ~/.claude/settings.json hooks.PreToolUse):
  python3 ~/ai-infra/hackathon/agent-5-contrarian/tool_shadow.py
"""

from __future__ import annotations

import json
import re
import sys
import os
import subprocess
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

MANIFEST_DIR = Path.home() / "ai-infra" / "manifests"
FIND_TOOL = Path.home() / "ai-infra" / "find_tool.py"
MIN_RELEVANCE = 0.25          # Below this → allow (no confident match)
LOG_FILE = Path.home() / "ai-infra" / "hackathon" / "agent-5-contrarian" / "shadow.log"

# Whitelist: tool entry prefixes loaded at startup
TOOL_WHITELIST: list[str] = []

# Bash patterns that signal the agent is manually implementing something
# rather than delegating to a registered tool.
# Each tuple: (compiled_regex, human_readable_signal_name, query_for_find_tool)
SHADOW_SIGNALS: list[tuple[re.Pattern, str, str]] = [
    # Fabricating a numeric score inline
    (re.compile(r'\bscore\s*=\s*\d+', re.I), "hardcoded score assignment", "compliance scoring eu ai act"),
    # Writing ad-hoc scoring logic
    (re.compile(r'(compliance|readiness|eu.ai.act|eu_ai_act).{0,60}(score|rating|assess)', re.I),
     "manual compliance scoring", "eu ai act compliance score"),
    # Manually calling OpenAI/Anthropic for something a tool handles
    (re.compile(r'(openai|anthropic).{0,80}(score|audit|classify|assess)', re.I),
     "LLM-based manual scoring", "compliance scoring audit"),
    # Writing an ad-hoc dict/JSON score result
    (re.compile(r'["\']score["\']\s*:\s*\d+', re.I), "hardcoded JSON score field", "compliance scoring"),
    # Manual EU AI Act article checking (article9_check, article_14_assess, etc.)
    # Note: no \b — article9_check has '_' after digit which is a word char
    (re.compile(r'article.{0,3}(9|14|16|17|22|29|43|69)', re.I),
     "manual EU AI Act article check", "eu ai act compliance"),
    # Writing a scoring function from scratch
    (re.compile(r'def\s+\w*(score|audit|assess|compliance)\w*\s*\(', re.I),
     "defining scoring function inline", "compliance scoring audit"),
    # Manual GDPR/DPO checking (def check_gdpr, gdpr_check, etc.)
    (re.compile(r'(gdpr|dpo|data.protect)', re.I),
     "manual GDPR/DPO assessment", "gdpr compliance scoring"),
    # Outputting a fake score with print/echo
    (re.compile(r'(print|echo).{0,40}\d{1,3}.{0,20}(score|complian|readiness)', re.I),
     "printing fabricated score", "compliance scoring"),
    # Hardcoding audit results
    (re.compile(r'(tier|gap|recommendation).{0,40}=.{0,40}["\']', re.I),
     "hardcoding audit result fields", "compliance scoring audit"),
    # Manual bias/risk evaluation
    (re.compile(r'(bias|high.risk|risk.level).{0,60}(test|check|eval|score)', re.I),
     "manual bias/risk evaluation", "bias testing eu ai act audit"),
]

# Tool categories that override — if find_tool returns these categories, block
BLOCKING_CATEGORIES = {"gtm", "compliance", "audit", "research", "scoring"}


# --------------------------------------------------------------------------- #
# Whitelist loading and normalization
# --------------------------------------------------------------------------- #

def normalize_entry(entry: str) -> str:
    """
    Normalize a manifest entry to extract the essential command.

    Strip: leading 'cd ... && ', leading env vars like 'PYTHONPATH=... '
    Keep: the core command (python3 -m module.cli score, etc.)

    Example:
      Input:  'cd ~/path && PYTHONPATH=src python3 -m hermes_score.cli score --stdin'
      Output: 'python3 -m hermes_score.cli score'

    Returns the normalized prefix for substring matching.
    """
    # Strip leading 'cd ... && ' pattern
    match = re.match(r'cd\s+[^\s]+\s*&&\s*(.*)', entry)
    if match:
        entry = match.group(1)

    # Strip leading env vars: PYTHONPATH=... VAR=value ... (keep the command after)
    entry = re.sub(r'^([A-Z_]+=[^\s]+\s+)*', '', entry)

    # Extract the core command up to the first argument that looks like a flag or input
    # Keep: python3 -m module.cli command_verb
    # This ensures we match actual invocations without getting too broad
    parts = entry.split()
    if len(parts) >= 2:
        # Take first ~3-4 meaningful parts: python3 -m module command
        normalized = ' '.join(parts[:min(4, len(parts))])
        return normalized.strip()

    return entry.strip()


def load_tool_whitelist() -> list[str]:
    """
    Load all manifest entry points and normalize them for whitelist matching.
    Parses YAML manifest files (gracefully handles missing PyYAML).
    Returns list of normalized entries. Gracefully skips unreadable manifests.
    """
    whitelist = []

    if not MANIFEST_DIR.exists():
        return whitelist

    try:
        for manifest_file in MANIFEST_DIR.glob("*.yaml"):
            try:
                content = manifest_file.read_text()
                # Simple YAML parsing: extract entry: field
                # Pattern: entry: "...value..." or entry: ...value (multiline)
                entry_match = re.search(r'^entry:\s*["\']?(.+?)["\']*\s*$', content, re.MULTILINE)
                if entry_match:
                    entry = entry_match.group(1).strip().strip('\'"')
                    if entry:
                        normalized = normalize_entry(entry)
                        if normalized:
                            whitelist.append(normalized)
            except Exception:
                # Gracefully skip unreadable manifests
                pass
    except Exception:
        pass

    return whitelist


# --------------------------------------------------------------------------- #
# Utilities
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    """Append a line to shadow.log. Non-fatal if it fails."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            import datetime
            f.write(f"[{datetime.datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def is_pure_tool_invocation(command: str, whitelist: list[str]) -> bool:
    """
    Check if the ENTIRE command is a pure tool invocation (no chaining to non-tools).

    Strategy: Split on &&, ||, ; and check if ALL real (non-cd) segments are tool invocations.
    Also skip pure piping (echo | tool is ok, but tool && echo is NOT ok).

    Example:
      cd ~/path && PYTHONPATH=... python3 -m cli score ... → TRUE (cd is skipped, cli is tool)
      cd ~/path && ... && echo "fake" → FALSE (echo is not a tool)
      echo "data" | python3 -m cli score ... → TRUE (echo feeds tool, whole segment is tool)
      python3 -m cli && echo "score=62" → FALSE (two segments, second is not tool)

    Returns True if ALL non-cd segments are (or contain) tool invocations.
    """
    if not whitelist:
        return False

    # Split on logical operators (&&, ||, ;)
    segments = re.split(r'\s*(?:&&|\|\||;)\s*', command)

    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue

        # Skip pure 'cd' commands (they just change directory)
        if re.match(r'^cd\s+', segment):
            continue

        # For this segment, check if it contains a tool invocation
        # (handle pipes: any piped part that's a tool counts as tool invocation)
        segment_has_tool = False
        for part in segment.split('|'):
            part = part.strip()
            if not part:
                continue
            # Strip leading env vars
            part = re.sub(r'^([A-Z_]+=[^\s]+\s+)*', '', part)
            # Check against whitelist
            for entry in whitelist:
                if part.startswith(entry):
                    segment_has_tool = True
                    break
            if segment_has_tool:
                break

        # If this non-cd segment does NOT contain a tool, return False
        if not segment_has_tool:
            return False

    return True


def run_find_tool(query: str, limit: int = 3) -> list[dict[str, Any]]:
    """Call find_tool.py and return matches list. Returns [] on any failure."""
    if not FIND_TOOL.exists():
        return []
    try:
        result = subprocess.run(
            [sys.executable, str(FIND_TOOL), query, f"--limit={limit}"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        return data.get("matches", [])
    except Exception:
        return []


def format_block_message(signal: str, command_excerpt: str, matches: list[dict]) -> str:
    """Format the stderr block message shown to the model."""
    lines = [
        "=== TOOLSHADOW BLOCKED ===",
        f"Signal: {signal}",
        f"Command excerpt: {command_excerpt[:120]}",
        "",
        "You are reimplementing something a registered tool already does.",
        "Use the tool instead:",
        "",
    ]
    for m in matches:
        name = m.get("name", "?")
        one_liner = m.get("one_liner", m.get("description", ""))
        entry = m.get("entry", "")
        rel = m.get("relevance", 0)
        lines.append(f"  [{name}] (relevance={rel:.2f})")
        lines.append(f"    {one_liner}")
        lines.append(f"    $ {entry}")
        lines.append("")
    lines.append("Invoke the tool above. Do NOT fabricate the output.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Main hook logic
# --------------------------------------------------------------------------- #

def main() -> int:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except Exception:
        # Cannot parse input — allow (fail open)
        return 0

    tool_name = data.get("tool_name", "")
    if tool_name != "Bash":
        # Only intercept Bash calls
        return 0

    tool_input = data.get("tool_input", {})
    command = str(tool_input.get("command", ""))

    if not command.strip():
        return 0

    # --- Signal detection (happens before whitelist check) ---
    triggered: tuple[re.Pattern, str, str] | None = None
    for pattern, signal_name, query in SHADOW_SIGNALS:
        if pattern.search(command):
            triggered = (pattern, signal_name, query)
            break

    if triggered is None:
        return 0

    # --- Whitelist check: if signal triggered, check if this is a pure tool invocation ---
    _, signal_name, query = triggered
    whitelist = TOOL_WHITELIST if TOOL_WHITELIST else load_tool_whitelist()
    if is_pure_tool_invocation(command, whitelist):
        log(f"WHITELISTED TOOL INVOCATION (signal={signal_name!r}): CMD={command[:80]!r}")
        return 0

    log(f"SIGNAL={signal_name!r} CMD={command[:80]!r}")

    # --- Find real tool ---
    matches = run_find_tool(query)

    # Filter to confident matches only
    good_matches = [m for m in matches if (m.get("relevance") or 0) >= MIN_RELEVANCE]

    if not good_matches:
        # No confident match — allow (don't block spuriously)
        log(f"NO MATCH for query={query!r} — allowing")
        return 0

    log(f"BLOCKING — matches={[m.get('name') for m in good_matches]}")

    # --- Block with message ---
    excerpt = command[:200].replace("\n", " ")
    msg = format_block_message(signal_name, excerpt, good_matches)
    sys.stderr.write(msg + "\n")
    return 2  # Block tool execution


if __name__ == "__main__":
    sys.exit(main())
