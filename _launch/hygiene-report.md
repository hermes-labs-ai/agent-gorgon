# Hygiene Report — agent-gorgon (audit mode)

All proposed fixes land in proposed-edits.md + fixes.patch. No files edited directly.

| Check | Status | Notes |
|-------|--------|-------|
| README one-liner tagline | PASS | "Stop your AI agents from fabricating tool output when a registered tool exists for the task." Clear. |
| README install section | PASS | git clone + bash install.sh. Runnable. |
| README usage example | PASS | Quickstart with exact prompts. |
| README link to docs | PASS | docs/BLUEPRINT.md linked. |
| README license | PASS | MIT, linked. |
| llms.txt | MISSING | Needs creation. Proposed in proposed-edits.md. |
| CITATION.cff | NOT NEEDED | Not a research-artifact class. agent-framework does not require CFF. |
| LICENSE | PASS | MIT present. |
| Badges | MISSING | No CI badge, no license badge. Low priority — no PyPI package. |
| gh-metadata.sh | MISSING | Written below in gh-metadata.sh. |
| .github/ISSUE_TEMPLATE/ | MISSING | Optional but recommended. Low priority. |
| Test count accurate in README | NEEDS REVIEW | "36 + 45 + 24" — verify ordering matches actual test files. |
| 5 failing tests | BUG | See fixes.patch. One-line fix. |
| Dead imports | MINOR | `import os` unused in user_prompt_submit.py and pre_tool_use_bash.py. |
| Hackathon-origin log path | MINOR | pre_tool_use_bash.py:41 logs to ~/ai-infra/hackathon/... on fresh install. |

## Proposed llms.txt

To be created at repo root (proposed — do not apply directly):

```
# agent-gorgon

> Stop AI agents from fabricating tool output when a registered tool exists.

## What this is

agent-gorgon is a 3-layer enforcement system for Claude Code. It installs three hooks
into Claude Code's hook system that interdict the tool-fabrication failure mode at every
decision point: before the model generates (UserPromptSubmit), during Bash execution
(PreToolUse), and after the final response (Stop).

## Who it is for

Claude Code power users who maintain a local tool registry (YAML manifests describing
CLI tools, entry commands, input/output formats) and have observed their agent generating
plausible-looking structured output — compliance scores, audit JSON, ranked lists —
from training priors instead of invoking the actual registered tool.

## Entry points

- install.sh — idempotent installer for all 3 hooks
- find_tool.py — discovery engine, takes a natural-language query, returns matching tools
- hooks/user_prompt_submit.py — UserPromptSubmit hook
- hooks/pre_tool_use_bash.py — PreToolUse (Bash) hook
- hooks/stop.py — Stop hook

## Canonical URL

https://github.com/roli-lpci/agent-gorgon

## Related

- lintlang: https://github.com/roli-lpci/lintlang (static linter for AI agent configs)
- langquant: https://github.com/roli-lpci/langquant (LPCI proof — language scaffold as state)
- claude-router: https://github.com/roli-lpci/claude-router (scaffold-aware routing)

## Contact

Roli Bosch — https://github.com/roli-lpci
Hermes Labs — AI audit tooling
```
