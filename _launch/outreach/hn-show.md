# Show HN Draft

**Title:** Show HN: agent-gorgon - 3-layer Claude Code hooks that stop agents fabricating tool output

---

**Body:**

Two minutes before I ran this tool on itself, Claude fabricated what it does.

I asked Claude to describe agent-gorgon. Without invoking the repo's own find_tool.py, it invented: "agent-gorgon extracts your MEMORY.md pattern." That is not what it does. The real repo is a tool-discovery hook defense system. Claude had access to the actual files. It generated confident, plausible output from training priors instead of reading them.

That is the failure mode agent-gorgon is built to catch.

The repo installs three hooks into Claude Code's hooks system (UserPromptSubmit, Stop, PreToolUse/Bash). Each catches a different point in the fabrication cycle:

- UserPromptSubmit fires before the model generates. It runs find_tool.py against the prompt, injects the top 3 manifest matches (with exact entry commands) into additionalContext. The model cannot claim it did not know.
- PreToolUse/Bash detects Bash commands that reimplement a registered tool (e.g., hardcoding a compliance score inline) and blocks with exit 2.
- Stop scans the final assistant response for structured artifacts (JSON with score fields, grade fields, article-by-article breakdowns) that appear without a tool call. If detected: block, inject system message, force re-run.

105 tests, 3 hooks, one YAML manifest per tool in your registry. The log at ~/.claude/hooks/logs/tool-discovery.jsonl doubles as an audit trail showing which tools were suggested and which prompts hit gaps.

The architecture diagram in docs/BLUEPRINT.md shows why UserPromptSubmit is the right intervention point - PreToolUse only fires if the model decided to call a tool, which it does not when fabricating. Stop fires after fabrication has already occurred. UserPromptSubmit is the only hook that shifts the first-token distribution.

Repo: https://github.com/roli-lpci/agent-gorgon

What failure modes have you seen with Claude Code that this would or would not catch?

---

## First-hour engagement plan

1. **Reply within 10 minutes to the first commenter.** Have these pre-written responses ready:

   - If someone asks "does this work with non-Claude agents?" - Reply: "The hook spec is Claude Code specific, but the manifest format (YAML + find_tool.py) is portable. The concept translates to any agent runtime with pre-generation hooks. The core insight is that you need to fire before the first token, not after."

   - If someone pushes back "why not just use system prompts?" - Reply: "We did. The BLUEPRINT.md documents the exact failure: the model acknowledged the CLAUDE.md rules, generated fabricated output anyway, and admitted it post-hoc. System prompts are advisory. Hooks are enforcement. Different layer entirely."

   - If someone asks "what's the false-positive rate on the Stop hook?" - Reply: "Honest answer: not measured in production at scale yet. The compound signal (compliance keyword AND score field AND no tool call in transcript) is designed to minimize false positives. Real tool invocations leave tool_use blocks in the transcript that the hook checks for. The gap detection log (tool-discovery-gaps.jsonl) is how you tune it."

2. Do not upvote your own post. Do not ask others to.

3. Watch for technical comments - the hook spec details (exit code 2 semantics, additionalContext injection, transcript format) are interesting to practitioners. Go deep on those.

4. Post the X thread 1 hour after HN (not simultaneously - HN community dislikes coordinated cross-posting).

5. If it gets traction (>20 points in 2 hours), post the blog to DEV.to the same day.
