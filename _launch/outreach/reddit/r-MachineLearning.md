# r/MachineLearning Draft

**Subreddit:** r/MachineLearning
**Flair:** Project

---

**Title:** [Project] agent-gorgon: 3-layer runtime enforcement for tool-vs-fabricate decisions in Claude Code agents

---

**Body:**

**Problem:** Autonomous agents with access to a registered tool registry systematically choose to generate structured output from training priors rather than invoking the registered tool. This happens even when (a) the tool's entry command is in CLAUDE.md, (b) the model is explicitly told to use it, and (c) the model acknowledges the instruction before generating the fabricated output.

**Why this matters beyond compliance use cases:** any agent pipeline where tool invocations are auditable and plain-text generation is not (scoring, classification, ranked lists, structured reports) has this exposure. The agent's output is indistinguishable from real tool output to a downstream consumer.

**What was tried and why it failed:**
- System prompt rules: acknowledged, ignored
- MCP tool registration: tool visible to model, model still fabricated
- PreToolUse/Bash hook: never fires on plain-text fabrication (the model made no tool call)
- Single UserPromptSubmit injection: injected context is processed then ignored at generation time

**The 3-layer architecture in agent-gorgon:**

Layer 1 (pre-generation): UserPromptSubmit hook runs find_tool.py against the prompt, injects top manifest matches as a hard instruction with exact entry commands into additionalContext. Intervention at first-token distribution shift.

Layer 2 (execution): PreToolUse/Bash hook pattern-matches against 10 shadow signals (hardcoded score fields, ad-hoc scoring function definitions, fabricated JSON in output statements). Exits 2 to block if a registered tool matches.

Layer 3 (post-generation): Stop hook compound signal detection - compliance keywords AND (score fields OR grade fields OR article-by-article structure) in the assistant message with no tool_use block in the transcript. Exits 2 to block stop, forces model to retry using the tool.

**Data:** No empirical measurement of false-positive rate or fabrication reduction rate exists yet. The repo has 105 tests covering the detection logic and subprocess integration. Production measurement is the obvious next step.

**Code:** https://github.com/roli-lpci/agent-gorgon
