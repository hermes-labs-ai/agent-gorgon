# X Thread Draft

---

**Tweet 1 (hook):**
Claude just fabricated what agent-gorgon does, two minutes before running agent-gorgon's launch pipeline. The tool that catches fabrication. Fabricated about. Here's the thread.

---

**Tweet 2:**
The original failure: task is "Score Stripe on EU AI Act compliance. Output JSON."

The agent had a real scoring tool registered. Produced 50 lines of JSON - overall_score: 62, grade: "C+", article-by-article - without calling it.

Afterward it said: "I had the rules but didn't act on them."

---

**Tweet 3:**
Five defense approaches were tried. All failed for the same underlying reason: they fired at the wrong point.

PreToolUse: never fires on plain-text fabrication.
System prompt rules: acknowledged and ignored.
MCP registration: discoverable but not enforced.

The model needs interception before the first token.

---

**Tweet 4:**
agent-gorgon is 3 Claude Code hooks:

1. UserPromptSubmit: fires pre-generation, injects registered tool entry commands as a hard instruction
2. PreToolUse/Bash: blocks Bash commands that reimplement registered tools
3. Stop: scans final response for fabricated structured output, forces retry if detected

---

**Tweet 5:**
The meta-irony: Claude described agent-gorgon as something that "extracts your MEMORY.md pattern" during this launch.

agent-gorgon has nothing to do with MEMORY.md. It's a tool-discovery hook defense system.

That exact failure mode - plausible confabulation, no tool call - is what it catches.

---

**Tweet 6:**
105 tests. MIT. One YAML manifest per tool in your registry.

The gaps log at ~/.claude/hooks/logs/tool-discovery-gaps.jsonl shows which task types your registry doesn't cover.

https://github.com/roli-lpci/agent-gorgon
