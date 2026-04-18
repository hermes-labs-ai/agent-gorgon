# PR to kyrolabs/awesome-agents

**Target list:** https://github.com/kyrolabs/awesome-agents (2.2K stars, pushed 2026-04-14 - actively maintained)

**Why this list:** agent-gorgon is agent *safety infrastructure*, not an agent itself. kyrolabs/awesome-agents has a "Tools & Libraries" style section where reliability/safety tools fit.

**Alternative target if this one's category doesn't fit:** `Jenqyang/Awesome-AI-Agents` (1K stars, pushed today).

---

## PR title

`Add agent-gorgon: tool-fabrication defense for autonomous agents`

## PR body

Adding agent-gorgon, a defense mechanism that stops LLM-based autonomous agents from fabricating tool output when a real tool for the task exists. The pattern it catches: agent asked to "score X on compliance, output JSON" generates plausible JSON from training priors instead of calling the registered compliance-scorer tool, even when the tool's entry command is in its context.

Implements three Claude Code hooks (UserPromptSubmit, Stop, PreToolUse/Bash) plus a YAML-manifest discovery engine. Works with any agent runtime that supports hooks.

Relevant to this list because reliability tooling is a critical gap in agent infrastructure - agents that hallucinate work output are shipping in production without detection.

## Entry to add

Find the best-fit section (likely "Tools", "Libraries", or "Frameworks") and append:

```markdown
- [agent-gorgon](https://github.com/roli-lpci/agent-gorgon) - Three-layer hook defense that stops Claude Code agents from fabricating tool output when a registered tool exists for the task. YAML-manifest discovery engine, pytest-covered, MIT.
```

If the list has an emoji prefix convention per section, match it.

## Before submitting

- [ ] Read the list's CONTRIBUTING.md - some awesome-* lists require specific PR body format
- [ ] Confirm the section you're adding to doesn't restrict to "agents only" (some do - if so, retarget to Jenqyang/Awesome-AI-Agents)
- [ ] Keep entry description to a single line matching neighbors' length
- [ ] PR from a fork
