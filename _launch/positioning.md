# Positioning — agent-gorgon

## Why Now

The Claude Code hook specification became stable in early 2026. The MCP ecosystem hit a tipping point around the same time — hundreds of registerable tools, dozens of community manifests, tool-discovery patterns becoming a standard pattern rather than an experiment. But the ecosystem assumed agents would reliably invoke registered tools. They do not.

The specific failure mode agent-gorgon addresses - an agent generating fabricated structured output despite a registered tool existing for the task - is not new. It was documented by multiple users in the Claude Code community as early as late 2025. What changed: the hook spec now gives you a lever early enough to matter. UserPromptSubmit fires before the first token. That is the intervention point that was previously missing. Before that hook, all defenses were post-hoc.

The EU AI Act enforcement calendar running to August 2026 creates additional pressure: organizations building AI systems for regulated use cases need auditable evidence that their agents used real tools, not training-prior confabulation. A log of tool invocations (which agent-gorgon's JSONL audit trail provides) is auditable. A JSON blob generated from training priors is not.

## ICP

**Who adopts this today:** A senior ML/infrastructure engineer at a 10-100 person startup building an internal Claude Code automation. They have written 5-20 YAML manifests for their own tools (scorers, classifiers, report generators). They have seen their Claude session produce output that looks exactly like what their tool would output - but they never called it. They are not sure how often this happens. They want it to stop.

**What they care about:** reliability of agent output in production, not research. They will read the README, run install.sh, check that tests pass, and look at the JSONL log file to confirm the hook fired. They will not read a paper. They will share it on internal Slack if it works on the first try.

**Where they find it:** Show HN (they check it 3x/week), r/LocalLLaMA (active), GitHub trending for Claude-related repos. Not Reddit ML — too academic for their use case.

## Competitor Delta

1. **Do nothing (status quo):** Most teams simply accept that agents hallucinate. They add "always use find_tool.py" to CLAUDE.md. This instruction is ignored by the model precisely when it matters most - high-confidence generation of plausible structured output. agent-gorgon does not rely on the model reading instructions; it intercepts at the runtime level.

2. **Prompt engineering / system prompt rules:** Fragile. The Stripe scoring failure documented in this repo's BLUEPRINT.md occurred despite explicit CLAUDE.md rules. The model acknowledged the rules, ignored them, then admitted it after the fact. System prompt rules are advisory. Hooks are enforcement.

3. **MCP tool registration (model-server tools visible to the model):** MCP registration makes tools discoverable but does not prevent the model from choosing to generate output directly instead of calling the tool. agent-gorgon is complementary to MCP - it can intercept Bash commands that reimplement an MCP tool's logic. The interception layer is the missing piece.

## Adjacent Interests

- **lintlang** (roli-lpci/lintlang) - static analysis for agent configs. If you are running lintlang to check your CLAUDE.md, you are exactly the person who also wants agent-gorgon on your hooks.
- **Claude Code hooks documentation** (docs.claude.com) - anyone who has read the hook spec and wondered "what would I actually use PreToolUse for" - this is the concrete answer.
- **OpenHands / SWE-agent audit work** - teams running autonomous coding agents who discovered they cannot fully audit what the agent did vs. claimed to do. The JSONL trail from agent-gorgon's hooks is a lightweight audit log.
