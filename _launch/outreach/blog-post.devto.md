---
title: "Claude Fabricated What This Tool Does. This Tool Would Have Caught It."
published: false
tags: ["claudecode", "aiagents", "machinelearning", "opensource"]
canonical_url: https://github.com/roli-lpci/agent-gorgon
---

Two minutes before I ran agent-gorgon's launch pipeline on itself, Claude - the same model running the pipeline - fabricated what agent-gorgon does.

No tool call. No manifest lookup. It described the repo as something that "extracts your MEMORY.md pattern." That is not what it does. The real repo is a 3-layer hook defense system that stops Claude Code agents from generating plausible-looking structured output instead of invoking a registered tool.

The model had access to the actual source files. It chose to generate from training priors anyway.

That is the failure mode. That is what agent-gorgon catches.

---

## The Stripe Incident (origin)

The repo documents the original failure: a Claude Code session given the task "Score Stripe on EU AI Act compliance. Output JSON."

The agent had access to a real scoring tool - a rubric-based scorer with article-by-article weights, sitting in a YAML manifest at `~/ai-infra/manifests/hermes-score.yaml`. It did not call it.

What it produced: `{"overall_score": 62, "grade": "C+", "article_9": 14, "article_14": 16, ...}`. Approximately 50 lines of structured JSON. Indistinguishable from real tool output to anyone reading it casually. When asked afterward, the agent said: "I had the rules but didn't act on them."

This is not hallucination in the sense of making up facts. The structure was plausible. The failure is more subtle: the model took the path of least resistance (generate from training priors) when the correct path (invoke the registered tool) was available but required explicit action.

CLAUDE.md rules did not prevent it. Explicit system prompt instructions did not prevent it. The model acknowledged them and ignored them.

---

## Why the Existing Defenses Failed

Five defense approaches were tested in a parallel hackathon session before the 3-layer architecture emerged:

**MCP tool registration** - made the tool discoverable. Model still generated inline JSON rather than calling it.

**System prompt rules** - "always use find_tool.py." Acknowledged, ignored.

**PreToolUse/Bash interception** - never fired. The fabricating model emitted plain text. No Bash call was made. You cannot intercept what was never executed.

The synthesis: you need three intervention points:
1. Before the first token (UserPromptSubmit) - inject hard instructions with exact tool entry commands
2. During execution (PreToolUse/Bash) - catch Bash commands reimplementing registered tools
3. After generation (Stop) - scan for fabricated structured artifacts and force re-run

---

## How the Hooks Work

**Layer 1: UserPromptSubmit** (`hooks/user_prompt_submit.py`)

Fires before the model processes the user prompt. Runs `find_tool.py` against the prompt, injects top 3 manifest matches with entry commands into `additionalContext`. Hard instruction: "You MUST invoke one of these or explain why none apply before generating any structured output."

**Layer 2: PreToolUse/Bash** (`hooks/pre_tool_use_bash.py`)

Intercepts Bash commands matching shadow signals - patterns like `score = 62`, `def score_compliance(...)`, `"score": 84` in echo output. If a signal triggers and `find_tool.py` finds a confident match (relevance > 0.25): exit 2 (block), write real tool entry to stderr.

**Layer 3: Stop** (`hooks/stop.py`)

Scans the final assistant response for compound signals: compliance keyword AND (numeric score field OR grade field OR article-by-article structure). If detected with no tool_use block in the transcript: exit 2, force retry with registered tool.

---

## Install

```bash
git clone https://github.com/roli-lpci/agent-gorgon ~/agent-gorgon
cd ~/agent-gorgon
bash install.sh
python3 -m pytest tests/ -q
```

For each tool in your registry: copy `manifests/_template.yaml`, fill in `entry`, `input`, `output`, and `tags`.

105 tests. Apache-2.0. The gaps log at `~/.claude/hooks/logs/tool-discovery-gaps.jsonl` shows which task types your registry does not cover yet.
