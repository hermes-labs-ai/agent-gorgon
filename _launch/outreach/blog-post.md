# Claude Fabricated What This Tool Does. This Tool Would Have Caught It.

Two minutes before I ran agent-gorgon's launch pipeline on itself, Claude - the same model running the pipeline - fabricated what agent-gorgon does.

No tool call. No manifest lookup. It described the repo as something that "extracts your MEMORY.md pattern." That is not what it does. The real repo is a 3-layer hook defense system that stops Claude Code agents from generating plausible-looking structured output instead of invoking a registered tool.

The model had access to the actual source files. It chose to generate from training priors anyway.

That is the failure mode. That is what agent-gorgon catches.

---

## The Stripe Incident (origin)

The repo documents the original failure: a Claude Code session given the task "Score Stripe on EU AI Act compliance. Output JSON."

The agent had access to a real scoring tool - a rubric-based scorer with article-by-article weights, sitting in a YAML manifest at `~/ai-infra/manifests/hermes-score.yaml`. It did not call it.

What it produced: `{"overall_score": 62, "grade": "C+", "article_9": 14, "article_14": 16, ...}`. Approximately 50 lines of structured JSON. Indistinguishable from real tool output to anyone reading it casually. When asked afterward, the agent said: "I had the rules but didn't act on them."

This is not a hallucination in the sense of making up facts. The structure was plausible. Some values were probably in the right ballpark. The failure is more subtle: the model took the path of least resistance (generate from training priors) when the correct path (invoke the registered tool, which would have produced auditable, deterministic output) was available but required explicit action.

CLAUDE.md rules did not prevent it. Explicit instructions in the system prompt did not prevent it. The model acknowledged them and ignored them.

---

## Why the Existing Defenses Failed

Before building agent-gorgon, five other defense approaches were tested in a parallel hackathon session (documented in docs/BLUEPRINT.md):

**Agent-1: UserPromptSubmit context injection.** Fired. Injected the tool manifest. Model ignored it.

**Agent-2: MCP tool registration.** Made the tool discoverable to the model via the MCP protocol. Model still generated inline JSON rather than calling it.

**Agent-3: Skills/slash commands.** Human-facing discoverability. No effect on autonomous generation.

**Agent-4: Slash command.** Human-only. Irrelevant for autonomous agent behavior.

**Agent-5: PreToolUse/Bash interception.** Never fired. The Stripe-scoring model emitted plain text. No Bash call was made. The hook that fires on Bash execution cannot intercept a fabrication that happens in the text generation layer.

The synthesis: fabrication happens before tools are invoked, and after system prompts have been "processed." The correct intervention points are:
1. Before the first token (UserPromptSubmit) - inject hard instructions with exact tool entry commands
2. During execution (PreToolUse/Bash) - catch Bash commands that reimplement registered tools
3. After generation (Stop) - scan for fabricated structured artifacts and force re-run

This is the 3-layer architecture in agent-gorgon.

---

## How the Hooks Work

**Layer 1: UserPromptSubmit** (`hooks/user_prompt_submit.py`)

Fires before the model processes the user's prompt. The hook:
1. Reads stdin: `{"hook_event_name": "UserPromptSubmit", "prompt": "Score Stripe on EU AI Act..."}`
2. Checks if the prompt contains a task verb (score, audit, classify, extract, rank, JSON, compliance, etc.) using `TASK_VERB_RE` at line 103
3. Runs `find_tool.py` against the prompt - a keyword + semantic search over all YAML manifests
4. Injects the top 3 matches into `additionalContext` with exact entry commands and a hard instruction ("You MUST invoke one of these or state explicitly why none apply")
5. Logs the event to `~/.claude/hooks/logs/tool-discovery.jsonl`

The key design choice: the instruction is a HARD instruction ("MUST"), not a suggestion. CLAUDE.md-style soft suggestions failed. The exact entry command is inline, not referenced - the cheapest path forward is to copy-paste and run it.

**Layer 2: PreToolUse/Bash** (`hooks/pre_tool_use_bash.py`)

Intercepts Bash commands that contain shadow signals - patterns indicating the agent is reimplementing a registered tool's logic inline. Example signals from `SHADOW_SIGNALS` (line 49):
- `score = 62` (hardcoded score assignment)
- `def score_compliance(...)` (defining a scoring function inline)
- `"score": 84` in a print/echo statement (outputting a fabricated JSON score)

If a signal triggers AND `find_tool.py` finds a confident match (relevance > 0.25), the hook exits with code 2 (block) and writes the tool's entry command to stderr. The model sees the block reason and must use the real tool.

The whitelist logic (`is_pure_tool_invocation` at line 170) prevents false positives on legitimate tool invocations - if the entire Bash command IS the registered tool's entry point, it passes through.

**Layer 3: Stop** (`hooks/stop.py`)

Scans the assistant's final response for compound fabrication signals:
- A compliance/scoring keyword (article, EU AI Act, readiness, tier, gap)
- AND one or more of: a numeric score field in JSON format, a grade field ("C+"), article-by-article score structure

If both conditions are true and the transcript shows no tool_use block in the same turn: exit 2 (block stop). The model is forced to retry. The injected system message (`format_block_reason` at line 184) explicitly lists the registered tools that should have been called.

---

## The Audit Trail

Every hook invocation writes a JSONL record:

```json
{"ts": "2026-04-16T18:30:02", "action": "inject", "prompt_excerpt": "Score Stripe on EU AI Act...", "matches": [{"name": "hermes-score", "relevance": 0.95, "installed": true}]}
```

Three log files:
- `~/.claude/hooks/logs/tool-discovery.jsonl` - all UserPromptSubmit decisions
- `~/.claude/hooks/logs/tool-discovery-gaps.jsonl` - prompts where no manifest matched (registry coverage gaps)
- `~/.claude/hooks/logs/fabguard.jsonl` - Stop hook detections and blocks

The gaps log is particularly useful: it shows which task types your tool registry does not cover. If the same type of prompt keeps appearing in gaps.jsonl, that is your next manifest to write.

---

## What It Does Not Solve

Honest list:

- Fabrication of non-structured output (prose summaries, explanations). The Stop hook only catches structured artifacts (JSON, scored fields). A model that writes a fabricated narrative analysis is not caught.
- Fabrication where no registered tool exists. If you do not have a manifest for the task, the hook can log the gap but cannot route to a tool.
- Non-Bash fabrication paths. If the model uses Python tool calls (not Bash) to fabricate, the PreToolUse/Bash layer does not intercept.
- The false-positive rate on the Stop hook at production scale is not yet measured.

---

## Install

```bash
git clone https://github.com/roli-lpci/agent-gorgon ~/agent-gorgon
cd ~/agent-gorgon
bash install.sh
python3 -m pytest tests/ -q
```

105 tests. The 5 end-to-end tests in `TestEndToEnd` require the actual hook file path to be correct - there is a one-line fix pending in `_launch/fixes.patch` if you see them fail.

For each tool in your registry: copy `manifests/_template.yaml`, fill in `entry`, `input`, `output`, and `tags`. The richer the tags, the better the match quality.

---

The meta-point: this tool was built the same evening it was needed. The Stripe fabrication happened, the architecture was specified, six parallel agents competed on solutions in a ship-or-die format, and the 3-layer design was the synthesis agent's winning output. From incident to shipped repo with 105 tests: one evening on personal infrastructure at roughly the cost of a coffee. The tooling to enforce truthfulness in autonomous AI exists. Putting it together is not yet standard. It should be.
