# Agent Gorgon

> Stop your AI agents from fabricating tool output when a registered tool exists for the task.

A 3-layer defense for [Claude Code](https://docs.claude.com/en/docs/claude-code) (and any agent runtime that supports hooks). Built by [Hermes Labs](https://github.com/roli-lpci).

## The problem

You give an agent a task: *"Score Stripe on EU AI Act compliance. Output JSON."*

You have a tool that does this — a real scorer with a real rubric, sitting in your registry. The agent **does not call it**. It generates plausible-looking JSON from training priors. `overall_score: 62`, `grade: "C+"`, article-by-article breakdown. All fabricated. Indistinguishable from real output to a casual reader. When asked, the agent admits: *"I had the rules but didn't act on them."*

This pattern is silently happening in production agent deployments everywhere. Anyone using Claude/GPT/etc. as an autonomous agent has shipped this kind of confabulation in customer-facing work and not noticed.

## The fix

Three hooks installed into Claude Code's settings.json. Each catches a different failure mode:

| Hook | When it fires | What it does |
|---|---|---|
| **`UserPromptSubmit`** | Before the model thinks | Searches the tool registry for matching tools, injects their entry commands directly into model context. Model can't claim it didn't know. |
| **`Stop`** | After the model finishes | Scans the assistant's response text for structured artifacts (JSON, tables) that match a manifest's output schema. If matched AND no tool was invoked → blocks with exit 2, forces re-run with the actual tool. |
| **`PreToolUse`** (Bash matcher) | Before a Bash command runs | Detects commands that reimplement registered tools (e.g., `python3 -c "score=62"`) and routes the agent to the canonical tool instead. |

Plus a discovery engine (`find_tool.py`) that reads YAML manifests describing each tool, returns copy-paste-ready entry commands.

## Quickstart

```bash
git clone https://github.com/roli-lpci/agent-gorgon ~/agent-gorgon
cd ~/agent-gorgon
bash install.sh
```

The installer:
1. Validates your `~/.claude/settings.json`
2. Registers all 3 hooks (idempotent)
3. Creates a log dir at `~/.claude/hooks/logs/`
4. Verifies registration

Then in a fresh Claude Code session, prompt:

```
Score Stripe on EU AI Act compliance. Output JSON.
```

If the architecture works, the model will discover and invoke the registered scoring tool instead of fabricating an answer.

## Test it

```bash
cd ~/agent-gorgon && python3 -m pytest tests/ -q
```

Each hook ships with its own test suite (36 + 45 + 24 cases respectively). Adversarial test suite included for the PreToolUse layer.

## Architecture

See [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) for the discovery engine spec.

```
agent-gorgon/
├── find_tool.py          # discovery engine — natural-language → tool match
├── manifests/            # YAML tool descriptors (schema in _template.yaml)
├── hooks/                # the 3 enforcement layers
├── tests/                # pytest suites
├── converters/           # format bridges (json↔csv, text↔json)
├── install.sh            # idempotent installer
└── docs/                 # blueprint + how-it-was-built
```

## Adding your own tools

Each tool you want the registry to discover gets a YAML manifest at `manifests/{tool-name}.yaml`. Copy `_template.yaml`, fill in `entry`, `input`, `output`, `tags`, and `category`. The engine auto-loads everything in `manifests/`.

The richer your manifest's `tags` and `description`, the better the matches.

## How this came to exist

Spec'd, built, and shipped in one evening using parallel subagent hackathons. The architecture you see here is the survivor of a 7-agent ship-or-die competition where each agent had to deliver a working, tested solution to the fabrication problem within ~10 minutes. The 3-layer defense was the synthesis-agent's winning architecture; the Stop-hook detection was contributed by the contrarian agent's analysis.

The fact that this is shippable today, by one person in one evening, on personal infrastructure costing roughly the price of a coffee — is the actual story. The technical components were already standard. Putting them together to enforce truthfulness in autonomous AI is not yet standard, but it should be.

## License

MIT — see [LICENSE](LICENSE).

## Related projects (Hermes Labs)

- [`lintlang`](https://github.com/roli-lpci/lintlang) — static linter for AI agent configs
- [`langquant`](https://github.com/roli-lpci/langquant) — LPCI proof: language scaffold as Markov state for stateless LLMs
- [`claude-router`](https://github.com/roli-lpci/claude-router) — scaffold-aware routing for Claude API
