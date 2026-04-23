# agent-gorgon

**Stop AI agents from fabricating tool output when a registered tool exists.** A 3-layer hook defense for [Claude Code](https://docs.claude.com/en/docs/claude-code) and any agent runtime that supports `UserPromptSubmit` / `PreToolUse` / `Stop` hooks.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-116%20passing-brightgreen)](tests)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![Hermes Seal](https://img.shields.io/badge/hermes--seal-manifest%20staged-blue)](https://hermes-labs.ai)

![agent-gorgon](docs/hero.jpg)

## Pain

- An agent has tools registered for a task and invents the output anyway. Plausible JSON, plausible rubric, nothing real behind it.
- Fabricated output is indistinguishable from real output in a quick read. You catch it months later, in front of a customer.
- "Use the tool" in the system prompt doesn't save you — the model decided, mid-response, that it already knew.
- You don't want a 6-month OPA/policy-engine project for what is essentially: *don't skip the tool.*
- You want defense-in-depth: the model is told at prompt time, the output is checked at finish time, and the shell path is blocked from reimplementing.

## The pattern this breaks

You have a registered tool for a scored audit task. You prompt:

> "Score this agent on EU AI Act compliance. Output JSON."

The agent generates plausible-looking JSON from training priors. `overall_score: 62`, `grade: "C+"`, article-by-article breakdown. All fabricated. When you ask why, the agent says: *"I had the rules but didn't act on them."*

This happens quietly in production deployments. Anyone shipping Claude/GPT/etc. as an autonomous agent has almost certainly shipped this confabulation in customer-facing work and not noticed yet.

## The fix

Three hooks installed into your Claude Code `settings.json`. Each catches a different failure mode:

| Hook | When it fires | What it does |
|---|---|---|
| **`UserPromptSubmit`** | Before the model thinks | Searches the tool registry for matching tools, injects entry commands directly into model context. Model can't later claim it didn't know. |
| **`Stop`** | After the model finishes | Scans the assistant's response for structured artifacts (JSON, tables) whose shape matches a manifest's output schema. If matched AND no tool was invoked → blocks with exit 2, forces re-run with the actual tool. |
| **`PreToolUse`** (Bash matcher) | Before a Bash command runs | Detects commands that reimplement a registered tool (e.g., `python3 -c "score = 62"`) and routes the agent to the canonical tool instead. |

Plus a discovery engine — `find_tool.py` — that reads YAML manifests describing each tool and returns copy-paste-ready entry commands. Natural-language query in, ranked tool matches out.

## Install

```bash
git clone https://github.com/roli-lpci/agent-gorgon
cd agent-gorgon
bash install.sh
```

The installer:

1. Validates your `~/.claude/settings.json`
2. Registers all 3 hooks (idempotent — safe to re-run)
3. Creates a log dir at `~/.claude/hooks/logs/`
4. Verifies registration

Python 3.10+. Zero runtime dependencies (stdlib only).

## Verify it works

In a fresh Claude Code session, give the agent a task that matches a registered tool in `manifests/`. You should see the registered tool invoked rather than the agent fabricating output. If the agent still fabricates, check `~/.claude/hooks/logs/` for hook activity.

## Tests

```bash
cd agent-gorgon && python3 -m pytest tests/ -q
```

**116 tests.** Each hook has its own suite covering the happy path plus bypass resistance (can the model opt out via prompt wording? obfuscated task verbs? malformed stdin?). Adversarial test suite included for the `PreToolUse` layer.

## Architecture

See [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) for the full discovery-engine spec.

```
agent-gorgon/
├── find_tool.py      # discovery engine — natural-language → tool match
├── manifests/        # YAML tool descriptors (schema in _template.yaml)
├── hooks/            # the 3 enforcement layers
├── tests/            # pytest suites (116 tests)
├── converters/       # format bridges (json↔csv, text↔json)
├── install.sh        # idempotent installer
└── docs/             # blueprint + hero image
```

## Adding your own tools

Copy `manifests/_template.yaml` to `manifests/{tool-name}.yaml` and fill in `entry`, `input`, `output`, `tags`, `category`, and `description`. The engine auto-loads everything in `manifests/`.

The richer the `tags` and `description`, the better the matches `find_tool.py` produces.

## When to use it

- You're running Claude Code (or an equivalent) with registered tools and seeing fabricated output.
- You want a deterministic "did the agent actually call the tool?" check, not a model-judge approximation.
- You're shipping agent work to customers and need an auditable trail of tool invocations vs. model-generated output.

## When not to use it

- Single-shot chat where no tools are registered — there's nothing to enforce.
- Agent runtimes without hook points (many orchestration frameworks don't support pre/post hooks). This design requires Claude Code or a runtime that exposes `UserPromptSubmit` / `PreToolUse` / `Stop`.
- If your goal is to block network egress or sandbox the agent — that's a different layer (use a process-level sandbox).

## Origin

Spec'd, built, and tested in one evening using parallel subagent hackathons. The architecture is the survivor of a 7-agent ship-or-die round where each agent had ~10 minutes to deliver a working, tested solution to the fabrication problem. The 3-layer defense is the synthesis-agent's architecture; the `Stop`-hook detection came from the contrarian agent's analysis. Full build log is in [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md).

## Security and supply chain

- Staged `hermes-seal` v1 manifest at `.hermes-seal.yaml` (if present). Signature is granted out-of-band by the Hermes Labs internal sealing toolchain.
- Zero runtime dependencies by design — stdlib only.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

---

## About Hermes Labs

[Hermes Labs](https://hermes-labs.ai) builds AI audit infrastructure for enterprise AI systems — EU AI Act readiness, ISO 42001 evidence bundles, continuous compliance monitoring, agent-level risk testing. We work with teams shipping AI into regulated environments.

**Our OSS philosophy — read this if you're deciding whether to depend on us:**

- **Everything we release is MIT, fully free, forever.** No "open core," no SaaS tier upsell, no paid version with the features you actually need. You can run this entire repo commercially, without talking to us.
- **We open-source our own infrastructure.** This hook defense, and the other tools listed below, are what Hermes Labs uses internally to audit its own agents and produce deliverables for customers. We don't publish demo code — we publish production code.
- **We sell audit work, not licenses.** If you want an ANNEX-IV pack, an ISO 42001 evidence bundle, gap analysis against the EU AI Act, or agent-level red-teaming delivered as a report, that's at [hermes-labs.ai](https://hermes-labs.ai). If you just want the code to run it yourself, it's right here.

**The Hermes Labs OSS stack** (public, MIT, production-grade):

| Tool | What it does |
|---|---|
| **[lintlang](https://github.com/roli-lpci/lintlang)** | Static linter for AI agent configs, tool descriptions, system prompts. Zero-LLM CI gate. `pip install lintlang` |
| **[agent-convergence-scorer](https://github.com/roli-lpci/agent-convergence-scorer)** | Score how similar N agent outputs are — exact match, Jaccard, divergence point, composite. `pip install agent-convergence-scorer` |
| **[little-canary](https://github.com/roli-lpci/little-canary)** | Prompt injection detection for LLM apps using sacrificial canary-model probes + structural preflight |
| **[hermes-jailbench](https://github.com/roli-lpci/hermes-jailbench)** | Jailbreak regression benchmark for LLM endpoints — repeatable known-pattern attacks, deterministic scoring |
| **[claude-router](https://github.com/roli-lpci/claude-router)** | Router that picks the right Claude model tier + scaffold using local embeddings |
| **[zer0dex](https://github.com/roli-lpci/zer0dex)** | Local dual-layer memory for AI agents — compressed index + vector retrieval |
| **[colony-probe](https://github.com/roli-lpci/colony-probe)** | Defensive prompt confidentiality audit — detects system-prompt reconstruction via multi-turn probing |
| **[suy-sideguy](https://github.com/roli-lpci/suy-sideguy)** | Runtime policy guard for autonomous agents — user-space enforcement + forensic reporting |
| **[rule-audit](https://github.com/roli-lpci/rule-audit)** | Static prompt audit — contradictions, coverage gaps, priority ambiguities, edge cases |
| **[intent-verify](https://github.com/roli-lpci/intent-verify)** | Repo intent verification + spec-drift checks against markdown specs and handoffs |
| **[quick-gate-python](https://github.com/roli-lpci/quick-gate-python)** / **[quick-gate-js](https://github.com/roli-lpci/quick-gate-js)** | Quality-gate CLI with bounded auto-repair + escalation artifacts |
| **[repo-audit](https://github.com/roli-lpci/repo-audit)** | 15-second launch-readiness punch-list for any public GitHub repo |

Natural pairing: `agent-gorgon` enforces tool invocation; `lintlang` audits the agent config that declared the tool; `agent-convergence-scorer` measures whether your enforced-tool outputs are actually consistent across runs.

---

Built by [Hermes Labs](https://hermes-labs.ai) · [@roli-lpci](https://github.com/roli-lpci)
