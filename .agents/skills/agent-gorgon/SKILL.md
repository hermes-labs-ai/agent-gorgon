---
name: agent-gorgon
description: Use when you need a runtime policy guard for an AI agent process — watching process, file, and network activity from user space, applying deterministic policy, and attempting SIGSTOP or SIGKILL on reviewed triggers — with an audit-only mode to rehearse policy before enforcing it. No SDK required, works against any PID.
license: MIT
compatibility: Requires Python 3.10+; installs via `pip install agent-gorgon` or runs standalone via `uvx agent-gorgon`. Optional LLM-assisted flag review needs a local Ollama instance; `--no-llm` runs on deterministic rules alone.
---

# agent-gorgon

agent-gorgon is a runtime policy guard for AI agent processes: it watches
process, file, and network activity from user space, applies deterministic
policy, and attempts SIGSTOP or SIGKILL on reviewed triggers — no SDK
required, works against any PID. Audit-only mode rehearses policy first;
every decision is logged as evidence.

## Use it for

- Watching an untrusted or experimental agent's process/file/network
  behavior against a declared policy scope, without modifying the agent
- Rehearsing a policy in `--audit-only` mode before enabling SIGSTOP/SIGKILL
  enforcement
- Producing a per-decision JSONL evidence log for post-hoc review
- Guarding any PID by process name or exact PID — no agent-side SDK or
  instrumentation required

## Do not use it for

- A sandbox or containment boundary by itself — it observes and can signal a
  process, it does not isolate its filesystem or network namespace
- Kernel-level or root-required enforcement guarantees — it operates from
  user space
- Silent production enforcement without first validating the policy in
  `--audit-only` mode against real traffic

## Quickstart

```bash
pip install agent-gorgon
agent-gorgon --scope starter --agent-pid <PID> --no-llm --audit-only
```

Or without installing, via [uv](https://docs.astral.sh/uv/):

```bash
uvx agent-gorgon --scope starter --agent-pid <PID> --no-llm --audit-only --poll 1
```

Real output watching a live process for a few seconds:

```
2026-09-15 16:33:25 [INFO] 🛡️  Agent Gorgon active
2026-09-15 16:33:25 [INFO]    PID: 78200
2026-09-15 16:33:25 [INFO]    Poll: 1.0s
2026-09-15 16:33:25 [INFO]    Control: audit-only (SIGSTOP/SIGKILL disabled)
2026-09-15 16:33:25 [INFO]    LLM: qwen3:4b disabled (rules only)
2026-09-15 16:33:25 [WARNING] ⚠️  FLAG [1/12]: process_exec: <observed command>
2026-09-15 16:33:25 [WARNING] ⚠️  FLAG [4/12]: file_read: ~/.cache/uv/.lock
```

## Commands

```
agent-gorgon --scope <starter|coding-agent|path-to-yaml> --agent-pid <PID> [--no-llm] [--audit-only] [--poll SECONDS] [--log-dir DIR]
agent-gorgon --scope <scope> --agent-name <name>   # resolves to a PID, must be unique
```

## Output shape

- Console: timestamped `INFO` lines on startup/config, `WARNING FLAG [n/total]`
  lines per policy-triggered event with the exact observed action
- `--log-dir`: one JSONL evidence file per run (`actions_<timestamp>.jsonl`),
  one record per decision
- `--audit-only`: flags are logged, no SIGSTOP/SIGKILL is ever sent
- Without `--audit-only`: reviewed triggers can receive SIGSTOP (pause) or
  SIGKILL (terminate)

## Common gotchas

- `--scope` is required; use `starter` for a low-disruption default policy,
  `coding-agent` for a policy tuned to coding-agent process trees, or a path
  to a custom scope YAML.
- `--agent-pid` and `--agent-name` are mutually exclusive; prefer
  `--agent-pid` — `--agent-name` errors if it resolves to more than one
  process.
- `--no-llm` disables the localhost Ollama probe entirely; without it, the
  tool expects Ollama reachable for LLM-assisted flag review.
- Always validate a new scope in `--audit-only` first — a first run against
  live traffic in enforcement mode can SIGKILL a process on an untuned
  policy.

## More

Full docs and scope YAML reference:
https://github.com/hermes-labs-ai/agent-gorgon
