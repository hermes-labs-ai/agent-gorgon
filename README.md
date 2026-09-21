<div align="center">

<h1>Agent Gorgon</h1>

<img src="assets/agent-gorgon-artwork.jpg" width="620" alt="Agent Gorgon artwork: a watchful eye encircled by two coral serpents" />

<p><strong>Runtime policy guard for AI agent processes. Watch what an autonomous agent actually does, apply deterministic policy, and keep structured forensic receipts.</strong></p>

<p><a href="https://github.com/hermes-labs-ai/agent-gorgon">Agent Gorgon</a> is built by <a href="https://hermes-labs.ai">Hermes Labs</a>, an agent-driven infrastructure company building systems for when language becomes execution.</p>

<a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache--2.0-green.svg"></a>
<a href="https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://pypi.org/project/agent-gorgon/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/agent-gorgon"></a>
<a href="https://pypi.org/project/agent-gorgon/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/agent-gorgon"></a>

</div>

## The problem

Autonomous coding agents need shell access to be useful. Once they have it, they can spawn child processes, open network connections, read credentials, write outside the workspace, or run destructive commands.

Prompt guardrails and input filters can reduce risk before execution, but they do not observe everything the process tree actually does on the host after code starts running. Full kernel sandboxes can provide stronger isolation, but they also change the execution environment and are not always how developers want to run local coding agents.

Agent Gorgon adds a **reactive user-space runtime layer** around an existing agent process. It watches process, file, and network activity available from user space, applies deterministic policy, and records what it observed and what control action it attempted.

Start in audit-only mode. See what would have been flagged, halted, or killed. Review the evidence. Then decide whether to enable active controls.

## What it does

- **Wrap an existing agent command.** Use `agent-gorgon run` around Claude Code, Codex CLI, Aider, a custom harness, or another terminal workload without requiring that tool to adopt an SDK.
- **Attach to an existing PID.** Monitor a process you did not launch through Agent Gorgon.
- **Audit before enforcing.** Audit-only mode records verdicts without sending `SIGSTOP` or `SIGKILL`.
- **Apply deterministic controls.** Reviewed HALT and KILL policy can attempt process-tree signaling when enforcement is enabled.
- **Keep structured forensic receipts.** JSONL action evidence and incident reports distinguish the policy verdict, the signal attempt, and the observed process state.
- **Keep model analysis advisory.** Optional local Ollama analysis may provide context, but it cannot authorize HALT or KILL decisions.
- **Stay local by default.** Agent Gorgon includes no Hermes Labs telemetry or remote reporting client.

## Quickstart

Agent Gorgon requires Python 3.9+.

```bash
pip install agent-gorgon
agent-gorgon --version
```

The safest first real-world run is audit-only:

```bash
agent-gorgon run --audit-only --scope coding-agent -- <your agent command>
```

For example:

```bash
agent-gorgon run --audit-only --scope coding-agent -- claude
agent-gorgon run --audit-only --scope coding-agent -- codex
```

Audit-only evaluates the same policy path but sends no `SIGSTOP` or `SIGKILL`. When the wrapped command exits, Agent Gorgon prints a compact summary and writes evidence:

```text
agent-gorgon run: mode=audit-only exit=0 observed=14 safe=11 flags=3 would-halt=0 would-kill=0 evidence=/home/you/.local/share/agent-gorgon/logs/actions_20260911_101500.jsonl
```

Read that evidence before turning enforcement on.

When you have reviewed the scope against the exact workload and host environment, active signaling for `agent-gorgon run` is explicit:

```bash
agent-gorgon run --enforce --scope coding-agent -- <your agent command>
```

## Safe packaged audit demo

For a controlled calibration path with no real agent, network access, or credentials:

```bash
agent-gorgon-audit-demo --out /tmp/agent-gorgon-audit-demo.json
```

The demo launches owned fixtures, evaluates SAFE/HALT/KILL expectations in audit-only mode, writes a machine-readable receipt, and exits nonzero if an observed verdict does not match the declared ground truth.

See [`docs/EVIDENCE.md`](docs/EVIDENCE.md) for reproducible receipts, overhead measurements, and their limitations.

## Attach to an existing process

`agent-gorgon run` is the common path. PID mode is for a process that is already running:

```bash
agent-gorgon   --scope starter   --agent-pid <PID>   --no-llm   --audit-only
```

Prefer an exact PID over process-name matching.

## How it works

Agent Gorgon polls operating-system telemetry available to the monitored process tree through `psutil` and evaluates observations against the active scope.

The normal CLI poll interval is **0.5 seconds**. More aggressive intervals can be configured with `--poll`, with higher watcher overhead. The packaged audit harness uses shorter intervals for its controlled scenarios; those should not be confused with the CLI default.

| Verdict | Meaning | Response |
|---|---|---|
| `SAFE` | Observation is within active policy | Continue |
| `FLAG` | Suspicious or outside expected scope, below intervention threshold | Log and continue |
| `HALT` | Deterministic dangerous pattern matched | Attempt process-tree `SIGSTOP` and record evidence |
| `KILL` | Deterministic severe violation matched | Attempt process-tree `SIGKILL` and record evidence |

The optional local LLM path is advisory-only. Deterministic policy owns active control decisions.

### The `coding-agent` scope

`coding-agent` is a shipped **starter scope for coding-agent workloads**, not a universal or production-calibrated policy.

It is designed to make common development activity usable while surfacing behavior such as:

- reads of SSH, AWS, GPG, gcloud, GitHub, netrc, credential, and key material;
- outbound transfer utilities such as `curl`, `wget`, and `nc`;
- writes outside the expected workspace;
- network activity outside configured policy;
- destructive recursive deletion patterns.

The scope cannot know your repository layout, caches, credentials policy, network requirements, or threat model. Run it in audit-only mode first and adapt it to the workload.

See [`docs/HARNESS_RECIPES.md`](docs/HARNESS_RECIPES.md) for scenario and harness guidance.

## Structured forensic receipts

Agent Gorgon separates observation from claims about enforcement.

Default evidence locations include:

- `~/.local/share/agent-gorgon/warden.log`
- `~/.local/share/agent-gorgon/logs/actions_*.jsonl`
- `~/.local/share/agent-gorgon/logs/incidents/*.json`

Evidence directories are created for the current user and evidence files are restricted to that user where the host supports those permissions.

Generate a structured incident report from recent evidence:

```bash
agent-gorgon-forensic   --last-hours 24   --workspace /path/to/workspace   --evidence-dir ~/.local/share/agent-gorgon/logs   --out report.json
```

These are **structured forensic receipts**, not cryptographically immutable records. They are local evidence artifacts that should be protected and retained according to your environment.

## When to use Agent Gorgon

Use Agent Gorgon when you want:

- visibility into what an autonomous or semi-autonomous agent process actually does on the host;
- an audit-first way to rehearse runtime policy before signaling anything;
- deterministic user-space controls around an existing tool without an SDK integration;
- local evidence for review after a session;
- another layer in a defense-in-depth architecture alongside stronger isolation.

## Important boundaries

Agent Gorgon is deliberately explicit about what it does **not** prove.

- **Not a kernel sandbox.** It does not replace namespaces, seccomp, virtualization, or other kernel/VM isolation.
- **Reactive, not pre-execution interposition.** An action can begin or finish between polling observations.
- **User-space visibility is incomplete.** Short-lived children, file handles, or other activity can be missed depending on timing and operating-system visibility.
- **Snapshot diffs are not process attribution.** Unattributed filesystem changes are recorded but do not by themselves justify suspending a process.
- **Signal attempts are attempts.** A process tree can change while a signal is being applied, and operating-system behavior can differ.
- **A scope is not a proof of coverage.** Policies need calibration against each workload and environment.
- **Audit receipts describe the evaluated environment.** They are not cross-platform certification.

CI exercises Python 3.9–3.12 on Ubuntu. Production use outside the evaluated environments should be treated as unevaluated until validated for the exact host and workload. Active controls are POSIX-oriented.

## Privacy and network behavior

Agent Gorgon itself has no external telemetry or Hermes Labs reporting client.

Unless `--no-llm` is used, it may probe the configured local Ollama service, which defaults to `http://localhost:11434`, and may send local action context to that configured Ollama endpoint for advisory analysis.

`--no-llm` disables that advisory path.

Local evidence can contain sensitive paths, commands, and remote IP/port observations. Treat it as operationally sensitive data.

## Recommended rollout

1. Install Agent Gorgon.
2. Run the packaged audit demo if you want a controlled smoke test.
3. Wrap the real workload with `--audit-only`.
4. Review the JSONL evidence.
5. Copy and narrow a starter scope for your environment.
6. Repeat audit-only until expected work is quiet and dangerous cases are visible.
7. Enable `--enforce` only when you are comfortable with the policy and host behavior.

## Documentation

- [Evidence and reproducible receipts](docs/EVIDENCE.md)
- [Harness recipes](docs/HARNESS_RECIPES.md)
- [Audit checklist](docs/AUDIT_CHECKLIST.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Compatibility shim notes](compat/suy-sideguy/README.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Release checklist](PUBLISH_CHECKLIST.md)
- [Contributor agent guide](AGENTS.md)
- [Layered implementation plan](docs/IMPLEMENTATION_PLAN_LAYERED.md)
- [Examples](examples/)

## Project basics

Agent Gorgon is maintained by [Hermes Labs](https://hermes-labs.ai).

Distributed under the Apache-2.0 License. See [LICENSE](LICENSE).

Security issues should be reported according to [SECURITY.md](SECURITY.md).
