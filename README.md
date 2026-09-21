<div align="center">

<h1>Agent Gorgon</h1>

<img src="assets/agent-gorgon-artwork.jpg" width="500" alt="Agent Gorgon artwork: a watchful eye encircled by two coral serpents" />

<p><strong>Audit coding agents at runtime. Enforce deterministic policy when you are ready.</strong></p>

<p>Watch process, file, and network activity visible from user space, rehearse policy without sending signals, and keep a local evidence trail.</p>

<p>Agent Gorgon is developed by <a href="https://hermes-labs.ai">Hermes Labs</a>.</p>

<p>Hermes Labs studies failure modes in agent and LLM systems, develops open-source tools that treat language as part of the runtime, and works with teams to remediate reliability failures in production.</p>

<p>
<a href="#quickstart">Quickstart</a> ·
<a href="docs/EVIDENCE.md">Evidence</a> ·
<a href="docs/HARNESS_RECIPES.md">Recipes</a> ·
<a href="SECURITY.md">Security</a>
</p>

<a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache--2.0-green.svg"></a>
<a href="https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://pypi.org/project/agent-gorgon/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/agent-gorgon"></a>
<a href="https://pypi.org/project/agent-gorgon/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/agent-gorgon"></a>

</div>

## Why Agent Gorgon

Autonomous agents need shell access to be useful. Agent Gorgon adds a reactive user-space policy layer around the process that gets that access—without requiring the agent or its tools to adopt an SDK.

- **Observe the process tree.** Wrap a command you launch or attach to an exact PID and inspect the process, file, and network activity visible from user space.
- **Audit before enforcing.** Exercise the same deterministic policy path without sending `SIGSTOP` or `SIGKILL`, then enable controls only after the scope is calibrated.
- **Keep the evidence.** Local JSONL actions and incident reports separate the policy verdict, the signal attempt, and the observed process state.

```text
agent command or PID
        ↓
user-space observation
(process · files · network)
        ↓
deterministic policy
SAFE · FLAG · HALT · KILL
        ↓
audit-only: record      enforce: attempt signal
        ↓
local actions + incident evidence
```

## Quickstart

Agent Gorgon requires Python 3.9+.

```bash
python -m pip install agent-gorgon
agent-gorgon --version
```

Start with the packaged audit demo. It launches controlled fixtures that it owns—no real agent, network access, or credentials—and writes a machine-readable receipt:

```bash
agent-gorgon-audit-demo --out /tmp/agent-gorgon-audit-demo.json
```

The demo evaluates declared SAFE, HALT, and KILL expectations in audit-only mode. It exits nonzero if an observed verdict does not match the declared ground truth; read the receipt before treating the run as a passing calibration.

See [Evidence and reproducible receipts](docs/EVIDENCE.md) for captured results, overhead measurements, and their limitations.

## Wrap a real agent

Run your normal command behind Agent Gorgon. `agent-gorgon run` is audit-only unless you explicitly pass `--enforce`:

```bash
agent-gorgon run --audit-only --scope coding-agent -- claude
# or:
agent-gorgon run --audit-only --scope coding-agent -- <your agent command>
```

When the command exits, Agent Gorgon returns its exit status, prints a compact summary, and leaves the action evidence on disk:

```text
agent-gorgon run: mode=audit-only exit=0 observed=14 safe=11 flags=3 would-halt=0 would-kill=0 evidence=/home/you/.local/share/agent-gorgon/logs/actions_20260911_101500.jsonl
```

After you have reviewed the evidence and narrowed the scope for the exact workload and host, active signaling is explicit:

```bash
agent-gorgon run --enforce --scope coding-agent -- <your agent command>
```

The shipped `coding-agent` scope is a starter policy, not universal or production-calibrated coverage.

## How it works

Agent Gorgon polls operating-system telemetry available to the monitored process tree through `psutil` and evaluates each observation against the active scope. The normal CLI poll interval is 0.5 seconds; shorter intervals increase watcher overhead.

| Verdict | Meaning | Response |
|---|---|---|
| `SAFE` | Observation is within active policy | Continue |
| `FLAG` | Suspicious or outside expected scope, below intervention threshold | Log and continue |
| `HALT` | Deterministic dangerous pattern matched | Attempt process-tree `SIGSTOP` and record evidence |
| `KILL` | Deterministic severe violation matched | Attempt process-tree `SIGKILL` and record evidence |

Optional local Ollama analysis is advisory-only. It cannot authorize HALT or KILL decisions; deterministic policy owns active control.

## Scopes and policy

`coding-agent` is designed to make common development activity usable while surfacing:

- reads of SSH, AWS, GPG, gcloud, GitHub, netrc, credential, and key material;
- outbound transfer utilities such as `curl`, `wget`, and `nc`;
- writes outside the expected workspace;
- network activity outside configured policy;
- destructive recursive deletion patterns.

The scope cannot know your repository layout, caches, credentials policy, network requirements, or threat model. Calibrate it in audit-only mode and adapt it to the workload. See [Harness recipes](docs/HARNESS_RECIPES.md) for scenario and scope guidance.

To monitor a process that is already running, prefer an exact PID:

```bash
agent-gorgon \
  --scope starter \
  --agent-pid <PID> \
  --no-llm \
  --audit-only
```

Unlike `agent-gorgon run`, the direct PID command does not default to audit-only. Keep `--audit-only` until you intentionally want active controls.

## Evidence and operational boundaries

Default evidence locations include:

- `~/.local/share/agent-gorgon/warden.log`
- `~/.local/share/agent-gorgon/logs/actions_*.jsonl`
- `~/.local/share/agent-gorgon/logs/incidents/*.json`

Generate a structured incident report from recent evidence:

```bash
agent-gorgon-forensic \
  --last-hours 24 \
  --workspace /path/to/workspace \
  --evidence-dir ~/.local/share/agent-gorgon/logs \
  --out report.json
```

These are structured local receipts, not cryptographically immutable records.

Important boundaries:

- **Not a kernel sandbox.** Agent Gorgon does not replace namespaces, seccomp, virtualization, or other kernel/VM isolation.
- **Reactive, not pre-execution interposition.** An action can begin or finish between polling observations.
- **User-space visibility is incomplete.** Short-lived children, file handles, or other activity can be missed.
- **Signal attempts are attempts.** The process tree can change while a signal is being applied.
- **A scope is not proof of coverage.** Validate each policy against its workload and environment.

CI exercises Python 3.9–3.12 on Ubuntu. Active controls are POSIX-oriented. Treat other operating systems, Python versions, and production environments as unevaluated until they have been validated directly.

## Privacy and network behavior

Agent Gorgon includes no Hermes Labs telemetry or remote reporting client.

Unless `--no-llm` is used, Agent Gorgon probes the local Ollama service at `http://localhost:11434` and may send local action context to it for advisory analysis. `--no-llm` disables that path.

Local evidence can contain sensitive paths, commands, and remote IP/port observations. Protect it as operationally sensitive data.

## Documentation

- [Evidence and reproducible receipts](docs/EVIDENCE.md)
- [Harness recipes](docs/HARNESS_RECIPES.md)
- [Audit checklist](docs/AUDIT_CHECKLIST.md)
- [Examples](examples/)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)
- [Release checklist](PUBLISH_CHECKLIST.md)
- [Compatibility shim notes](compat/suy-sideguy/README.md)
- [Layered implementation plan](docs/IMPLEMENTATION_PLAN_LAYERED.md)
- [Contributor agent guide](AGENTS.md)

## License and security

Distributed under the Apache-2.0 License. See [LICENSE](LICENSE). Report security issues according to [SECURITY.md](SECURITY.md).
