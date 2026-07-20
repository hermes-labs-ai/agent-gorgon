# agent-warden

agent-warden is a user-space runtime policy guard for autonomous AI agents. It polls a live
process tree, applies deterministic policy to attributed observations, and records control attempts
and forensic evidence.

**Detect high-risk runtime observations and attempt SIGSTOP or SIGKILL controls.** Agent Warden is a
polling monitor, not pre-execution interposition: an action may already have started or completed
before it is observed.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)
[![CI](https://github.com/hermes-labs-ai/agent-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/hermes-labs-ai/agent-warden/actions/workflows/ci.yml)

If 40 files disappear between snapshots, Agent Warden records 40 unattributed delete observations.
It does not suspend the monitored process from those observations alone because a directory diff
cannot establish which process performed the deletion.

## Pain

- Logs alone cannot pause a process after a high-risk observation.
- An inline LLM judge does not provide process-tree, file, or network visibility and is not given
  stop authority here.
- Name-based targeting can select the wrong process; exact PID targeting is the safer boundary.
- A policy file needs an active observer and explicit control outcomes to become operational
  evidence rather than documentation alone.

## Install

Agent Warden 0.1.5 is unreleased. To inspect the candidate from a source checkout:

```bash
pip install -e .
```

After the canonical distribution is published, the install command will be
`pip install agent-warden`.

After both 0.1.5 distributions are published, existing `suy-sideguy` users can upgrade through the
compatibility release:

```bash
pip install --upgrade suy-sideguy
```

The 0.1.5 compatibility release installs the matching `agent-warden` distribution and temporarily forwards the
legacy `suy_sideguy` imports and `suy-*` commands with deprecation warnings.

Python 3.9+.

## Quick start

```bash
agent-warden --scope examples/scope.generic.yaml --agent-pid 12345 --poll 0.5 --no-llm
```

`examples/` is part of the repository, not the installed wheel. From a wheel-only install, copy and
review an example scope from the repository or supply your own scope file before running the command.

Representative local log lines while the agent runs (SAFE lines require `--verbose`):

```text
🛡️  Agent Warden active
⚠️  FLAG [1/12]: process_exec: unknown-command
🟡 HALT: Suspicious process spawned: curl
```

After a run:

```bash
agent-warden-forensic --last-hours 24
```

## When to use it

Use `agent-warden` when you run autonomous or semi-autonomous agents and need best-effort
userspace runtime observation, reactive process controls, and forensic evidence as one layer in a
defense-in-depth setup.

## When not to use it

- Not a kernel-level sandbox. If your threat model requires kernel isolation, use a kernel sandbox.
- Not a substitute for input-side prompt-injection defenses.
- Not proof that any single policy file covers every workload safely. Policies need calibration on each workload.

![agent-warden preview](https://raw.githubusercontent.com/hermes-labs-ai/agent-warden/main/assets/preview.png)

---

## What this tool is (and is not)

### ✅ What it does
- Polls the process, file, and network signals available for an agent process tree
- Applies deterministic policy rules; an optional local Ollama judge can only recommend SAFE/FLAG
- Attempts **HALT** on deterministic, process-attributed triggers (SIGSTOP, a reversible pause,
  plus a local log/report)
- Attempts **KILL** with `SIGKILL` for deterministic severe violations
- Stores evidence and can generate incident-ready forensic reports

### ⚠️ What it does not do
- It is **not kernel-level enforcement** (it runs in userspace)
- It is reactive polling, not syscall interception or a guarantee that a dangerous action is stopped before effect
- File visibility via `psutil.open_files()` is best-effort and OS-dependent
- Short-lived children and actions between polls can be missed; this is not complete process or
  syscall visibility
- Snapshot-diff create/delete observations are unattributed and never suspend or kill the monitored process
- Network observations are remote IP/port pairs; hostname allowlists do not authenticate an observed IP
- Signal attempts can fail or only partially cover a changing process tree; reports record the
  observed outcome and failed HALT/KILL attempts remain retryable

---

## Install

Agent Warden 0.1.5 is not yet published. For candidate development:

```bash
git clone https://github.com/hermes-labs-ai/agent-warden.git
cd agent-warden
pip install -e ".[dev]"
```

After publication:

```bash
pip install agent-warden
```

Requires Python 3.9+.

---

## 5-minute quickstart

### 1) Choose target process
Use one of:
- `--agent-pid` (recommended for production)
- `--agent-name` (convenient, but can match unintended processes)

### 2) Start from the example policy scope
- Open `examples/scope.openclaw.yaml`
- For staged rollout, start with `examples/scope.low-disruption.yaml`
- Narrow allowlists to only what your workload truly needs
- For a generic baseline, start with `examples/scope.generic.yaml`

### 3) Run the warden

```bash
# Safer targeting: PID
agent-warden --scope examples/scope.generic.yaml --agent-pid 12345 --poll 0.5 --no-llm

# Convenience targeting: process name
agent-warden --scope examples/scope.generic.yaml --agent-name my-agent --poll 0.5 --no-llm
```

### 4) Generate report after a run

```bash
agent-warden-forensic --last-hours 24
```

---

## Where logs and evidence go

Default paths:

- `~/.local/share/sysmond/warden.log`
- `~/.local/share/sysmond/logs/actions_*.jsonl`
- `~/.local/share/sysmond/logs/incidents/*.json`

Tip: treat these as security artifacts. Protect access and define retention/rotation.

---

## Privacy and network behavior

- Agent Warden has no telemetry or external reporting client.
- By default it probes `http://localhost:11434` and, when Ollama is available, sends the current
  action, a scope summary, and up to 20 recent actions to that local service for non-enforcing
  advisory analysis. Use `--no-llm` to disable the probe and advisory calls.
- Remote IP policy checks do not perform reverse DNS. Raw IPs must be allowed or forbidden
  explicitly; hostname allowlists apply only when a hostname is supplied by an integration.
- Local JSONL evidence contains full observed paths, commands, and remote IP/port values. Protect
  it as sensitive operational data and configure retention.

## Recommended rollout strategy

Agent Warden 0.1.5 has no audit-only or confirm mode. Deterministic HALT/KILL rules are active when
the warden runs. Start against a disposable process and reviewed low-disruption scope, use
`--no-llm` for a deterministic no-advisory trial, and deploy against important workloads only after
validating hard invariants and OS visibility.

---

## Important safety caveats

- `SIGKILL` is immediate and can interrupt legitimate work if policy is too broad.
- Name matching (`--agent-name`) can over-match; prefer PID targeting in production.
- This project should be one part of a layered defense strategy.

## Verdict levels

| Verdict | Meaning | Response |
|---------|---------|----------|
| `SAFE` | Action is within policy | Continue |
| `FLAG` | Suspicious, below threshold | Log, continue |
| `HALT` | Dangerous pattern detected | Attempt process-tree SIGSTOP (reversible); write local evidence |
| `KILL` | Critical violation | Attempt process-tree SIGKILL; write local evidence |

### HALT triggers (attempt SIGSTOP, a reversible pause; the agent is not intentionally killed)
- **curl or wget child observed** — unexpected outbound-data-transfer process
- **50+ distinct process-attributed network-connection observations in 60 seconds** — bulk egress signal
- **Process-attributed write outside allowed workspace** — unexpected filesystem access, when the OS exposes write mode
- **3+ process-attributed `FILE_DELETE` events in 10 seconds** — available to integrations that can supply attribution; built-in snapshot diffs do not activate this trigger
- **Relative recursive delete with no observed child cwd** — the target cannot be resolved safely,
  so the Warden pauses instead of guessing SAFE or assigning irreversible KILL authority

### KILL triggers (attempt process-tree SIGKILL after observation)
- **Attributed SSH key access** — observed read/write to `~/.ssh/` or `*id_rsa*`, `*id_ed25519*`
- **Attributed config write** — observed write to `~/.openclaw/openclaw.json`
- **Observed child `rm -rf` command targeting a protected root** — filesystem root, home, or a
  configured forbidden root; relative operands are resolved against the observed child cwd
- **Attributed forbidden-path or forbidden-extension access** — paths in `filesystem.forbidden_paths` or extensions in `filesystem.forbidden_extensions`

---

## Expected flag noise (early rollout)

Early flag noise is normal during policy calibration on real workloads.

- Treat early `FLAG` events as calibration data, not immediate defects.
- Flags do not auto-kill by default. `WARDEN_KILL_ON_FLAGS=1` explicitly enables accumulation kills using `flag_threshold` and `flag_window`.
- Keep **hard invariants** (e.g., forbidden secrets paths / destructive commands) as immediate stop decisions.
- There is no audit-only switch in 0.1.5; trial the warden only against a disposable target until its deterministic controls are validated.

---


## Release quality status

_Current status based on repository checks and CI configuration; not a formal security certification._


- ✅ Tests in repo (`pytest`)
- ✅ Package buildable (`python -m build`)
- ✅ CI workflow (`.github/workflows/ci.yml`)
- ✅ Publish workflow (`.github/workflows/publish.yml`)
- ✅ Security disclosure policy (`SECURITY.md`)

If agent-warden saves you time, please [star the repo](https://github.com/hermes-labs-ai/agent-warden) — it helps others find it.

---

## About Hermes Labs

Hermes Labs is an independent AI-reliability lab building open-source tools that catch silent failure modes in production AI. More at [hermes-labs.ai](https://hermes-labs.ai).

---

## Development

```bash
pip install -e .[dev]
pytest
```

Also see:
- `CONTRIBUTING.md`
- `SECURITY.md`
- `PUBLISH_CHECKLIST.md`
- `AGENTS.md`
- `CODE_OF_CONDUCT.md`
- Audit checklist: `docs/AUDIT_CHECKLIST.md`
- Layered plan: `docs/IMPLEMENTATION_PLAN_LAYERED.md`

## Related Hermes Labs tools

- [te-drift-detector](https://github.com/hermes-labs-ai/te-drift-detector) — zero-LLM drift detection for agent sessions (catch it before the warden has to act)
- [hermes-blind](https://github.com/hermes-labs-ai/hermes-blind) — recovery scaffold that bends a drifted session back
- [lintlang](https://github.com/hermes-labs-ai/lintlang) — static linter for agent configs and prompts (catch it before runtime)
