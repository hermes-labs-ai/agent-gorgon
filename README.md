# agent-gorgon

**A runtime policy guard for autonomous AI agents.** agent-gorgon watches the process tree, file
activity, and network connections visible from user space; applies deterministic policy; attempts
SIGSTOP or SIGKILL for configured triggers; and preserves forensic evidence of what it observed
and attempted.

> Public release: `agent-gorgon==0.1.6` on PyPI. The package installs the established
> `agent-warden` and `agent-warden-forensic` commands. Current `main` also contains an unreleased
> `--audit-only` mode for non-signaling calibration.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)
[![CI](https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml/badge.svg)](https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/agent-gorgon)](https://pypi.org/project/agent-gorgon/)
[![Python versions](https://img.shields.io/pypi/pyversions/agent-gorgon)](https://pypi.org/project/agent-gorgon/)

## Why use it

- Logs alone cannot pause a process after a high-risk observation.
- A policy file by itself does not observe a live process or record whether a control attempt worked.
- An inline LLM judge does not provide process-tree, file, or network visibility. Here, the optional
  local judge is advisory-only; deterministic rules retain exclusive HALT/KILL authority.
- A runtime incident needs evidence that separates a verdict from the attempted and observed
  control outcome.

## Install

The canonical distribution is `agent-gorgon`; the command remains `agent-warden`:

```bash
pip install agent-gorgon==0.1.6
agent-warden --help
```

Requires Python 3.9+. PyPI 0.1.6 has active controls and does not include `--audit-only`; review a
scope against a disposable target before using that release.

Support boundary: CI exercises Python 3.9–3.12 on Ubuntu. Production use on macOS, Windows, or
Python 3.13+ is currently `UNEVALUATED`; active controls and command reduction are POSIX-oriented.

## Safe first run from current source

Current `main` includes the unreleased, non-signaling `--audit-only` candidate. This POSIX example
monitors a disposable three-second process, disables the optional localhost Ollama advisory, and
exits when the target exits:

```bash
git clone https://github.com/hermes-labs-ai/agent-gorgon.git
cd agent-gorgon
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
sleep 3 & TARGET_PID=$!
agent-warden \
  --scope examples/scope.low-disruption.yaml \
  --agent-pid "$TARGET_PID" \
  --poll 0.2 \
  --no-llm \
  --audit-only
```

The startup output should identify the exact PID and make both boundaries explicit:

```text
Control: audit-only (SIGSTOP/SIGKILL disabled)
LLM: qwen3:4b disabled (rules only)
Agent ended. Warden shutting down.
```

For an actual workload, copy and narrow one of the [example scopes](examples/), prefer an exact
`--agent-pid`, and inspect the evidence after the target exits:

```bash
agent-warden-forensic --last-hours 24
```

## When to use it

Use `agent-warden` when you run autonomous or semi-autonomous agents and need userspace runtime
observation, reactive process controls, and forensic evidence as one layer in a defense-in-depth
setup.

## When not to use it

- Not a kernel-level sandbox. If your threat model requires kernel isolation, use a kernel sandbox.
- Not a substitute for input-side prompt-injection defenses.
- Not proof that any single policy file covers every workload safely. Policies need calibration on each workload.
- Not pre-execution interposition. An action may start or finish before polling observes it.

If 40 files disappear between snapshots, agent-gorgon records 40 unattributed delete observations.
It does not suspend the monitored process from those observations alone because a directory diff
cannot establish which process performed the deletion.

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
  observed outcome. Failed HALT/KILL attempts remain retryable; retries reconcile actual process
  state and update one episode report without repeating rollback side effects

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

From an editable source install, start with `--audit-only` against a disposable process and a
reviewed low-disruption scope. Add
`--no-llm` for a deterministic no-advisory trial. Audit-only mode records verdicts but does not send
SIGSTOP or SIGKILL. Remove `--audit-only` only after validating hard invariants and OS visibility;
there is still no interactive confirmation mode once active controls are enabled.

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
- **Recursive delete outside allowed filesystem scope** — arbitrary literal targets do not become
  SAFE merely because their `sh`/`bash` wrapper is allowed; conventional relative project cleanup
  remains low-noise when its observed cwd resolves inside `filesystem.allowed_paths`
- **Recursive delete with unresolved wrapper, command, option, or target semantics** — the Warden
  pauses when exact reduction is not possible instead of guessing SAFE or assigning KILL authority
- **Recursive delete inside executable shell command substitution** — unquoted/double-quoted
  `` `...` `` and `$(...)` forms pause reversibly; single-quoted substitution text remains data

### KILL triggers (attempt process-tree SIGKILL after observation)
- **Attributed SSH key access** — observed read/write to `~/.ssh/` or `*id_rsa*`, `*id_ed25519*`
- **Attributed config write** — observed write to `~/.openclaw/openclaw.json`
- **Observed child `rm -rf` command targeting a protected root** — filesystem root, home, or a
  configured forbidden root; relative operands are resolved against the observed child cwd, and
  supported `env` wrappers plus root/home glob and ancestor forms are reduced before classification;
  direct child argv is preserved so literal `~`, `$HOME`, and wildcard bytes are not re-expanded
- **Attributed credential read with active or newly observed non-local network egress** — an
  established external socket at read time, or a new external connection inside the configured
  short window, activates the correlation; IP loopback IPC is exempt and does not disarm it
- **Attributed forbidden-path or forbidden-extension access** — paths in `filesystem.forbidden_paths` or extensions in `filesystem.forbidden_extensions`

---

## Expected flag noise (early rollout)

Early flag noise is normal during policy calibration on real workloads.

- Treat early `FLAG` events as calibration data, not immediate defects.
- Flags do not auto-kill by default. `WARDEN_KILL_ON_FLAGS=1` explicitly enables accumulation kills using `flag_threshold` and `flag_window`.
- Keep **hard invariants** (e.g., forbidden secrets paths / destructive commands) as immediate stop decisions.
- PyPI 0.1.6 has no audit-only switch. The unreleased source candidate adds it for disposable-target calibration; active controls remain the 0.1.6 behavior.

---


## Release quality status

_Current status based on repository checks and CI configuration; not a formal security certification._


- ✅ Tests in repo (`pytest`)
- ✅ Package buildable (`python -m build`)
- ✅ CI workflow (`.github/workflows/ci.yml`)
- ✅ Publish workflow and PyPI Trusted Publisher are configured; end-to-end publication
  awaits the next separately approved release.
- ✅ Security disclosure policy (`SECURITY.md`)

If agent-gorgon saves you time, please [star the repo](https://github.com/hermes-labs-ai/agent-gorgon) — it helps others find it.

---

## About Hermes Labs

Hermes Labs is an AI reliability engineering studio for production agents and LLM
applications. agent-gorgon is the runtime-observation and control layer in its open-source
toolkit. More at [hermes-labs.ai](https://hermes-labs.ai).

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

- [te-drift-detector](https://github.com/hermes-labs-ai/te-drift-detector) — experimental lexical feature-delta telemetry for human triage
- [hermes-blind](https://github.com/hermes-labs-ai/hermes-blind) — context-compensation scaffold for evidence-bound LLM evaluation prompts
- [lintlang](https://github.com/hermes-labs-ai/lintlang) — static linter for agent configs and prompts (catch it before runtime)
