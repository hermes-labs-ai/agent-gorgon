# agent-gorgon

## The problem

An autonomous agent process can spawn a child that reads `~/.ssh/id_rsa`, writes outside its
workspace, or shells out to `curl`/`wget` -- and by default nothing watches for that at runtime
except the agent's own (possibly compromised or simply buggy) judgment. Sandboxes and
input-side filters don't cover this: they run before or around the agent, not against what its
process tree actually does once it starts executing. Agent Gorgon is the userspace layer that
watches the running process tree, applies a deterministic policy to what it sees, and can pause
or kill a matching process -- calibrated first in a mode that changes nothing.

**See what an autonomous agent process does, apply deterministic runtime policy, and keep evidence
of every control decision.** Agent Gorgon observes the process tree plus file and network activity
visible from user space. It can safely rehearse policy in audit-only mode, then attempt SIGSTOP or
SIGKILL for reviewed triggers when active controls are enabled.

> Version 0.1.8 makes `agent_gorgon` the canonical Python import and `agent-gorgon` the primary
> command. The earlier `agent_warden` import and `agent-warden` commands remain available as
> deprecated compatibility aliases for this transition release.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)
[![CI](https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml/badge.svg)](https://github.com/hermes-labs-ai/agent-gorgon/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/agent-gorgon)](https://pypi.org/project/agent-gorgon/)
[![Python versions](https://img.shields.io/pypi/pyversions/agent-gorgon)](https://pypi.org/project/agent-gorgon/)

## Why teams use it

- **Calibrate before signaling.** Audit-only mode shows which actions would HALT or KILL without
  pausing or terminating the target.
- **Keep control deterministic.** The optional local LLM is advisory-only; it cannot authorize a
  HALT or KILL.
- **Preserve an evidence trail.** JSONL actions and incident reports separate the policy verdict,
  signal attempt, and observed process outcome.
- **Add a reactive layer around existing agents.** Agent Gorgon watches a supplied PID; it does not
  require the target application to adopt an SDK.

## Install

The package, Python import, and primary command all use Gorgon names:

```bash
pip install agent-gorgon==0.1.8
agent-gorgon --help
```

For Python integrations, import the canonical namespace:

```python
from agent_gorgon.warden import Scope
```

Existing `agent_warden` imports and `agent-warden` / `agent-warden-forensic` commands continue to
work in 0.1.8 as deprecated compatibility aliases. The legacy commands print a deprecation notice;
update integrations to the Gorgon names when convenient.

The shim's source and its deprecation window live in
[`compat/suy-sideguy/README.md`](compat/suy-sideguy/README.md).

Requires Python 3.9+. Start with `--audit-only`; active controls are enabled only when that flag is
omitted, after you have reviewed the policy against a disposable target.

Support boundary: CI exercises Python 3.9–3.12 on Ubuntu. Production use on macOS, Windows, or
Python 3.13+ is currently `UNEVALUATED`; active controls and command reduction are POSIX-oriented.

## See it work safely

This POSIX demo creates a temporary command named `wget` that only runs `sleep`. Agent Gorgon sees
the suspicious child name and records the HALT it would request, but `--audit-only` sends no signal
and the command performs no network activity:

```bash
DEMO_DIR=$(mktemp -d /tmp/agent-gorgon-demo.XXXXXX)
ln -s "$(command -v sleep)" "$DEMO_DIR/wget"
/bin/sh -c '"$1" 3 & wait' agent-demo "$DEMO_DIR/wget" &
TARGET_PID=$!

agent-gorgon \
  --scope starter \
  --agent-pid "$TARGET_PID" \
  --poll 0.05 \
  --no-llm \
  --audit-only \
  --log-dir "$DEMO_DIR/evidence"
```

The useful result is explicit:

```text
Control: audit-only (SIGSTOP/SIGKILL disabled)
LLM: qwen3:4b disabled (rules only)
🟡 AUDIT ONLY, would HALT: Suspicious process spawned: wget
Observed: 1 | Safe: 0 | Flags: 0 | Halts: 1 | Kills: 0
```

Generate a private JSON summary at an explicit path:

```bash
agent-gorgon-forensic \
  --last-hours 24 \
  --workspace "$DEMO_DIR/workspace" \
  --evidence-dir "$DEMO_DIR/evidence" \
  --out "$DEMO_DIR/report.json"
```

The installed `starter` scope is for audit-only evaluation. For a real workload, copy and narrow a
scope from [examples](examples/), prefer an exact `--agent-pid`, and keep evidence outside the
target's workspace. Remove the temporary demo directory when you no longer need its report.

## When to use it

Use Agent Gorgon when you run autonomous or semi-autonomous agents and need userspace runtime
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
  state and update one episode report without claiming an unobserved outcome

## Where logs and evidence go

Default paths:

- `~/.local/share/agent-gorgon/warden.log`
- `~/.local/share/agent-gorgon/logs/actions_*.jsonl`
- `~/.local/share/agent-gorgon/logs/incidents/*.json`

Agent Gorgon creates these directories for the current user only (`0700`) and evidence files as
private (`0600`). Define retention and rotation appropriate to your environment.

---

## Privacy and network behavior

- Agent Gorgon has no telemetry or external reporting client.
- By default it probes `http://localhost:11434` and, when Ollama is available, sends the current
  action, a scope summary, and up to 20 recent actions to that local service for non-enforcing
  advisory analysis. Use `--no-llm` to disable the probe and advisory calls.
- Remote IP policy checks do not perform reverse DNS. Raw IPs must be allowed or forbidden
  explicitly; hostname allowlists apply only when a hostname is supplied by an integration.
- Local JSONL evidence contains full observed paths, commands, and remote IP/port values. Protect
  it as sensitive operational data and configure retention.

## Recommended rollout strategy

Start with `--audit-only` against a disposable process and a reviewed low-disruption scope. Add
`--no-llm` for a deterministic no-advisory trial. Audit-only records verdicts but sends no SIGSTOP
or SIGKILL. Remove it only after validating the policy and OS visibility for the exact workload;
there is no interactive confirmation mode once active controls are enabled.

---

## Important safety caveats

- `SIGKILL` is immediate and can interrupt legitimate work if policy is too broad.
- Name targeting requires one unique exact process-name match; exact PID targeting remains the
  recommended path.
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
- **Attributed private-key access** — observed read/write to recognized SSH key names such as
  `id_rsa` or `id_ed25519`, plus key extensions such as `*.pem` or `*.key` under `~/.ssh`; broad
  directory rules belong in the operator's scope
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
- Version 0.1.7 includes audit-only calibration; active controls remain explicit through omission
  of `--audit-only`.

---


## Release quality status

_Current status based on repository checks and CI configuration; not a formal security certification._


- ✅ Tests in repo (`pytest`)
- ✅ Package buildable (`python -m build`)
- ✅ CI workflow (`.github/workflows/ci.yml`)
- ✅ Release workflow builds, tests, inspects, and smoke-installs the exact tagged artifact before
  requesting PyPI trusted publication
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
- Concrete harness recipes: `docs/HARNESS_RECIPES.md`
- Owned-process audit fixtures, attribution/false-trigger results, honest overhead measurements:
  `examples/harness/` and `docs/EVIDENCE.md`
- Layered plan: `docs/IMPLEMENTATION_PLAN_LAYERED.md`

## Related Hermes Labs tools

- [te-drift-detector](https://github.com/hermes-labs-ai/te-drift-detector) — experimental lexical feature-delta telemetry for human triage
- [hermes-blind](https://github.com/hermes-labs-ai/hermes-blind) — context-compensation scaffold for evidence-bound LLM evaluation prompts
- [lintlang](https://github.com/hermes-labs-ai/lintlang) — static linter for agent configs and prompts (catch it before runtime)
