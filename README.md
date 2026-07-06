# agent-warden

agent-warden is a runtime policy guard for autonomous AI agents that enforces kill/flag policy on a live agent process and emits a forensic report of what it actually did.

**Watch an agent process and SIGKILL it on policy violation.** Userspace warden that scores file, network, and subprocess behavior against a YAML policy and stops the agent at the action that's about to break things — not the postmortem an hour later.

[![PyPI](https://img.shields.io/pypi/v/suy-sideguy)](https://pypi.org/project/suy-sideguy/)
[![Python](https://img.shields.io/pypi/pyversions/suy-sideguy)](https://pypi.org/project/suy-sideguy/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)
[![CI](https://github.com/hermes-labs-ai/agent-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/hermes-labs-ai/agent-warden/actions/workflows/ci.yml)

If your agent passed every static check and then deleted 40 files in 8 seconds, this is the watcher that would have stopped it at file 4. The static gate was never going to catch a runtime decision.

## Pain

- Your agent ran `rm -rf` outside `/tmp` at 2am and you found out from the morning standup. The audit log was perfect; it just wasn't going to wake anyone up.
- You added an LLM judge in front of every shell call. It's 800ms per action, doubles your cost, and still missed the 200ms read of `~/.ssh/id_rsa` because the judge isn't on the file-system event path.
- You tried `--agent-name my-agent` once. It matched three unrelated processes including your editor. PID-target your enforcement or don't bother.
- Your "policy YAML" is an aspirational doc, not something a process is enforcing. A policy without an enforcer is a memo.
- You're treating runtime safety as a layer you'll add "after MVP." MVP shipped; the agent has shell access; the layer didn't.

## Install

```bash
pip install suy-sideguy
```

(package still publishes as suy-sideguy; renaming to agent-warden next release)

Python 3.9+.

## Quick start

```bash
suy-warden --scope examples/scope.generic.yaml --agent-pid 12345 --poll 0.5
```

Live output while the agent runs:

```text
target=12345 verdict=SAFE action=continue
target=12345 verdict=FLAG action=log_continue  reason=high_fd_count
target=12345 verdict=HALT action=suspend       reason=mass_deletion_3_in_10s
```

After a run:

```bash
suy-forensic-report --last-hours 24
```

## When to use it

Use `agent-warden` when you run autonomous or semi-autonomous agents and need *userspace* runtime containment, policy enforcement, and forensic evidence — as one layer in a defense-in-depth setup.

## When not to use it

- Not a kernel-level sandbox. If your threat model requires kernel isolation, use a kernel sandbox.
- Not a substitute for input-side prompt-injection defenses.
- Not proof that any single policy file covers every workload safely. Policies need calibration on each workload.

![agent-warden preview](assets/preview.png)

---

## What this tool is (and is not)

### ✅ What it does
- Watches process, file, and network behavior for an agent process
- Applies policy rules (optionally with a local LLM judge via Ollama)
- **HALT** suspicious actions (SIGSTOP the agent, a reversible pause, plus alert) before they escalate
- **KILL** severe violations with `SIGKILL` when policy requires it
- Stores evidence and can generate incident-ready forensic reports

### ⚠️ What it does not do
- It is **not kernel-level enforcement** (it runs in userspace)
- File visibility via `psutil.open_files()` is best-effort and OS-dependent
- Network checks are based on observed remote IP/port; domain matching can be lossy after DNS

---

## Install

```bash
pip install suy-sideguy
```

Requires Python 3.9+.

For development:

```bash
git clone https://github.com/hermes-labs-ai/agent-warden.git
cd agent-warden
pip install -e ".[dev]"
```

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
suy-warden --scope examples/scope.generic.yaml --agent-pid 12345 --poll 0.5

# Convenience targeting: process name
suy-warden --scope examples/scope.generic.yaml --agent-name my-agent --poll 0.5
```

### 4) Generate report after a run

```bash
suy-forensic-report --last-hours 24
```

---

## Where logs and evidence go

Default paths:

- `~/.local/share/sysmond/warden.log`
- `~/.local/share/sysmond/logs/actions_*.jsonl`
- `~/.local/share/sysmond/logs/incidents/*.json`

Tip: treat these as security artifacts. Protect access and define retention/rotation.

---

## Recommended rollout strategy

1. **Audit-first**: observe and tune policy without auto-kill pressure.
2. **Confirm mode** for ambiguous events.
3. **Enforce mode** only after your hard invariants are validated.

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
| `HALT` | Dangerous pattern detected | Suspend agent (SIGSTOP, reversible), alert operator |
| `KILL` | Critical violation | `SIGKILL` immediately |

### HALT triggers (SIGSTOP the agent, a reversible pause, plus alert; agent is not killed)
- **3+ file deletions in 10 seconds** — mass deletion pattern
- **curl or wget spawned** — unexpected outbound data transfer
- **50+ network calls in 60 seconds** — bulk messaging / API spam
- **Write outside allowed workspace** — unexpected filesystem access

### KILL triggers (immediate, no recovery)
- **SSH key access** — any read/write to `~/.ssh/` or `*id_rsa*`, `*id_ed25519*`
- **Config tampering** — writing to `~/.openclaw/openclaw.json`
- **rm -rf on non-tmp paths** — destructive sweep outside `/tmp`
- **Forbidden paths** — any path in your scope's `deny_write` list

---

## Expected flag noise (early rollout)

Early flag noise is normal during policy calibration on real workloads.

- Treat early `FLAG` events as calibration data, not immediate defects.
- Use policy thresholds (`flag_threshold`, `flag_window`) to control when accumulated risk escalates to kill.
- Keep **hard invariants** (e.g., forbidden secrets paths / destructive commands) as immediate stop conditions.
- Start in audit-first mode, then tighten only after reviewing forensic logs.

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
