---
name: agent-gorgon
description: Use when an autonomous agent process needs userspace runtime observation before you trust it unattended — agent-gorgon watches the process tree it launches (or an existing PID) plus file and network activity, applies deterministic policy, and can rehearse in audit-only mode before attempting SIGSTOP/SIGKILL on reviewed triggers. No SDK required, no MCP.
license: Apache-2.0
compatibility: Requires Python 3.9+; installs via pip. CI-exercised on Python 3.9-3.12 on Ubuntu; active controls and command reduction are POSIX-oriented, and macOS/Windows/3.13+ production use is unevaluated.
---

# agent-gorgon

Agent Gorgon is a userspace layer that watches an autonomous agent's running
process tree, applies deterministic policy to what it sees, and can pause or
kill a matching process — calibrated first in audit-only mode that changes
nothing. It observes process, file, and network activity visible from user
space; it is not kernel-level enforcement.

## Use it for

- Calibrating a policy against a real agent session in `--audit-only` mode
  before enabling any active control
- Watching a command you are about to launch, so the process tree it creates
  is monitored from the start (`agent-gorgon run`)
- Attaching to an already-running agent process you did not launch, by exact
  PID
- Generating a machine-readable audit demo receipt with no repository
  checkout required (`agent-gorgon-audit-demo`)

## Do not use it for

- A kernel-level sandbox or a substitute for input-side prompt-injection
  defenses — it is one layer in a defense-in-depth setup, not the whole
  strategy
- Pre-execution interposition — it is reactive polling, so an action can
  start or finish before polling observes it
- Enabling active SIGSTOP/SIGKILL controls (`--enforce`, or omitting
  `--audit-only`) without first calibrating the policy against a disposable
  target — there is no interactive confirmation once active controls are on

## Quickstart

```bash
pip install agent-gorgon==0.3.0
agent-gorgon run --audit-only --scope coding-agent -- <your agent command>
```

That launches the command, watches the process tree it creates, and prints
what it *would* have halted — nothing is paused or terminated. Example
summary line:

```text
agent-gorgon run: mode=audit-only exit=0 observed=14 safe=11 flags=3 would-halt=0 would-kill=0 evidence=/home/you/.local/share/agent-gorgon/logs/actions_20260911_101500.jsonl
```

Run the packaged audit demo (three scenarios: SAFE/HALT/KILL) with no
checkout required:

```bash
agent-gorgon-audit-demo --out /tmp/agent-gorgon-audit-demo.json
```

## Output shape

- `agent-gorgon run`: one summary line (`observed`, `safe`, `flags`,
  `would-halt`, `would-kill`) plus a JSONL evidence file per session
- Verdict levels per observed action: `SAFE`, `FLAG`, `HALT` (attempted
  SIGSTOP, reversible), `KILL` (attempted SIGKILL)
- `agent-gorgon-audit-demo`: JSON receipt with each scenario's expected vs.
  observed verdict and honest watcher-overhead measurements; exits nonzero
  on any mismatch

## Common gotchas

- Active controls require an explicit `--enforce` (for `run`) or omitting
  `--audit-only` (PID mode) — nothing is signaled by default.
- The packaged `--scope coding-agent` only knows the launch directory plus
  toolchain caches; add your own project trees before relying on it.
- Short-lived children between polls can be missed — this is not complete
  process or syscall visibility.
- File-visibility and network observations are best-effort and OS-dependent;
  do not treat coverage as complete.

## More

Full docs and CLI reference:
https://github.com/hermes-labs-ai/agent-gorgon
