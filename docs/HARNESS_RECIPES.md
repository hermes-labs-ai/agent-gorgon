# Harness recipes

Concrete, verified invocation patterns for pointing Agent Gorgon at a real agent process. Every
recipe below has been exercised in this repository (`agent_warden.audit_demo`, `tests/`, or the
README demo) against an owned child process; none of it sends a signal to a process this tool
did not intend to target. Recipes for frameworks not present in this repo (LangChain agent
loops, browser-driven agents, remote/containerized runtimes) are intentionally omitted rather
than described speculatively — add one here only after it has actually been run once.

Run the harness itself with `agent-gorgon-audit-demo` (packaged, no checkout required) or
`python3 examples/harness/run_audit_workload.py` (source-checkout wrapper over the same code).

## Recipe 1 — you spawn the agent yourself (subprocess)

The most reliable pattern: your orchestration code starts the agent and already has its PID.

```python
import subprocess

agent = subprocess.Popen(["python3", "my_agent.py"], cwd="/path/to/agent-workspace")

subprocess.Popen([
    "agent-gorgon",
    "--scope", "/path/to/scope.yaml",
    "--agent-pid", str(agent.pid),
    "--audit-only",   # remove only after reviewing the policy against a disposable run
    "--poll", "0.5",
])
```

This is the exact shape `agent_warden.audit_demo::_run_wrapper` uses and that
`agent-gorgon-audit-demo` exercises end to end.

## Recipe 2 — CLI wrapper around a shell-launched agent

If the agent is started from a shell script or Makefile target, capture `$!` (the PID of the
last backgrounded job) and hand it to Agent Gorgon:

```bash
./run_my_agent.sh &
AGENT_PID=$!

agent-gorgon --scope scope.yaml --agent-pid "$AGENT_PID" --audit-only --poll 0.5
```

This is what the README's "See it work safely" demo does, and what
`agent_warden.audit_demo::suspicious_child_name` reproduces for the HALT trigger.

## Recipe 3 — attaching to an already-running agent by exact name

Only when you cannot capture the PID at launch time, and only when you can guarantee a unique
process name:

```bash
agent-gorgon --scope scope.yaml --agent-name my-agent-binary --audit-only --poll 0.5
```

`--agent-name` requires exactly one match (`agent_warden.warden.find_process_by_name` raises on
zero or multiple matches; see `tests/test_scope.py`). Prefer Recipe 1 or 2 whenever you control
the launch — `--agent-name` over-matches in production if two instances of the same binary run
side by side (`AGENTS.md`).

## Building a scope for your workload (do this before any recipe above)

1. Copy the closest example (`examples/scope.generic.yaml`, `examples/scope.openclaw.yaml`, or
   `examples/harness/scope.audit-demo.yaml`) — never hand-write the nested schema from scratch.
2. Set `filesystem.allowed_paths` to the **resolved** path of the agent's workspace, not the
   string you typed. On macOS in particular, `os.path.realpath()` your workspace path before
   writing the scope — see `docs/EVIDENCE.md` §2 for a confirmed false-trigger this step avoids.
3. Run `agent-gorgon-audit-demo`-style fixtures (or your own, following the same "owned child
   process, ground-truth verdict" shape) against a disposable copy of the real workload before
   removing `--audit-only`.
4. Walk `docs/AUDIT_CHECKLIST.md` before enabling active controls or
   `WARDEN_KILL_ON_FLAGS=1`.

## Adding your own fixture

`agent_warden.audit_demo::Scenario` is the contract: a wrapper `Popen` you own plus the verdict
the built-in rules should reach for it. Add a new function there, add it to `ALL_SCENARIOS`,
and run `agent-gorgon-audit-demo` — it will fail (non-zero exit) if the observed verdict does
not match what you declared, which is the point. `examples/harness/workload_fixtures.py` and
`run_audit_workload.py` re-export the same names for source-checkout use and need no changes.
