# AGENTS.md

`agent-warden` is a best-effort user-space polling guard for agent processes.

## Use it for

- watching process, file, and network behavior after the agent starts running
- applying policy verdicts and attempting SIGSTOP/SIGKILL controls for HALT/KILL
- generating forensic evidence after suspicious or blocked activity

## Do not use it for

- kernel-level sandboxing
- prompt injection detection on inbound input
- assuming name-based process matching is safe enough for production targeting

## Minimal commands

```bash
pip install -e ".[dev]"
agent-warden --scope examples/scope.low-disruption.yaml --agent-pid 12345 --poll 0.5
agent-warden --scope examples/scope.low-disruption.yaml --agent-pid 12345 --poll 0.5 --audit-only
agent-warden-forensic --last-hours 24
pytest -q
```

## Output shape

- the warden emits runtime verdicts and records attempted control outcomes
- forensic reporting reads stored incident artifacts and produces an incident-ready summary

## Success means

- the policy scope loads cleanly
- the target process is identified correctly
- runtime events are classified consistently and evidence is preserved

## Common failure cases

- using `--agent-name` when multiple matching processes exist
- overly broad policies that create noisy early flags
- expecting full OS visibility from `psutil.open_files()` on every platform
- assuming activity shorter than the poll interval will always be observed
