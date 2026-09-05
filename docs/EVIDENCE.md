# Audit-only workload evidence

Measured 2026-09-05 against this branch, macOS ARM, Python 3.14, using only child processes
spawned by the harness. No signal was sent to any unrelated process; every run used
`--audit-only --no-llm`. Reproduce with the packaged command (installable via
`pip install agent-gorgon`, no repository checkout required):

```bash
agent-gorgon-audit-demo --out /tmp/gorgon_evidence.json
```

or, from a source checkout, the equivalent thin wrapper:

```bash
python3 examples/harness/run_audit_workload.py --out /tmp/gorgon_evidence.json
```

Both invoke the same harness -- the scenarios, runner, and scope template live in
`agent_warden.audit_demo` (re-exported as `agent_gorgon.audit_demo`); `examples/harness/` is a
compatibility wrapper over it, not a separate implementation.

## 1) Attribution / false-trigger result (current run)

| Scenario                    | Expected | Observed | Attribution     | Match |
|------------------------------|----------|----------|------------------|-------|
| `safe_workspace_write`       | SAFE     | SAFE     | attributed (1/1) | yes   |
| `suspicious_child_name`      | HALT     | HALT     | attributed (1/1) | yes   |
| `forbidden_extension_write`  | KILL     | KILL     | attributed (1/1) | yes   |

`false_trigger_or_miss_count: 0` on this run, with the scope's `allowed_paths` rendered against
`os.path.realpath(workspace)` (see finding below for why that step is required).

This is a 3-scenario smoke check, not a statistical false-positive rate. It demonstrates the
harness catches a real mismatch when one exists (see below) and confirms the three built-in
rules it exercises hold on this platform.

## 2) Confirmed false-trigger: unresolved `/tmp` paths on macOS

Before rendering `allowed_paths` against the *resolved* workspace path, the identical workload
produced a false FLAG:

```json
{
  "verdict": "FLAG",
  "reason": "Path outside allowed scope: /private/var/folders/.../T/agent-gorgon-workload.XXXX/safe_output.txt (LLM disabled)"
}
```

Root cause: `psutil.open_files()` returns the OS-resolved path. On macOS, `/tmp` is a symlink to
`/private/tmp`, and `$TMPDIR` (what `tempfile.mkdtemp()` uses) resolves under
`/private/var/folders/...`. A scope written with a literal `/tmp/...` glob in `allowed_paths`
never matches those resolved observations, so a write entirely inside the intended workspace is
flagged as out-of-scope. `agent_warden/warden.py`'s filesystem check (`fnmatch` against the raw
pattern, no `realpath()`) does not compensate for this.

Mitigation used here and recommended for any macOS scope: build `allowed_paths` from
`os.path.realpath(path)`, not the path string you started with. `agent_warden.audit_demo::_render_scope` does this; `agent_warden/audit_demo_scope.yaml` documents it
inline. This is a scope-authoring gotcha, not a fix to `agent_warden` itself.

## 3) Honest overhead evidence

Agent Gorgon polls the target from a **separate process**; it does not instrument or wrap the
target's own execution, so there is no meaningful "percent slower" number for the target itself.
The only real cost is the watcher process's own CPU time, which scales directly with
`--poll`:

| `--poll` | Watcher CPU (avg of per-100ms samples) | Notes |
|----------|------------------------------------------|-------|
| `0.05s`  | ~43% of one core                          | Matches the aggressive interval used in the README demo and this harness's default scenarios |
| `0.5s`   | ~10% of one core                          | The CLI default |

Both measured over a 2-3s single-process, single-child workload; `cpu_percent()` samples are
noisy at this scale (a single sample after process start reads ~99% from Python interpreter
startup, then settles). Treat these as order-of-magnitude, not a certified benchmark — run
`agent-gorgon-audit-demo` on your own target shape and poll interval before trusting a CPU
budget for it.

Target-side wall clock in this harness (`target_baseline_seconds` vs
`target_watched_wallclock_seconds`) differed by roughly the watcher's own process startup/shutdown
time (~0.05-0.15s in this environment), not by anything charged to the target's execution.

## 4) What this evidence does not cover

- No FLAG-accumulation, network, or unattributed-delete scenarios are included yet; those need a
  real network egress path or a directory-diff fixture, both of which need more care to keep
  "owned processes only" (see `agent_warden/warden.py` for the unattributed snapshot-diff
  behavior, already covered by `tests/test_fs_diff_observer.py`).
- Three scenarios is not a statistically meaningful false-positive rate against a real agent
  workload. It is a repeatable regression harness for the rules it exercises, run on demand
  before trusting a new scope against a real target (`docs/AUDIT_CHECKLIST.md`).
