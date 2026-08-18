# agent-warden

Runtime safety guard for autonomous AI agents. Monitors process/file/network behavior, applies policy rules, terminates violations.

## Commands

- `pip install -e ".[dev]"` -- Install with dev deps
- `pytest` -- Run the full test suite
- `pytest tests/test_scope.py -v` -- Single test module
- `ruff check agent_warden/` -- Lint
- `mypy agent_warden/` -- Type check
- `python -m build` -- Build wheel + sdist
- `agent-warden --scope examples/scope.openclaw.yaml --agent-pid 12345 --poll 0.5` -- Run warden
- `agent-warden-forensic --last-hours 24` -- Generate incident report

## Architecture

```
agent_warden/
  warden.py          # Main loop: observe → evaluate → enforce (entry point)
  observer.py        # Process/file/network monitoring via psutil
  policy.py          # Rule evaluation engine
  scope.py           # YAML scope parser (allowlists, blocklists, thresholds)
  enforcement.py     # SIGKILL dispatch
  forensic_report.py # Evidence aggregation, incident report export
  models.py          # Shared dataclasses (Action, Observation, Verdict)
  cli.py             # Argument parsing
```

Enforcement pipeline: Observer → Rule Engine (deterministic scope checks — the SOLE authority for KILL and HALT) → Killswitch (SIGKILL / reversible SIGSTOP) → Responder (forensic report). The LLM Judge (Ollama) is an advisory-only sidecar off the enforcement hot path: its verdicts are capped to SAFE/FLAG and it can never kill or suspend.

## Key Constraints

- Python 3.9+ required (`from __future__ import annotations` in all modules)
- Three runtime deps only: `psutil`, `PyYAML`, `httpx`
- `SIGKILL` is irreversible — kill-path changes need tests + forensic validation
- Fail-open on observer errors (log and continue, don't crash the warden)
- LLM judge calls Ollama `/api/chat` — no abstraction layer yet
- Scope files are YAML with OS-specific path comments

## Code Style

- `from __future__ import annotations` in every module
- Dataclasses + Enum for structured data
- `logging.getLogger(__name__)` per module
- Type hints on all public functions
- Ruff line length: 100, target Python 3.9

## Gotchas

- `psutil.open_files()` visibility is OS-dependent and best-effort
- Network checks match IP/port, not domain — DNS resolution is lossy
- `--agent-name` can over-match processes; prefer `--agent-pid` in production
- Log/evidence paths default to `~/.local/share/sysmond/` (legacy naming)
- Flags do not auto-kill unless `WARDEN_KILL_ON_FLAGS=1`; then `flag_threshold` and
  `flag_window` control accumulation
