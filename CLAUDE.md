# agent-gorgon

User-space runtime policy guard for autonomous AI agent processes. Polls the process tree plus
file and network activity via psutil, applies a deterministic YAML scope, can SIGSTOP (HALT) or
SIGKILL (KILL) the target tree, and keeps private forensic evidence. Distribution `agent-gorgon`,
canonical import `agent_gorgon`, version 0.3.0. `agent_warden` / `agent-warden*` are deprecated
compatibility aliases (formerly Agent Warden).

## Commands

Local checks match `.github/workflows/ci.yml` exactly (Python 3.9-3.12 on Ubuntu):

- `pip install -e ".[dev]"` -- Install with dev deps (use a fresh venv; needs `PyYAML>=6.0.3`)
- `pytest -q` -- Full offline suite (no Ollama, no network)
- `pytest tests/test_scope.py -v` -- Single test module
- `ruff check .` -- Lint (whole repo, including tests, examples and the compat shim)
- `mypy agent_gorgon agent_warden` -- Type check (the compat shim is not type-checked)
- `python -m build && python -m build compat/suy-sideguy` -- Build both distributions
- `agent-gorgon run --audit-only --scope coding-agent -- python3 my_agent.py` -- Launch and watch
  a command (audit-only default; `--enforce` for active controls). Options end at `--`.
- `agent-gorgon --scope starter --agent-pid 12345 --poll 0.5 --no-llm --audit-only` -- Safe
  calibration run against an already-running process (`starter` = packaged low-disruption scope)
- `agent-gorgon --scope examples/scope.openclaw.yaml --agent-pid 12345 --poll 0.5` -- Active
  controls (only after reviewing the scope against a disposable target)
- `agent-gorgon-forensic --last-hours 24 [--evidence-dir DIR --workspace DIR --out FILE]`
- `agent-gorgon-audit-demo --out /tmp/agent-gorgon-audit-demo.json` -- Packaged 3-scenario
  audit-only demo against child processes it spawns and owns (SAFE / HALT / KILL ground truth)
- `python -m agent_gorgon.warden --help` / `python -m agent_gorgon.forensic_report --help`

`agent-warden` and `agent-warden-forensic` still work but print a deprecation notice to stderr.

## Architecture

The implementation lives in `agent_warden/`; `agent_gorgon/` is the canonical public namespace
that re-exports it. Do not duplicate logic between the two.

```text
agent_warden/
  warden.py            # The whole runtime: Scope (YAML parse + validation), LLMJudge,
                       #   IncidentLogger, Killswitch, ProcessObserver, Warden loop,
                       #   find_process_by_name, resolve_scope_path, argparse main/entrypoint
  forensic_report.py   # Evidence aggregation -> private JSON incident summary (own CLI)
  intent_match.py      # Instruction/intent classification helpers
  audit_demo.py        # Owned-child-process audit demo scenarios + harness (own CLI)
  run_command.py       # `agent-gorgon run`: spawn a command, watch its tree, relay signals,
                       #   forward its exit status (dispatched from warden.entrypoint)
  audit_demo_scope.yaml# Scope template for the audit demo (WORKSPACE_GLOB is realpath'd in)
  scopes/low-disruption.yaml  # The packaged `--scope starter`
  scopes/coding-agent.yaml    # The packaged `--scope coding-agent` (mirrored in examples/;
                       #   tests/test_coding_agent_scope.py asserts the two stay identical)
  cli.py scope.py enforcement.py observer.py policy.py models.py
                       # Thin re-export facades over warden.py, kept for import stability
  _version.py          # Single source of __version__

agent_gorgon/          # Star re-exports of every agent_warden module + legacy.py (deprecated
                       #   agent-warden console aliases). Console scripts in pyproject.toml
                       #   point here.
compat/suy-sideguy/    # Separate, unpublished PyPI shim distribution forwarding the historical
                       #   suy_sideguy imports and suy-* commands; version-pinned to agent-gorgon
examples/              # Scope files (nested schema) + harness/ wrappers over audit_demo
tests/                 # pytest; several tests are contract/regression guards (see below)
```

Enforcement pipeline: ProcessObserver -> deterministic Scope rules (the SOLE authority for HALT
and KILL) -> Killswitch (SIGSTOP = reversible HALT, SIGKILL = KILL) -> IncidentLogger /
forensic report. `--audit-only` records the verdict and sends no signal. The LLMJudge (Ollama)
is an advisory-only sidecar off the enforcement hot path: its output is capped to SAFE/FLAG and
coerced if the model says anything else; it can never kill or suspend.

## Key Constraints

- Python 3.9+ (`from __future__ import annotations` in every module); CI matrix 3.9-3.12.
- Three runtime deps only: `psutil`, `PyYAML`, `httpx`.
- `SIGKILL` is irreversible -- kill-path changes need tests plus forensic validation; do not
  change kill/halt semantics without a test in `tests/`.
- Fail-open on observer errors (log and continue; never take down the warden). Snapshot-diff
  create/delete observations are unattributed and never HALT/KILL on their own.
- LLM judge: `LLMJudge.OLLAMA_URL = http://localhost:11434/api/chat`, availability probed via
  `/api/tags`, default model `qwen3:4b` (`--model`), disabled with `--no-llm`. No abstraction
  layer. Tests must not require Ollama.
- Scope YAML is the NESTED schema (`agent`, `filesystem`, `network`, `process`, `behavior`).
  Unknown sections/keys and the legacy flat `allow_*/deny_*` schema are rejected at load.
  `filesystem.workspace_paths` is optional and names the trees walked for the create/delete
  snapshot diff; without it the snapshot falls back to `allowed_paths`. Packaged scope names
  resolve through `PACKAGED_SCOPES` in `warden.py`; add a name there and ship the YAML in
  `agent_warden/scopes/`. Relative path patterns resolve against the process's cwd.
- Version is pinned in four places that must agree: `pyproject.toml`, `agent_warden/_version.py`,
  the literal in `tests/test_gorgon_namespace.py`, and the README install line. Releases are the
  owner's call; `publish.yml` refuses a tag whose CHANGELOG entry still says `Unreleased`.
- The compat shim (`compat/suy-sideguy/pyproject.toml`) pins an exact `agent-gorgon==X` and
  `publish-compat.yml` asserts shim version == canonical version. It is slated for removal in
  0.4.0, not before 2026-10-10, and only after the owner records the flip (see CHANGELOG 0.1.5).

## Code Style

- `from __future__ import annotations` in every module
- Dataclasses + Enum for structured data; `logging.getLogger(__name__)` per module
- Type hints on all public functions
- Ruff: line length 100, target py39, rules pinned to `E4,E7,E9,F,I,UP,B` in pyproject (do not
  rely on ruff's default rule set; it changes between releases)
- mypy runs with `follow_imports = "skip"` -- project code is checked, dependency bodies are not
  (`tests/test_mypy_ci_contract.py` guards this)

## Gotchas

- `psutil.open_files()` visibility is OS-dependent and best-effort; it reports resolved paths
  (macOS `/private/var/...`), so `allowed_paths` globs must be realpath'd.
- Network checks match remote IP/port, not domain -- no reverse DNS.
- `--agent-name` must resolve to exactly one process or it is rejected; prefer `--agent-pid`.
- Evidence defaults to `~/.local/share/agent-gorgon/` (`warden.log`, `logs/actions_*.jsonl`,
  `logs/incidents/*.json`), created 0700 with 0600 files; `--log-dir` overrides.
  `agent-gorgon-forensic` reads it via `--evidence-dir` (alias `--sysmond-logs`, legacy name).
- Flags do not auto-kill unless `WARDEN_KILL_ON_FLAGS=1`; then `behavior.flag_threshold` and
  `behavior.flag_window` control accumulation.
- `.pre-commit-config.yaml` pins an older ruff and a `ruff-format` hook that CI does not run;
  CI's gate is `ruff check .` at the pyproject-pinned ruff version.
