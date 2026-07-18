# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-07-06

### Changed
- **Agent Warden is the canonical identity** — the primary distribution is `agent-warden`,
  imports use `agent_warden`, and the CLIs are `agent-warden` and `agent-warden-forensic`.
- **Suy Sideguy is a time-bounded compatibility shim** — `suy-sideguy==0.1.5` depends on
  exactly `agent-warden==0.1.5`, forwards historical imports and commands, and emits
  deprecation diagnostics. The proposed default removal is Agent Warden 0.4.0, no earlier
  than 2026-10-10 and only after the owner records the release flip.

### Fixed
- **HALT now enforces** — a HALT verdict SIGSTOPs the agent process tree (reversible pause, signalled once, forensic halt report written). Previously HALT only logged and the agent kept running, contradicting the documented "freeze + alert" behavior.
- **LLM judge is advisory-only** — the Ollama judge can no longer emit KILL/HALT (schema is SAFE/FLAG; anything else is coerced to FLAG) and runs off the enforcement hot path, closing the blind-window DoS on the monitor. KILL and SIGSTOP remain the deterministic rule engine's exclusive authority.
- **Credential-read then network-out exfil pattern KILLs deterministically**; a bare network-out without a preceding credential read stays HALT/FLAG.
- **In-process deletes are now observed** — poll-time filesystem diff of scope roots emits synthetic FILE_DELETE/FILE_WRITE actions (`os.remove` opens no fd, so `psutil.open_files()` alone was blind to them).
- **No more SIGKILL on benign dev work** — rate-limit breaches and project-dir recursive deletes downgrade to FLAG; `rm -rf` on protected roots (`~/.ssh`, `~/.aws`, `~/.gnupg`) still KILLs, including the bare directory (contents-glob regression closed).
- **Shipped generic scope enforced nothing** — `examples/scope.generic.yaml` used a flat schema the parser silently read as empty allowlists; rewritten nested, and `Scope` now fails loud on legacy flat-schema keys.

### Added
- 49 regression tests covering the above (test suite: 41 to 90).

## [0.1.4] - 2026-05-30

### Added
- DOI-readiness metadata (CITATION.cff, .zenodo.json). Tagged `v0.1.4` on GitHub; not published to PyPI.

## [0.1.3] - 2026-03-08

### Added
- **HALT verdict** — new escalation level between FLAG and KILL. Dangerous patterns freeze the agent and alert the operator without killing the process.
- **HALT triggers**: 3+ file deletions in 10 seconds; curl/wget process spawned; 50+ network calls in 60 seconds (bulk messaging pattern); writes outside allowed workspace.
- **Hardcoded KILL triggers**: SSH key file access (`~/.ssh/`, `*id_rsa*`, `*id_ed25519*`); modification of `~/.openclaw/openclaw.json`; `rm -rf` on non-tmp paths.
- `intent_match.py` — standalone module for classifying instruction intent (READ/WRITE/DELETE/NETWORK/SPAWN) and detecting intent-action mismatches.

## [0.1.2] - 2026-03-02

### Fixed
- Standardized package metadata (author: Hermes Labs, email: lpcisystems@gmail.com)
- Removed leaked personal paths from repository
- Removed internal review documents
- Removed legacy product references and standardized naming
- Added contact email to SECURITY.md
- Added dependabot configuration

## [0.1.1] - 2026-03-02

### Fixed
- Resolved mypy type annotation errors across the codebase
- Fixed ruff f-string formatting warnings
- Added `from __future__ import annotations` for forward-compatible type hints

### Changed
- CI workflow now passes all lint and type checks cleanly
- Published to PyPI as `suy-sideguy`

## [0.1.0] - 2026-03-02

### Added
- Initial release of Suy Sideguy
- Runtime process, file, and network monitoring via `psutil`
- YAML-based policy engine with SAFE / FLAGGED / KILLED verdicts
- `suy-warden` CLI entrypoint for live agent monitoring
- `suy-forensic-report` CLI for post-incident forensic reports
- PID and process-name targeting modes
- Evidence logging (JSONL actions log + JSON incident files)
- Example scope policies (`scope.openclaw.yaml`, `scope.low-disruption.yaml`)
- Audit checklist and layered implementation plan
- Test suite with pytest
- CI and publish GitHub Actions workflows
- Security disclosure policy (`SECURITY.md`)
- Contributing guide and Code of Conduct

[0.1.2]: https://github.com/hermes-labs-ai/suy-sideguy/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/hermes-labs-ai/suy-sideguy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hermes-labs-ai/suy-sideguy/releases/tag/v0.1.0
