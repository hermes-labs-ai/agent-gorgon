# Publish Checklist — agent-gorgon + suy-sideguy compatibility shim

## Pre-release essentials

- [ ] Confirm version in `pyproject.toml` (and tag plan) is correct
- [ ] `python -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -U pip`
- [ ] `pip install -e '.[dev]'`
- [ ] `pytest` passes
- [ ] `python -m agent_warden.warden --help` works
- [ ] `python -m agent_warden.forensic_report --help` works

## Documentation

- [ ] README reflects current CLI and behavior
- [ ] Security caveats are accurate and explicit
- [ ] `CONTRIBUTING.md` present and current
- [ ] `SECURITY.md` present with private reporting guidance
- [ ] LICENSE present and correct

## Packaging sanity

- [ ] `python -m pip install build`
- [ ] `python -m build` succeeds for the repository root
- [ ] `python -m build compat/suy-sideguy` succeeds
- [ ] Verify `agent-gorgon` owns only `agent_warden` and the new entry points
- [ ] Verify `suy-sideguy` owns only `suy_sideguy` and the legacy entry points
- [ ] Verify both wheel/sdist pairs include the Apache-2.0 license
- [ ] Verify the shim pins the exact matching `agent-gorgon` version
- [ ] Validate console entry points:
  - [ ] `agent-warden --help`
  - [ ] `agent-warden-forensic --help`
  - [ ] `suy-warden --help` forwards and warns
  - [ ] `suy-forensic-report --help` forwards and warns
- [ ] In a fresh environment, install `agent-gorgon` from local artifacts and run new imports/CLIs
- [ ] In a second fresh environment, install local `suy-sideguy==0.1.4`, upgrade it to the
      local shim, and run both legacy and canonical imports/CLIs
- [ ] Repeat the upgrade from the currently published predecessor
      (`suy-sideguy==0.1.3` when this RC was prepared)
- [ ] Run the canonical CLI with `--no-llm` and verify no localhost advisory request occurs

## Security/reliability checks

- [ ] Scope example reviewed for least privilege
- [ ] Confirm docs recommend `--agent-pid` for production use
- [ ] Confirm logs path/retention strategy documented for operators
- [ ] Confirm kill semantics (`SIGKILL`) are explicit in docs

## Repo hygiene

- [ ] `.gitignore` excludes virtualenv/build/log artifacts
- [ ] No secrets or private logs in git history/staging
- [ ] `git status` clean except intentional release changes

## Release step

- [ ] Publish the canonical `agent-gorgon` artifact before the dependent shim artifact
- [ ] Keep the compatibility window through Agent Warden 0.3.x and no earlier than
      2026-10-10 unless the owner records a different window
- [ ] Commit with release-prep message
- [ ] Replace the changelog's `Unreleased` marker with the actual release date
- [ ] Tag release `v<version>`
- [ ] Publish release notes with known limitations
