# Contributing

Thanks for helping improve Agent Gorgon.

## Quick setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
```

## Before you open a PR

Run these checks locally:

```bash
pytest -q
ruff check .
mypy agent_gorgon agent_warden
python -m agent_gorgon.warden --help
python -m agent_gorgon.forensic_report --help
python -m build && python -m build compat/suy-sideguy
```

The test, lint, type-check and build commands are the ones `.github/workflows/ci.yml` runs
(`pip install build` first); the `--help` smoke checks are extra.

## Pull request expectations

Please keep PRs:
- **Focused** (small, clear scope)
- **Tested** (add/update tests when behavior changes)
- **Documented** (update README/docs for user-visible changes)
- **Security-aware** (call out any security-impacting changes explicitly)

## Bug reports (what to include)

To help us reproduce quickly, include:
- OS + Python version
- Exact command used
- Relevant scope file excerpt
- Sanitized logs/error output

If the issue might be security-sensitive, follow `SECURITY.md` instead of posting publicly.
