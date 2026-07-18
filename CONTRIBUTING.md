# Contributing

Thanks for helping improve Suy Sideguy.

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
pytest
python -m agent_warden.warden --help
python -m agent_warden.forensic_report --help
```

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
