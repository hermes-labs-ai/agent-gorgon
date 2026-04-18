# Contributing

## Setup

```bash
git clone https://github.com/roli-lpci/agent-gorgon
cd agent-gorgon
pip install -e .[dev]
```

No external dependencies. If `[dev]` extras are not yet defined in `pyproject.toml`,
just install pytest directly: `pip install pytest`.

## Run tests

```bash
pytest tests/ -q
```

All 100 tests must pass before submitting a PR.

## Format and lint

```bash
ruff format .
ruff check .
```

## Submitting a PR

1. Fork the repo and create a branch: `git checkout -b your-feature`
2. Make your changes.
3. Add or update tests to cover the change.
4. Run `pytest tests/ -q` and `ruff check .` locally. Fix any failures.
5. Open a PR with:
   - A one-line title describing what changed.
   - A brief description of why (link an issue if one exists).

## Manifest contributions

To add a new tool manifest, copy `manifests/_template.yaml`, fill all REQUIRED fields,
and set `tested: true`. See `AGENTS.md` for the full 5-step flow.

## Questions

Open an issue or email rbosch@lpci.ai.
