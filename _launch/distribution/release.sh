#!/usr/bin/env bash
# release.sh - agent-gorgon publish workflow (proposed - not yet applied)
#
# Prerequisites (one-time):
#   1. pyproject.toml is in place at repo root (apply pyproject.toml.proposed first)
#   2. .github/workflows/release.yml is in place (apply release.yml.proposed first)
#   3. PyPI Trusted Publishing configured at:
#        https://pypi.org/manage/account/publishing/
#      Add: project=agent-gorgon, owner=roli-lpci, repo=agent-gorgon,
#           workflow=release.yml, environment=release (optional)
#      This must be done BEFORE the first publish.
#
# Per-release steps:
#   1. Bump version in pyproject.toml (e.g. 0.1.0 → 0.1.1)
#   2. Update CHANGELOG.md - move [Unreleased] items into a new [X.Y.Z] - YYYY-MM-DD section
#   3. Commit the bump:
#        git add pyproject.toml CHANGELOG.md
#        git commit -m "release: vX.Y.Z"
#   4. Tag and push:
#        git tag vX.Y.Z
#        git push && git push --tags
#   5. GitHub Actions release.yml fires automatically on the tag push:
#        - builds sdist + wheel via `python -m build`
#        - publishes to PyPI via OIDC (no API token needed)
#   6. Verify the release:
#        pip install --upgrade agent-gorgon
#        agent-gorgon --version      # or: python -c "import agent_gorgon; print(agent_gorgon.__version__)"
#
# Fallback (manual publish if Trusted Publishing not configured yet):
#   python -m pip install --upgrade build twine
#   rm -rf dist/
#   python -m build
#   python -m twine check dist/*
#   python -m twine upload dist/*     # will prompt for __token__ + PyPI API token
#
# Rollback:
#   PyPI does not allow re-uploading the same version. To fix a bad release:
#     1. Yank it at https://pypi.org/project/agent-gorgon/#history
#     2. Bump version, cut a new release
#
# This script is documentation, not an executable. Copy blocks you want to run.

set -euo pipefail

echo "This is the release runbook, not an executable. Open it in an editor." >&2
exit 64
