# SHIP-REPORT Addendum - Distribution infrastructure follow-up

Completes the 8 gaps flagged in the post-run audit (packaging, AGENTS.md, CI, demo plan, awesome-* PRs).

## What landed

| # | File | Status |
|---|------|--------|
| 1 | `pyproject.toml.proposed` | ✅ hatchling build, zero external deps, entry points + project URLs |
| 2 | `AGENTS.md.proposed` | ✅ agentic AEO, repo-root target |
| 3 | `.github/workflows/test.yml.proposed` | ✅ matrix over Python 3.10/3.11/3.12 |
| 4 | `.github/workflows/release.yml.proposed` | ✅ PyPI Trusted Publishing via OIDC (no secrets) |
| 5 | `CHANGELOG.md.proposed` | ✅ Keep-a-Changelog 1.1.0 format |
| 6 | `CONTRIBUTING.md.proposed` | ✅ tailored to actual dev flow |
| 7 | `CODE_OF_CONDUCT.md.proposed` | ✅ references Contributor Covenant 2.1 via URL (not inlined) |
| 8 | `README-badges-and-hero.diff` | ✅ unified diff, hero + 6 badges |
| 9 | `release.sh` | ✅ runbook (not auto-executed), includes Trusted Publishing setup + manual fallback |
| 10 | `demo-plan.md` | ✅ 3-scene shot list + asciinema+agg recording recipe |
| 11 | `awesome-prs/` | ✅ 3 PR drafts: awesome-claude-code (primary, 39K stars active), awesome-agents (secondary), awesome-claude-code-plugins (tertiary, stale-flag raised) |

## Known stops / filter events

The agent that started this task hit an API content-filtering block after writing items 1-6, most likely on the verbatim Contributor Covenant 2.1 text (harassment-category language is a known false-positive trigger). Items 7-11 were written directly by the main session without the verbatim covenant - the `.proposed` COC file now references the covenant by URL instead of inlining it.

## Apply order (Roli's checklist)

From the repo root (`~/Documents/projects/agent-gorgon`):

```bash
# 1. Packaging + agent docs
cp _launch/distribution/pyproject.toml.proposed pyproject.toml
cp _launch/distribution/AGENTS.md.proposed AGENTS.md
cp _launch/distribution/CHANGELOG.md.proposed CHANGELOG.md
cp _launch/distribution/CONTRIBUTING.md.proposed CONTRIBUTING.md
cp _launch/distribution/CODE_OF_CONDUCT.md.proposed CODE_OF_CONDUCT.md

# 2. CI + release workflows
mkdir -p .github/workflows
cp _launch/distribution/.github/workflows/test.yml.proposed .github/workflows/test.yml
cp _launch/distribution/.github/workflows/release.yml.proposed .github/workflows/release.yml

# 3. Hero image + badges (hero must be copied before patch applies cleanly)
mkdir -p docs
cp _launch/images/hero.jpg docs/hero.jpg
git apply _launch/distribution/README-badges-and-hero.diff

# 4. Test locally
pip install -e .
pytest -q   # expect 100/105 until you apply _launch/fixes.patch first; then 105/105

# 5. Apply the earlier test-fix patch (from the original launch-repo run)
git apply _launch/fixes.patch
pytest -q   # expect 105/105

# 6. Stage + commit (review first!)
git add pyproject.toml AGENTS.md CHANGELOG.md CONTRIBUTING.md CODE_OF_CONDUCT.md
git add .github/workflows/ docs/hero.jpg README.md tests/test_user_prompt_submit.py
git commit -m "release prep: v0.1.0 distribution infra, CI, docs, badges"
git push
```

## Manual web steps (cannot be scripted)

1. **PyPI Trusted Publishing:** https://pypi.org/manage/account/publishing/ - add project=agent-gorgon, owner=roli-lpci, repo=agent-gorgon, workflow=release.yml. Required BEFORE first release.
2. **GitHub social preview:** repo Settings → General → Social preview → upload `_launch/images/social-1200x630.jpg`.
3. **GitHub repo description + topics:** run `bash _launch/gh-metadata.sh` (from the original run).
4. **Record demo GIF:** follow `_launch/distribution/demo-plan.md`, then update README's `<img src>` from `docs/hero.jpg` to `docs/demo.gif`.

## Then release

```bash
bash _launch/distribution/release.sh   # actually just prints the runbook; copy blocks you want
# after bumping version + updating CHANGELOG:
git tag v0.1.0 && git push --tags      # CI auto-publishes to PyPI
```

## Then outreach

```bash
# Submit 3 awesome-* PRs (manually, from forks - not automated)
cat _launch/distribution/awesome-prs/awesome-claude-code-pr.md  # primary target

# Use existing Show HN draft
cat _launch/outreach/hn-show.md

# Blog distribution via Delta's publishers (dry-run first)
cd ~/ai-infra/publishers && python3 publish_all.py --post silent-data-loss --platforms devto,medium --dry-run
```

## Research gaps

- `awesome-mcp-servers` not targeted: agent-gorgon is not an MCP server. If you build an MCP wrapper later, that list becomes relevant (84K+ stars, very active).
- `awesome-ai-safety` lists are numerous and lower-quality; evaluate before submitting.
- Did not verify each awesome-* list's exact CONTRIBUTING.md requirements - each PR draft has a "before submitting" checklist prompting that check.

## Voice lint

Ran on all files in `_launch/distribution/`: zero em-dashes, zero banned phrases. Clean.
