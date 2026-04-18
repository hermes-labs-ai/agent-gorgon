# Ship Report - agent-gorgon

## What shipped (artifact checklist)

- [x] _launch/test-diagnosis.md - 5 failing tests diagnosed, root cause documented
- [x] _launch/fixes.patch - unified diff, one line, fixes all 5 TestEndToEnd failures
- [x] _launch/proposed-edits.md - P0-P4 issues listed with diffs
- [x] _launch/classification.md - agent-framework
- [x] _launch/claim.md - falsifiable claim + audience
- [x] _launch/hygiene-report.md - all hygiene checks
- [x] _launch/gh-metadata.sh - repo description + topics command (do not run without review)
- [x] _launch/positioning.md - why-now, ICP, competitor delta, adjacent interests
- [x] _launch/images/hero.jpg - 1024x1024, 77KB (Pollinations.ai)
- [x] _launch/images/social-1200x630.jpg - 1200x630, 81KB (Pollinations.ai)
- [x] _launch/images/architecture.mmd - Mermaid source, mmdc not installed so SVG pending
- [x] _launch/images/prompts.md - re-roll prompts documented
- [x] ~/ai-infra/manifests/agent-gorgon.yaml - registered, find_tool.py returns it
- [x] _launch/outreach/hn-show.md - Show HN draft with first-hour plan
- [x] _launch/outreach/blog-post.md - ~1100 words
- [x] _launch/outreach/blog-post.devto.md - DEV.to version with frontmatter
- [x] _launch/outreach/reddit/r-LocalLLaMA.md
- [x] _launch/outreach/reddit/r-MachineLearning.md
- [x] _launch/outreach/linkedin.md
- [x] _launch/outreach/x-thread.md - 6 tweets
- [x] _launch/outreach/email-targets.csv - 10 rows, contacts TBD
- [x] _launch/outreach/README-outreach.md - do-this-then-this index
- [x] _launch/paper/DECISION.md - blog-only, confidence 0.30
- [x] _launch/LAUNCH-PLAN.md - T-3 to T+7 with gates
- [x] _launch/SHIP-REPORT.md - this file

## What needs Roli's review

- `_launch/fixes.patch` - apply with `git apply _launch/fixes.patch` then push
- `_launch/gh-metadata.sh` - run to set GitHub description + topics
- `_launch/outreach/hn-show.md` - edit voice if needed, post manually
- `_launch/outreach/email-targets.csv` - contacts are placeholders ("unknown"), SuperSearch each target before sending
- `_launch/images/hero.jpg` and `social-1200x630.jpg` - open and eyeball before uploading

## What Roli does next (ordered)

1. `git apply _launch/fixes.patch` from repo root. Run `python3 -m pytest tests/ -q`. Verify 105/105 passing.
2. Commit + push the fix. (Ask Claude to do this - git commit required.)
3. **MANUAL:** Upload `_launch/images/social-1200x630.jpg` as GitHub social preview. GitHub Settings > Social Preview. Cannot be scripted.
4. Review + run `bash _launch/gh-metadata.sh` to set repo description + topics.
5. Create `llms.txt` at repo root (content in hygiene-report.md). Commit + push.
6. Pick launch day (Tuesday-Thursday window). Post Show HN from hn-show.md.
7. SuperSearch 10 email targets to get real contact info. Update email-targets.csv.

## Paper decision

**blog-only** - confidence 0.30. No empirical measurement of fabrication reduction rate. Good blog story, not yet a paper. Path to publish-workshop: run controlled eval (hook vs. no-hook, 50+ prompts, 2+ models). See DECISION.md.

## Gates to reconsider

- HN karma check before posting. If account karma <50 on roli-lpci HN account, launch via r/LocalLLaMA first.
- Email contacts are placeholders. Do not run draft_batch.py until real names + emails are in email-targets.csv.
- mmdc not installed. Architecture diagram is .mmd only, no SVG. Install with `npm install -g @mermaid-js/mermaid-cli` if needed for GitHub README embed.
