# Outreach Bundle - agent-gorgon

All drafts. Nothing posted or sent. Roli reviews and pulls the trigger.

## File Index (do this, then this)

1. **Review hn-show.md first.** This is the primary launch vehicle. Edit the body if needed.
   - Post on Tuesday/Wednesday/Thursday 08:00-10:00 PT for best traction.
   - Have the pre-written responses ready (bottom of file) before posting.

2. **Apply fixes.patch before launching.** Run `git apply _launch/fixes.patch` from the repo root. This fixes the 5 failing TestEndToEnd tests. All 105 tests should pass after the patch.

3. **Upload social preview manually.** GitHub web UI: Settings > Social Preview > Upload. File is at `_launch/images/social-1200x630.jpg`. Cannot be automated via gh CLI.

4. **Run gh-metadata.sh after review.** `bash _launch/gh-metadata.sh` sets description + topics. Review the command first.

5. **Post x-thread.md** 1 hour after HN post (6 tweets, each <=280 chars, verified in the draft).

6. **Publish blog-post.md to DEV.to** using blog-post.devto.md (has frontmatter). Set `published: true` when ready. Add canonical_url to the Medium cross-post.

7. **Reddit posts (staggered, one per day max):**
   - `outreach/reddit/r-LocalLLaMA.md` - post day 3 after HN
   - `outreach/reddit/r-MachineLearning.md` - post day 4 after HN

8. **linkedin.md** - post day 1 after HN (professional audience, different network)

9. **email-targets.csv** - 10 targets, contacts TBD (SuperSearch each target's CTO/VP Engineering). Run `python3 ~/ai-infra/pipeline/draft_batch.py --input _launch/outreach/email-targets.csv --output _launch/outreach/drafts/` to generate personalized drafts. Send in waves of 25, T+7 days from launch.

## Files

| File | Platform | Status | Length |
|------|----------|--------|--------|
| hn-show.md | Hacker News | DRAFT | ~200 words |
| blog-post.md | Medium | DRAFT | ~1100 words |
| blog-post.devto.md | DEV.to | DRAFT | ~700 words |
| reddit/r-LocalLLaMA.md | r/LocalLLaMA | DRAFT | ~250 words |
| reddit/r-MachineLearning.md | r/MachineLearning | DRAFT | ~250 words |
| linkedin.md | LinkedIn | DRAFT | ~200 words |
| x-thread.md | X | DRAFT | 6 tweets |
| email-targets.csv | Cold email | DRAFT | 10 rows |
