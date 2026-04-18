# Launch Plan — agent-gorgon

## T-3 Days (prep)

**Gate: hygiene complete, images ready, gh-metadata applied.**

- [ ] Apply `_launch/fixes.patch` via `git apply _launch/fixes.patch` from repo root
- [ ] Run `python3 -m pytest tests/ -q` - confirm 105/105 passing
- [ ] Run `bash _launch/gh-metadata.sh` to set GitHub description + topics
- [ ] **MANUAL:** Upload social preview via GitHub web UI (Settings > Social Preview). File: `_launch/images/social-1200x630.jpg`. This cannot be automated.
- [ ] Create `llms.txt` at repo root (content in `_launch/hygiene-report.md`)
- [ ] Review and merge `_launch/proposed-edits.md` items P1-P4

**Fallback if gate fails:** Do not proceed to launch day. Repo with failing tests reflects poorly.

---

## T-2 Days (content review)

**Gate: blog post reviewed by Roli, HN account karma >=50 on roli-lpci.**

- [ ] Read blog-post.md end to end. Adjust tone if needed.
- [ ] Check HN karma on your account. If <50, the post will be flagged immediately.
- [ ] Verify architecture.mmd renders correctly (install mmdc via `npm install -g @mermaid-js/mermaid-cli` if needed for local preview)
- [ ] Pre-write 3 HN responses from `hn-show.md` in a local doc for fast copy-paste

**Fallback:** If HN karma <50, launch on r/LocalLLaMA first to build initial signal, then HN 3 days later.

---

## T-1 Day (cold email prep)

**Gate: email targets have real contact names + emails.**

- [ ] SuperSearch each target in email-targets.csv to find CTO/VP Engineering contact
- [ ] Update email-targets.csv with real names and emails
- [ ] Dry run: `python3 ~/ai-infra/pipeline/draft_batch.py --input _launch/outreach/email-targets.csv --output _launch/outreach/drafts/ --dry-run`
- [ ] Review generated drafts. Do not send yet.

**Fallback:** If draft_batch.py is not available, write manual emails using the blog-post.md framing. The Stripe incident story is the opening.

---

## T+0 Launch Day

**Post window: 08:00-10:00 PT, Tuesday/Wednesday/Thursday only.**

- [ ] Post Show HN using hn-show.md body verbatim (edit title if it feels off)
- [ ] Monitor first 30 minutes for comments
- [ ] Reply to first commenter within 10 minutes
- [ ] Post linkedin.md

**Go/no-go gate:** If the repo has failing tests at launch time, abort and fix first. Nothing else matters.

---

## T+1 Hour

- [ ] Post x-thread.md (6 tweets, pre-scheduled or manual)

---

## T+1 Day

- [ ] Publish blog-post.devto.md to DEV.to (change `published: false` to `published: true`)
- [ ] Cross-post to Medium (use blog-post.md, add canonical URL pointing to DEV.to)

---

## T+3 Days

- [ ] Post r-LocalLLaMA.md to r/LocalLLaMA
- [ ] Check HN thread for late comments, reply if warranted

---

## T+4 Days

- [ ] Post r-MachineLearning.md to r/MachineLearning

---

## T+7 Days

- [ ] Send cold email batch wave 1 (first 5 targets) via draft_batch.py
- [ ] Review gaps.jsonl to see which prompts triggered no-match - this is your next manifest to write

---

## Key Manual Steps (always flagged)

1. **Social preview upload** - GitHub web UI only, cannot be scripted
2. **HN posting** - manual, must be 08:00-10:00 PT window
3. **Email sending** - manual review required, draft_batch.py generates but does not send
4. **Reddit posting** - one per day max, stagger to avoid karma hits
