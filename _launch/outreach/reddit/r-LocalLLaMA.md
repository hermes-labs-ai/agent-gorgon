# r/LocalLLaMA Draft

**Subreddit:** r/LocalLLaMA
**Flair:** Discussion / Tool

---

**Title:** Built a 3-layer Claude Code hook system after Claude fabricated a compliance score instead of calling the tool that generates real ones

---

**Body:**

The failure mode: Claude Code session, task is "Score Stripe on EU AI Act compliance. Output JSON." There is a real scoring tool registered in the manifest. The agent produces 50 lines of structured JSON - article-by-article scores, an overall score of 62, a grade of "C+" - without calling anything. When asked why, it says "I had the rules but didn't act on them."

This is not hallucination in the traditional sense. The output is structurally correct and plausible. The failure is the agent choosing to fabricate rather than delegate to the tool that exists for this task.

I built agent-gorgon to intercept this at three points:

1. **UserPromptSubmit hook** - fires before the model generates. Searches the YAML manifest registry for matching tools, injects entry commands directly into model context as a hard instruction. "You MUST invoke one of these or explain why before generating structured output."

2. **PreToolUse/Bash hook** - catches Bash commands that reimplement registered tools inline (hardcoded scores, ad-hoc scoring functions, fabricated JSON in echo statements). Blocks with exit 2, routes to real tool.

3. **Stop hook** - scans the final response for compound fabrication signals (compliance keyword + numeric score fields in JSON). If detected with no tool call in the transcript, blocks the stop and forces a retry.

The key insight was why each earlier approach failed: PreToolUse never fires if the model didn't make a tool call to intercept. Stop fires after fabrication is complete. UserPromptSubmit alone wasn't enough (the agent acknowledges the injected context and ignores it). You need all three layers.

105 tests, MIT license: https://github.com/roli-lpci/agent-gorgon

The YAML manifest format (`manifests/_template.yaml`) works with any tool that has a deterministic CLI entry point. You describe input format, output format, tags, and entry command - find_tool.py handles keyword + semantic matching.

Anyone else dealing with this? Curious what patterns people are seeing in their own Claude Code deployments.
