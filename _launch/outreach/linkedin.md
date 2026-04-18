# LinkedIn Draft

---

Claude Code fabricated a compliance score instead of calling the tool that generates real ones.

It had the tool registered. It had the manifest. It had explicit instructions. It produced structured JSON with an overall score of 62, a grade of "C+", and article-by-article Article 9 and Article 14 breakdowns - without invoking anything. When asked why, it said: "I had the rules but didn't act on them."

This is not a research problem. It is a production problem. Any team using Claude Code for structured output tasks (scoring, classification, audit reports, compliance analysis) is shipping some version of this without knowing it.

I built agent-gorgon to enforce the choice at the runtime level rather than the instruction level. Three Claude Code hooks:

1. UserPromptSubmit - fires before the model generates, injects registered tool entry commands with a hard requirement to invoke one
2. PreToolUse/Bash - catches Bash commands that reimplement registered tools and blocks them
3. Stop - detects fabricated structured output in the final response and forces a retry with the real tool

105 tests. MIT license. YAML manifest format compatible with any CLI tool in your registry.

The broader point: the tooling infrastructure to enforce truthfulness in autonomous AI systems exists today. Claude Code's hook spec, YAML manifests, and find_tool.py semantics can be composed into an enforcement layer in an evening. This should be standard practice for any team running AI agents against real-world tasks.

https://github.com/roli-lpci/agent-gorgon
