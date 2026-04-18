# The Claim

Three Claude Code hooks — UserPromptSubmit, Stop, and PreToolUse — interdict the tool-fabrication failure mode at every decision point: before the model generates, during Bash execution, and after the final response, ensuring agents invoke registered tools rather than confabulate structured output.

**Audience:** Claude Code power users who maintain a local tool registry (YAML manifests) and have observed their agent generating plausible-looking JSON, scores, or compliance reports from training priors instead of invoking the actual tool.

**Why-now:** The MCP/Skills/Commands ecosystem is producing an explosion of registered tools that agents systematically ignore. The fabrication failure mode is not theoretical — it happened during the build of this repo. The hook spec needed to catch it only became stable in Claude Code in early 2026.
