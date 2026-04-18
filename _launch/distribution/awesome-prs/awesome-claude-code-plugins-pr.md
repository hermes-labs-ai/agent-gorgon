# PR to ccplugins/awesome-claude-code-plugins

**Target list:** https://github.com/ccplugins/awesome-claude-code-plugins (693 stars, pushed 2025-10-14 - **STALE, 6+ months without an update**)

**Staleness flag:** This repo hasn't been updated in over 6 months. A PR here may sit indefinitely. Submit as a secondary target, not primary. Primary goes to hesreallyhim/awesome-claude-code (see that PR draft).

**Why still worth filing:** The repo's niche is *specifically* hooks, slash commands, subagents, MCP servers for Claude Code. If reactivated, agent-gorgon is exactly on-scope.

---

## PR title

`Add agent-gorgon to Hooks`

## PR body

Adds agent-gorgon under Hooks. Three-hook defense (UserPromptSubmit + Stop + PreToolUse/Bash) that stops Claude Code from fabricating tool output when a registered tool matches the task. Discovery engine reads YAML manifests. 105 tests, zero dependencies, MIT.

## Entry to add

Match existing entry format by reading 2-3 adjacent entries in the Hooks section first. Rough template:

```markdown
- **[agent-gorgon](https://github.com/roli-lpci/agent-gorgon)** - Three-hook defense against tool-output fabrication. Ships with a YAML-manifest discovery engine.
```

## Before submitting

- [ ] Check if the repo is still accepting PRs (last merged PR > 90 days ago = likely abandoned - skip)
- [ ] If abandoned, redirect effort to hesreallyhim/awesome-claude-code (the active alternative)
- [ ] Match entry format to adjacent entries (bold name? plain? with or without description?)
