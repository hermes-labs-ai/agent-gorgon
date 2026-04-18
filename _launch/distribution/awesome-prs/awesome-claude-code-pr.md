# PR to hesreallyhim/awesome-claude-code

**Target list:** https://github.com/hesreallyhim/awesome-claude-code (39.2K stars, pushed today - actively maintained, THE canonical awesome-claude-code list)

**Target section:** `## Hooks 🪝`

**Entry format to match** (copy from the list's existing entries):
`- [name](url) by [author](url) - description.`

---

## PR title

`Add: agent-gorgon - 3-layer hook defense for Claude Code tool-output fabrication`

## PR body

Adds **agent-gorgon** to the Hooks section. It's a set of 3 Claude Code hooks plus a discovery engine that catch a common autonomous-agent failure: the model fabricating tool output (plausible JSON, scores, structured results) when a registered tool for the task exists.

The three hooks:
- `UserPromptSubmit` injects matching tool manifests into model context before generation
- `Stop` scans the final response for structured artifacts that should have been tool outputs and blocks with exit 2 if no tool was called
- `PreToolUse` (Bash matcher) blocks shell commands that reimplement a registered tool and routes to the canonical one

The discovery engine (`find_tool.py`) reads YAML manifests for each registered tool and returns copy-paste-ready entry commands. 105 tests pass. MIT licensed. Zero Python dependencies.

## Entry to add

Under `## Hooks 🪝`:

```markdown
- [agent-gorgon](https://github.com/roli-lpci/agent-gorgon) by [roli-lpci](https://github.com/roli-lpci) - Three-layer hook defense that stops Claude from fabricating tool output when a registered tool exists. Ships with a YAML-manifest discovery engine (find_tool.py), UserPromptSubmit + Stop + PreToolUse/Bash hooks, and an adversarial test suite. Zero dependencies, pytest-covered, MIT.
```

## Before submitting

- [ ] Verify the `## Hooks 🪝` section still exists (lists reorganize)
- [ ] Confirm description stays under the list's line-length norm (check 3 adjacent entries)
- [ ] Run the list's linter if one exists (`npm run lint` or a `scripts/check-format.sh`)
- [ ] PR from a fork, not a branch on the origin
