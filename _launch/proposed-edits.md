# Proposed Edits — agent-gorgon (audit mode)

All proposed changes are diffs only. Apply with:
  git apply _launch/fixes.patch

---

## P0 (breaks tests) — 5 tests failing

### tests/test_user_prompt_submit.py:209

**Problem:** `HOOK_PATH = HOOK_DIR / "hook.py"` — `tests/hook.py` does not exist. The real hook is `hooks/user_prompt_submit.py`. Conftest aliases it for unit-test imports, but subprocess invocation needs the real disk path.

**Fix (in fixes.patch):**
```diff
-    HOOK_PATH = HOOK_DIR / "hook.py"
+    HOOK_PATH = HOOK_DIR.parent / "hooks" / "user_prompt_submit.py"
```

**Impact:** Fixes all 5 TestEndToEnd failures: test_e2e_empty_stdin_exits_zero, test_e2e_malformed_stdin_exits_zero, test_e2e_chitchat_no_output, test_e2e_task_prompt_emits_context, test_e2e_performance_under_500ms_when_no_subprocess.

---

## P1 (dead imports — no behavior change, reduces linter noise)

### hooks/user_prompt_submit.py:40
```diff
-import os
```
`os` is never referenced in this file. `Path.home()` handles home-dir logic. Remove.

### hooks/pre_tool_use_bash.py:29
```diff
-import os
```
`os` is never referenced outside of `os.environ.copy()` — wait, actually not present here either. Remove.

### hooks/stop.py
```diff
-from typing import Any
```
`Any` appears in a type annotation in the file at line 109 (`payload: dict`) — actually `Any` is NOT used in stop.py. Remove.

---

## P2 (missing docstrings on public functions)

Functions missing docstrings (all in find_tool.py and hook mains):

- `find_tool.py:96` — `filter_tools()`: add one-liner "Filter tools list by category, tag, format, and interactive flag."
- `find_tool.py:124` — `summarize()`: add "Convert a tool dict to the output-safe summary format with relevance score."
- `find_tool.py:149` — `cmd_search()`: add "Execute keyword/tag search and return result dict."
- `find_tool.py:237` — `cmd_list()`: add "Return all tools (filtered) as a list result."
- `find_tool.py:248` — `build_parser()`: add "Build and return the argparse ArgumentParser."
- `find_tool.py:274` — `main()`: add "Entry point: parse args, load manifests, dispatch command."
- `hooks/user_prompt_submit.py:337` — `main()`: add "Hook entry point: read stdin, run pipeline, emit JSON to stdout."
- `hooks/pre_tool_use_bash.py:269` — `main()`: add "Hook entry point: detect Bash shadow signals, block if tool exists."
- `hooks/stop.py:227` — `main()`: add "Hook entry point: scan transcript for fabricated output, block if detected."

---

## P3 (hardcoded path in pre_tool_use_bash.py)

### hooks/pre_tool_use_bash.py:41
```python
LOG_FILE = Path.home() / "ai-infra" / "hackathon" / "agent-5-contrarian" / "shadow.log"
```
This path is a leftover from the hackathon origin. On a fresh install, `~/ai-infra/hackathon/agent-5-contrarian/` likely does not exist. The log function creates parent dirs, so it won't crash — but it will write logs in an unexpected location for new users.

**Proposed fix:**
```diff
-LOG_FILE = Path.home() / "ai-infra" / "hackathon" / "agent-5-contrarian" / "shadow.log"
+LOG_FILE = Path.home() / ".claude" / "hooks" / "logs" / "tool-shadow.jsonl"
```
Aligns with user_prompt_submit.py's log location convention.

---

## P4 (README — counts mismatch)

README line 55: "Each hook ships with its own test suite (36 + 45 + 24 cases respectively)."

Actual counts from pytest:
- test_pre_tool_use_bash.py: 45 tests
- test_stop.py: 24 tests
- test_user_prompt_submit.py: 36 tests (31 unit + 5 e2e)

Total = 105. README says 36+45+24=105. Order in README is UserPromptSubmit / Stop / PreToolUse but the numbers (36, 45, 24) may not match that order. After fix: 105/105 passing. Verify counts match before merging.

---

## Summary

| Priority | File | Issue | Behavior impact |
|----------|------|-------|-----------------|
| P0 | tests/test_user_prompt_submit.py:209 | Wrong HOOK_PATH for subprocess | 5 tests fail |
| P1 | hooks/user_prompt_submit.py:40 | Dead `import os` | None — linter noise |
| P1 | hooks/pre_tool_use_bash.py:29 | Dead `import os` | None — linter noise |
| P1 | hooks/stop.py | Dead `from typing import Any` | None — linter noise |
| P2 | find_tool.py, hooks/*.py | Missing docstrings on `main()` and helpers | None — discoverability |
| P3 | hooks/pre_tool_use_bash.py:41 | Hackathon-origin log path | Logs go to unexpected dir on fresh install |
| P4 | README.md:55 | Test count description may mismatch order | None — cosmetic |

Total diff size: approximately 25 lines changed.
