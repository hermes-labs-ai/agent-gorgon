# Test Failure Diagnosis — agent-gorgon

## Baseline
- Total: 105 tests
- Passing: 100
- Failing: 5 (all in `TestEndToEnd`, all the same root cause)

---

## Root Cause (shared by all 5)

**`tests/test_user_prompt_submit.py:209`**

```python
class TestEndToEnd:
    HOOK_PATH = HOOK_DIR / "hook.py"
```

`HOOK_DIR` is `Path(__file__).resolve().parent` — i.e., the `tests/` directory. The file `tests/hook.py` does not exist. The actual hook is at `hooks/user_prompt_submit.py`.

`conftest.py` registers `user_prompt_submit` as `sys.modules["hook"]` so the `import hook` at line 22 works fine for unit tests. But `TestEndToEnd._run()` invokes the hook as a **subprocess** (`subprocess.run([sys.executable, str(self.HOOK_PATH)])`), which means it needs the real file path on disk. That path is wrong.

---

## Individual Failures

### 1. `test_e2e_empty_stdin_exits_zero`
- **Test:** `tests/test_user_prompt_submit.py:224`
- **Bug:** `tests/test_user_prompt_submit.py:209` — `HOOK_PATH = HOOK_DIR / "hook.py"` resolves to `tests/hook.py`, which does not exist
- **Root cause:** subprocess invocation of a nonexistent file returns Python exit code 2 ("can't open file"). The test expects exit code 0.
- **Fix:** Change `HOOK_PATH` to point at `hooks/user_prompt_submit.py` (one directory up from tests/).

### 2. `test_e2e_malformed_stdin_exits_zero`
- **Test:** `tests/test_user_prompt_submit.py:231`
- **Bug:** Same as above — `HOOK_PATH` wrong
- **Root cause:** Identical. Subprocess fails before any hook logic runs.
- **Fix:** Same single-line fix.

### 3. `test_e2e_chitchat_no_output`
- **Test:** `tests/test_user_prompt_submit.py:235`
- **Bug:** Same — `HOOK_PATH` wrong
- **Root cause:** Identical.
- **Fix:** Same single-line fix.

### 4. `test_e2e_task_prompt_emits_context`
- **Test:** `tests/test_user_prompt_submit.py:241`
- **Bug:** Same — `HOOK_PATH` wrong
- **Root cause:** Identical. (The `pytest.skip` at line 243 would handle the missing `find_tool.py` case, but we never reach it because the subprocess fails first.)
- **Fix:** Same single-line fix.

### 5. `test_e2e_performance_under_500ms_when_no_subprocess`
- **Test:** `tests/test_user_prompt_submit.py:261`
- **Bug:** Same — `HOOK_PATH` wrong
- **Root cause:** Identical. Performance assertion at line 269 never reached.
- **Fix:** Same single-line fix.

---

## The Fix (one line, five tests fixed)

File: `tests/test_user_prompt_submit.py`

Change line 209:
```python
# before
HOOK_PATH = HOOK_DIR / "hook.py"
# after
HOOK_PATH = HOOK_DIR.parent / "hooks" / "user_prompt_submit.py"
```

`HOOK_DIR` is `tests/`, so `HOOK_DIR.parent / "hooks" / "user_prompt_submit.py"` resolves to `hooks/user_prompt_submit.py` — the actual hook file.

See `_launch/fixes.patch` for the unified diff.
