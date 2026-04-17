"""Conftest: alias renamed hook modules so existing test imports keep working."""
import sys
from pathlib import Path

HOOKS_DIR = Path(__file__).parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

import user_prompt_submit  # noqa: E402
import pre_tool_use_bash  # noqa: E402
import stop  # noqa: E402

sys.modules.setdefault("hook", user_prompt_submit)
sys.modules.setdefault("tool_shadow", pre_tool_use_bash)
sys.modules.setdefault("stop_hook", stop)
