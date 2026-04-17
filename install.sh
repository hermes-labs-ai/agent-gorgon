#!/usr/bin/env bash
# install.sh — Agent Gorgon: 3-layer fabrication defense for Claude Code
#
# Installs a discovery engine + 3 hooks that prevent your AI agent from
# fabricating tool output when a registered tool exists for the task.
#
# Idempotent. Safe to run multiple times.

set -euo pipefail

GORGON_HOME="${GORGON_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SETTINGS="$HOME/.claude/settings.json"
LOG_DIR="$HOME/.claude/hooks/logs"

HOOK_UPS="$GORGON_HOME/hooks/user_prompt_submit.py"
HOOK_PTU="$GORGON_HOME/hooks/pre_tool_use_bash.py"
HOOK_STOP="$GORGON_HOME/hooks/stop.py"

echo "=== Agent Gorgon Install ==="
echo "GORGON_HOME: $GORGON_HOME"
echo ""

# Preflight
for f in "$HOOK_UPS" "$HOOK_PTU" "$HOOK_STOP"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: hook missing at $f"
    exit 1
  fi
done

if [ ! -f "$SETTINGS" ]; then
  echo "Creating minimal settings.json..."
  mkdir -p "$(dirname "$SETTINGS")"
  echo '{}' > "$SETTINGS"
fi

python3 -c "import json,pathlib; json.loads(pathlib.Path('$SETTINGS').read_text()); print('settings.json: valid JSON')"

mkdir -p "$LOG_DIR"

# Install via Python (idempotent)
GORGON_HOME="$GORGON_HOME" SETTINGS="$SETTINGS" python3 - <<'PY'
import json, os, pathlib

settings_path = pathlib.Path(os.environ["SETTINGS"])
gorgon_home = os.environ["GORGON_HOME"]

data = json.loads(settings_path.read_text())
hooks = data.setdefault("hooks", {})

UPS  = f"python3 {gorgon_home}/hooks/user_prompt_submit.py"
PTU  = f"python3 {gorgon_home}/hooks/pre_tool_use_bash.py"
STOP = f"python3 {gorgon_home}/hooks/stop.py"

def already_installed(hook_list, suffix):
    return any(
        any(h.get("command", "").endswith(suffix) for h in entry.get("hooks", []))
        for entry in hook_list
    )

def add_hook(event, command, timeout=5, matcher=None):
    hook_list = hooks.setdefault(event, [])
    suffix = command.split("/")[-1]
    if already_installed(hook_list, suffix):
        print(f"  [{event}] {suffix}: already installed")
        return
    entry = {"hooks": [{"type": "command", "command": command, "timeout": timeout}]}
    if matcher:
        entry["matcher"] = matcher
    hook_list.append(entry)
    print(f"  [{event}] {suffix}: installed")

add_hook("UserPromptSubmit", UPS, timeout=5)
add_hook("Stop",             STOP, timeout=8)
add_hook("PreToolUse",       PTU, timeout=5, matcher="Bash")

settings_path.write_text(json.dumps(data, indent=2))
print("\nsettings.json written.")
PY

echo ""
echo "=== Verification ==="
SETTINGS="$SETTINGS" python3 - <<'PY'
import json, os, pathlib, sys
data = json.loads(pathlib.Path(os.environ["SETTINGS"]).read_text())
hooks = data.get("hooks", {})
required = {
    "UserPromptSubmit": "user_prompt_submit.py",
    "Stop":             "stop.py",
    "PreToolUse":       "pre_tool_use_bash.py",
}
ok = True
for event, suffix in required.items():
    found = any(
        any(h.get("command", "").endswith(suffix) for h in entry.get("hooks", []))
        for entry in hooks.get(event, [])
    )
    print(f"  {event:<20} {suffix:<28} {'OK' if found else 'MISSING'}")
    ok = ok and found
print("\nINSTALL COMPLETE." if ok else "ERROR: some hooks not registered.")
sys.exit(0 if ok else 1)
PY

echo ""
echo "=== Test ==="
echo "  cd $GORGON_HOME && python3 -m pytest tests/ -q"
echo ""
echo "=== First test in a fresh Claude Code session ==="
echo "  Prompt: 'Score Stripe on EU AI Act compliance. Output JSON.'"
echo "  Expected: model invokes the registered tool instead of fabricating."
