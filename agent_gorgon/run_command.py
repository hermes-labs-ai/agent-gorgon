"""Preferred command-wrapper module for Agent Gorgon (`agent-gorgon run`)."""

from agent_warden.run_command import *  # noqa: F401,F403
from agent_warden.run_command import main as _main

if __name__ == "__main__":
    raise SystemExit(_main())
