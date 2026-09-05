"""Preferred owned-process audit demo module for Agent Gorgon."""

from agent_warden.audit_demo import *  # noqa: F401,F403
from agent_warden.audit_demo import main as _main

if __name__ == "__main__":
    raise SystemExit(_main())
