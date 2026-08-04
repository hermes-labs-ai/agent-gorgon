"""Preferred runtime-policy module for Agent Gorgon."""

from agent_warden.warden import *  # noqa: F401,F403
from agent_warden.warden import entrypoint as _entrypoint


if __name__ == "__main__":
    raise SystemExit(_entrypoint())
