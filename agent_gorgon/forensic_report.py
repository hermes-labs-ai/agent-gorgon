"""Preferred forensic-report module for Agent Gorgon."""

from agent_warden.forensic_report import *  # noqa: F401,F403
from agent_warden.forensic_report import main as _main


if __name__ == "__main__":
    raise SystemExit(_main())
