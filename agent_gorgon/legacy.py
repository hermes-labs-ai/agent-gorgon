"""Console-entry compatibility aliases retained for Agent Warden users."""

from __future__ import annotations

import sys

from agent_warden.forensic_report import main as _forensic_main
from agent_warden.warden import entrypoint as _warden_entrypoint


def warden_entrypoint() -> int:
    print("DEPRECATION: agent-warden is deprecated; use agent-gorgon.", file=sys.stderr)
    return _warden_entrypoint()


def forensic_main() -> int:
    print("DEPRECATION: agent-warden-forensic is deprecated; use agent-gorgon-forensic.", file=sys.stderr)
    return _forensic_main()
