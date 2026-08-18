from __future__ import annotations

import sys
import warnings

REMOVAL_RELEASE = "0.4.0"
REMOVAL_NOT_BEFORE = "2026-10-10"
MESSAGE = (
    "suy-sideguy is deprecated; migrate to the agent-gorgon distribution, "
    "agent_gorgon imports, and agent-gorgon commands. The compatibility shim is proposed "
    f"for removal in {REMOVAL_RELEASE}, no earlier than {REMOVAL_NOT_BEFORE}."
)


def warn_import() -> None:
    warnings.warn(MESSAGE, DeprecationWarning, stacklevel=3)


def warn_cli() -> None:
    print(f"DEPRECATION: {MESSAGE}", file=sys.stderr)
