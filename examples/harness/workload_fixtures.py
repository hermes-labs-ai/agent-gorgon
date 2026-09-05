"""Owned-child-process workload fixtures for auditing Agent Gorgon.

This is a thin compatibility re-export: the fixtures now live in the installed
package as `agent_warden.audit_demo` (also reachable packaged and with zero
extra setup as the `agent-gorgon-audit-demo` console command) so that
installed users get the same harness as this source checkout, with no
duplicated logic. Run `agent-gorgon-audit-demo` directly, or keep using this
module from a checkout.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent_warden.audit_demo import (  # noqa: F401
    ALL_SCENARIOS,
    Scenario,
    forbidden_extension_write,
    safe_workspace_write,
    suspicious_child_name,
)
