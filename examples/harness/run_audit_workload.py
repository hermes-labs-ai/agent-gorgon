#!/usr/bin/env python3
"""Run the owned-child-process workload fixtures through `--audit-only` and
report attribution / false-trigger / overhead evidence.

This is a thin compatibility wrapper: the actual harness now lives in the
installed package as `agent_warden.audit_demo`, exposed with zero extra setup
as the `agent-gorgon-audit-demo` console command (`pip install agent-gorgon`
is enough -- no repo checkout required). This script exists so a source
checkout can still run it as `python3 examples/harness/run_audit_workload.py`,
without duplicating the harness logic.

Usage:
    python3 examples/harness/run_audit_workload.py [--out report.json] [--keep]

Exit code is nonzero if any scenario's observed verdict does not match its
expected ground truth (a false trigger or a missed detection).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Direct script execution puts examples/harness, not the checkout root, on
# sys.path. Keep the documented source-checkout command runnable without an
# editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent_warden.audit_demo import main, run_scenario  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
