"""Packaging regression: the audit demo must work from the installed package,
not only from examples/harness/.

`examples/harness/workload_fixtures.py` and `run_audit_workload.py` are thin
compatibility re-exports (see their module docstrings); the actual scenarios,
harness, and scope template live in `agent_warden.audit_demo` and are exposed
with zero extra setup as the `agent-gorgon-audit-demo` console command via the
canonical `agent_gorgon.audit_demo` re-export. This test imports the packaged
modules directly (no sys.path manipulation into examples/) and confirms the
scope template ships as package data and the console-script target resolves.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import tomllib

import agent_gorgon.audit_demo as gorgon_audit_demo
import agent_warden.audit_demo as warden_audit_demo


def test_scope_template_is_packaged_data():
    assert warden_audit_demo.SCOPE_TEMPLATE_PATH.exists()
    assert "WORKSPACE_GLOB" in warden_audit_demo.SCOPE_TEMPLATE_PATH.read_text()


def test_gorgon_namespace_reexports_scenarios_and_main():
    assert gorgon_audit_demo.ALL_SCENARIOS == warden_audit_demo.ALL_SCENARIOS
    assert gorgon_audit_demo.main is warden_audit_demo.main


def test_console_script_entry_point_matches_pyproject():
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    )
    scripts = pyproject["project"]["scripts"]
    assert scripts["agent-gorgon-audit-demo"] == "agent_gorgon.audit_demo:main"

    module_name, func_name = scripts["agent-gorgon-audit-demo"].split(":")
    module = importlib.import_module(module_name)
    assert callable(getattr(module, func_name))


def test_scope_template_is_declared_as_package_data():
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    )
    patterns = pyproject["tool"]["setuptools"]["package-data"]["agent_warden"]
    assert warden_audit_demo.SCOPE_TEMPLATE_PATH.name in patterns or any(
        warden_audit_demo.SCOPE_TEMPLATE_PATH.match(p) for p in patterns
    )


def test_source_checkout_wrapper_runs_without_install():
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "examples/harness/run_audit_workload.py", "--help"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--out OUT" in result.stdout
