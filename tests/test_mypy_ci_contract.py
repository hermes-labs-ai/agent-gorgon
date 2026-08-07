"""Regression tests for the CI type-checking boundary."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MYPY_CONFIG = PROJECT_ROOT / "pyproject.toml"


def _run_mypy(
    target: Path, module_root: Path, *extra_args: str
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["MYPYPATH"] = str(module_root)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--no-incremental",
            "--config-file",
            str(MYPY_CONFIG),
            *extra_args,
            str(target),
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )


def test_mypy_skips_dependency_implementation_but_checks_project_code(tmp_path: Path) -> None:
    dependency = tmp_path / "dependency_with_newer_syntax.py"
    dependency.write_text(
        """\
def normalize(value: object) -> int:
    match value:
        case int():
            return value
        case _:
            return 0
""",
        encoding="utf-8",
    )
    valid_project = tmp_path / "valid_project.py"
    valid_project.write_text(
        """\
from dependency_with_newer_syntax import normalize

def check(value: object) -> int:
    return normalize(value)
""",
        encoding="utf-8",
    )

    old_contract = _run_mypy(valid_project, tmp_path, "--follow-imports=normal")
    assert old_contract.returncode != 0
    assert re.search(rf"{re.escape(dependency.name)}:\d+(?::\d+)?: error:", old_contract.stdout)
    assert "[syntax]" in old_contract.stdout

    corrected_contract = _run_mypy(valid_project, tmp_path)
    assert corrected_contract.returncode == 0, corrected_contract.stdout + corrected_contract.stderr

    invalid_project = tmp_path / "invalid_project.py"
    invalid_project.write_text(
        """\
from dependency_with_newer_syntax import normalize

def check(value: object) -> int:
    normalize(value)
    return "not an int"
""",
        encoding="utf-8",
    )
    project_error = _run_mypy(invalid_project, tmp_path)
    assert project_error.returncode != 0
    assert "Incompatible return value type" in project_error.stdout
    assert "Pattern matching is only supported" not in project_error.stdout
