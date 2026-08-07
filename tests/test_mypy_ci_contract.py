"""Regression tests for the CI type-checking boundary."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


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
    # The dependency body contains a type error that is only reachable if mypy
    # follows the import and checks the implementation. A type error is used rather
    # than version-gated syntax because `python_version` is no longer pinned in the
    # config -- mypy 2.x dropped 3.9 as a target -- so the effective syntax level
    # varies with the interpreter under test.
    dependency = tmp_path / "dependency_implementation.py"
    dependency.write_text(
        """\
def normalize(value: object) -> int:
    return "dependency implementations are not type checked"
""",
        encoding="utf-8",
    )
    valid_project = tmp_path / "valid_project.py"
    valid_project.write_text(
        """\
from dependency_implementation import normalize

def check(value: object) -> int:
    return normalize(value)
""",
        encoding="utf-8",
    )

    dependency_error = re.compile(rf"{re.escape(dependency.name)}:\d+(?::\d+)?: error:")

    # Control: with imports followed, the dependency's own error is reported.
    followed = _run_mypy(valid_project, tmp_path, "--follow-imports=normal")
    assert followed.returncode != 0, followed.stdout + followed.stderr
    assert dependency_error.search(followed.stdout), followed.stdout
    assert "[return-value]" in followed.stdout, followed.stdout

    # Contract part 1: under the project config, the dependency is not checked.
    skipped = _run_mypy(valid_project, tmp_path)
    assert skipped.returncode == 0, skipped.stdout + skipped.stderr
    assert not dependency_error.search(skipped.stdout), skipped.stdout

    # Contract part 2: project code is still checked.
    invalid_project = tmp_path / "invalid_project.py"
    invalid_project.write_text(
        """\
from dependency_implementation import normalize

def check(value: object) -> int:
    normalize(value)
    return "not an int"
""",
        encoding="utf-8",
    )
    project_error = _run_mypy(invalid_project, tmp_path)
    assert project_error.returncode != 0, project_error.stdout + project_error.stderr
    assert "Incompatible return value type" in project_error.stdout, project_error.stdout
    assert not dependency_error.search(project_error.stdout), project_error.stdout


def test_mypy_config_is_accepted_without_warnings() -> None:
    """The config must not carry settings the installed mypy rejects or ignores.

    mypy reports unsupported config keys/values on stderr and continues, so a stale
    setting (such as the `python_version = "3.9"` pin that mypy 2.x refuses) stays
    silently inert instead of failing CI.
    """
    result = _run_mypy(PROJECT_ROOT / "agent_warden", PROJECT_ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
    assert MYPY_CONFIG.name not in result.stderr, result.stderr
    assert "is not supported" not in result.stderr, result.stderr
