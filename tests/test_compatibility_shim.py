from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


SHIM_SRC = Path(__file__).parents[1] / "compat" / "suy-sideguy" / "src"


def _clear_legacy_modules() -> None:
    for name in tuple(sys.modules):
        if name == "suy_sideguy" or name.startswith("suy_sideguy."):
            del sys.modules[name]


def test_legacy_imports_warn_and_forward(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(SHIM_SRC))
    _clear_legacy_modules()

    with pytest.warns(DeprecationWarning, match="suy-sideguy is deprecated"):
        legacy = importlib.import_module("suy_sideguy")

    canonical = importlib.import_module("agent_warden")
    legacy_warden = importlib.import_module("suy_sideguy.warden")
    canonical_warden = importlib.import_module("agent_warden.warden")

    assert legacy.__version__ == canonical.__version__
    assert legacy_warden.Warden is canonical_warden.Warden
    assert legacy_warden.Scope is canonical_warden.Scope


@pytest.mark.parametrize(
    ("module", "symbol"),
    [
        ("forensic_report", "parse_ts"),
        ("intent_match", "classify_instruction"),
        ("models", "AgentAction"),
        ("scope", "Scope"),
    ],
)
def test_legacy_submodules_reexport_public_symbols(
    monkeypatch: pytest.MonkeyPatch, module: str, symbol: str
) -> None:
    monkeypatch.syspath_prepend(str(SHIM_SRC))
    _clear_legacy_modules()

    with pytest.warns(DeprecationWarning):
        legacy = importlib.import_module(f"suy_sideguy.{module}")
    canonical = importlib.import_module(f"agent_warden.{module}")

    assert getattr(legacy, symbol) is getattr(canonical, symbol)


@pytest.mark.parametrize("module", ["warden", "forensic_report"])
def test_legacy_python_module_cli_forwards_with_visible_warning(module: str) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(SHIM_SRC), str(Path(__file__).parents[1])])
    result = subprocess.run(
        [sys.executable, "-m", f"suy_sideguy.{module}", "--help"],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "DEPRECATION: suy-sideguy is deprecated" in result.stderr
    assert "usage:" in result.stdout
