"""Agent Warden runtime policy package."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

from ._version import __version__ as __version__

__all__ = [
    "warden",
    "forensic_report",
    "scope",
    "models",
    "policy",
    "enforcement",
    "observer",
    "cli",
]


def __getattr__(name: str) -> ModuleType:
    """Load public submodules lazily.

    Eager imports made ``python -m agent_warden.warden`` import the target module
    before runpy executed it, producing a RuntimeWarning on every documented CLI
    smoke test. Lazy loading preserves ``from agent_warden import warden`` while
    keeping module entry points clean.
    """
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(f".{name}", __name__)
    globals()[name] = module
    return module
