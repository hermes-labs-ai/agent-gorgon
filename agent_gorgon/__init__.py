"""Preferred public import namespace for Agent Gorgon."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

from agent_warden import __version__ as __version__

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
    """Load the corresponding implementation module without eager imports."""
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(f"agent_warden.{name}")
    globals()[name] = module
    return module
