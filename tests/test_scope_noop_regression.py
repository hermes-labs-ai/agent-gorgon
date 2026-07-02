"""Regression for the silent-no-op scope bug (session 72d3af02).

The shipped generic scope was FLAT (allow_read/deny_write/deny_exec) while the
parser reads a NESTED schema, so it loaded empty allowlists and enforced nothing.
These tests pin: (1) every shipped example actually enforces, (2) a flat-schema
scope fails loud instead of running wide open.
"""
import pathlib

import pytest

from suy_sideguy.warden import Scope

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"


def test_generic_example_enforces_not_empty():
    s = Scope(str(EXAMPLES / "scope.generic.yaml"))
    assert s.allowed_paths, "generic scope has no allowed_paths -> enforces nothing"
    assert s.forbidden_paths
    assert s.forbidden_commands
    assert s.forbidden_extensions


def test_all_shipped_examples_enforce_something():
    for f in EXAMPLES.glob("scope.*.yaml"):
        s = Scope(str(f))
        assert any((s.allowed_paths, s.forbidden_paths, s.forbidden_extensions,
                    s.forbidden_commands, s.forbidden_domains)), \
            f"{f.name} loads but enforces nothing"


def test_flat_schema_fails_loud(tmp_path):
    p = tmp_path / "flat.yaml"
    p.write_text("allow_read:\n  - /tmp\ndeny_exec:\n  - curl\n")
    with pytest.raises(ValueError, match="flat schema"):
        Scope(str(p))
