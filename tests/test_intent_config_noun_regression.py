"""Regression: a read-only instruction that merely names a config object must
not be classified as CONFIG_CHANGE.

CONFIG_CHANGE is checked before READ and permits WRITE, so classifying
"read the config file" as CONFIG_CHANGE made ``check_intent_match`` report an
unsanctioned ``file_write`` as SAFE -- the guard failed open on exactly the
mismatch it exists to catch.
"""

from __future__ import annotations

import pytest

from agent_warden.intent_match import check_intent_match, classify_instruction


class _FakeAction:
    def __init__(self, kind: str) -> None:
        self.kind = kind


@pytest.mark.parametrize(
    "instruction",
    [
        "Read the config file",
        "Print the configuration",
        "Show the current settings",
        "Check the environment variables",
    ],
)
def test_read_only_config_mention_classifies_as_read(instruction: str) -> None:
    assert classify_instruction(instruction) == "READ"


def test_read_only_config_instruction_does_not_permit_write() -> None:
    """The fail-open case: this returned SAFE before the fix."""
    assert check_intent_match("Read the config file", [_FakeAction("file_write")]) == "FLAG"


def test_read_only_config_instruction_does_not_permit_config_change() -> None:
    assert check_intent_match("Print the configuration", [_FakeAction("config_change")]) == "HALT"


@pytest.mark.parametrize(
    "instruction",
    [
        "Update the config file",
        "Change the logging settings",
        "Set the environment variables for the run",
        "Configure the agent",
        "Install the dependencies",
        "Set up the virtualenv",
    ],
)
def test_mutating_config_instruction_still_classifies_as_config_change(instruction: str) -> None:
    assert classify_instruction(instruction) == "CONFIG_CHANGE"


def test_mutating_config_instruction_still_permits_write() -> None:
    assert check_intent_match("Update the config file", [_FakeAction("file_write")]) == "SAFE"
