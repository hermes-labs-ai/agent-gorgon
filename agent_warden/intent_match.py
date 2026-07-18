"""Intent-action consistency checker.

Classifies a natural-language instruction into an intent category, then
compares that intent against what was actually observed.  Returns a verdict
string: "SAFE", "FLAG", or "HALT".
"""

from __future__ import annotations

import re


# ── Intent classification ────────────────────────────────────────────────────

# Ordered from most-specific / highest-severity to least, so the first match wins.
_INTENT_PATTERNS: list[tuple[str, list[str]]] = [
    ("DELETE",        [r"\bdelete\b", r"\bremove\b", r"\berase\b", r"\bclean(?:up)?\b",
                       r"\bpurge\b", r"\btrash\b"]),
    ("SPAWN",         [r"\bspawn\b", r"\bexecute\b", r"\blaunch\b", r"\bfork\b",
                       r"\brun\s+(?:a\s+)?(?:script|command|process|program)\b"]),
    ("NETWORK",       [r"\bdownload\b", r"\bupload\b", r"\bfetch\b", r"\bsend\b",
                       r"\bpost\b", r"\bpull\b", r"\bpush\b", r"\bhttp\b", r"\burl\b",
                       r"\bnetwork\b", r"\bconnect\b", r"\bapi\s+call\b"]),
    ("CONFIG_CHANGE", [r"\bconfig(?:ure|uration)?\b", r"\bsetting\b",
                       r"\benvironment\s+var\b", r"\binstall\b", r"\bset\s+up\b"]),
    ("WRITE",         [r"\bwrite\b", r"\bcreate\b", r"\bsave\b", r"\bstore\b",
                       r"\bmodif(?:y|ied)\b", r"\bupdate\b", r"\bedit\b", r"\bappend\b",
                       r"\bgenerate\b"]),
    ("READ",          [r"\bread\b", r"\bcheck\b", r"\blist\b", r"\bshow\b",
                       r"\bdisplay\b", r"\bprint\b", r"\bget\b", r"\bload\b",
                       r"\bopen\b", r"\bview\b", r"\bsearch\b", r"\bfind\b",
                       r"\bscan\b", r"\banalyze\b", r"\binspect\b", r"\bparse\b"]),
]


def classify_instruction(text: str) -> str:
    """Return the dominant intent category for *text*."""
    lower = text.lower()
    for intent, patterns in _INTENT_PATTERNS:
        for pat in patterns:
            if re.search(pat, lower):
                return intent
    return "READ"  # safe default


# ── Action kind normalisation ────────────────────────────────────────────────

_KIND_MAP: dict[str, str] = {
    # ActionType.value strings from warden.py
    "file_read":     "READ",
    "file_write":    "WRITE",
    "file_delete":   "DELETE",
    "network_out":   "NETWORK",
    "process_exec":  "SPAWN",
    "process_spawn": "SPAWN",
    "unknown":       "READ",
    # Short aliases that callers may use directly
    "read":          "READ",
    "write":         "WRITE",
    "delete":        "DELETE",
    "network":       "NETWORK",
    "spawn":         "SPAWN",
    "exec":          "SPAWN",
    "config":        "CONFIG_CHANGE",
    "config_change": "CONFIG_CHANGE",
}


def _normalize_kind(kind: object) -> str:
    """Normalise an action's ``.kind`` attribute to an intent category string."""
    raw = kind.value if hasattr(kind, "value") else str(kind)
    return _KIND_MAP.get(raw.lower(), "READ")


# ── Mismatch severity ────────────────────────────────────────────────────────

# Actions that warrant HALT when not sanctioned by the instruction intent
_HALT_ACTIONS: frozenset[str] = frozenset({"DELETE", "SPAWN", "CONFIG_CHANGE"})

# Actions that warrant FLAG when not sanctioned
_FLAG_ACTIONS: frozenset[str] = frozenset({"WRITE", "NETWORK"})

# What each intent permits without complaint
_PERMITTED: dict[str, frozenset[str]] = {
    "READ":          frozenset({"READ"}),
    "WRITE":         frozenset({"READ", "WRITE"}),
    "DELETE":        frozenset({"READ", "WRITE", "DELETE"}),
    "NETWORK":       frozenset({"READ", "NETWORK"}),
    "SPAWN":         frozenset({"READ", "SPAWN"}),
    "CONFIG_CHANGE": frozenset({"READ", "WRITE", "CONFIG_CHANGE"}),
}


# ── Public API ───────────────────────────────────────────────────────────────

def check_intent_match(instruction: str, observed_actions: list) -> str:
    """Compare instruction intent against observed actions.

    Args:
        instruction:      Natural-language task description.
        observed_actions: Objects with a ``.kind`` attribute (string or Enum).

    Returns:
        ``"SAFE"``  – all observed actions are consistent with the instruction.
        ``"FLAG"``  – an unexpected but non-destructive action was observed.
        ``"HALT"``  – a dangerous action inconsistent with the instruction was
                      observed.
    """
    intent = classify_instruction(instruction)
    permitted = _PERMITTED.get(intent, frozenset({"READ"}))

    worst = "SAFE"
    for event in observed_actions:
        kind = _normalize_kind(getattr(event, "kind", "unknown"))
        if kind in permitted:
            continue
        if kind in _HALT_ACTIONS:
            return "HALT"  # short-circuit on first HALT-worthy mismatch
        if kind in _FLAG_ACTIONS:
            worst = "FLAG"

    return worst
