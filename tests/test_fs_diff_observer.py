"""Regression tests for the poll-time filesystem-diff observer.

Covers the macOS blind spot: psutil.open_files() cannot see in-process deletes
(os.remove() opens no fd). The ProcessObserver now snapshots the scope's
workspace dirs each poll and emits synthetic FILE_DELETE / FILE_WRITE actions
from the path-set diff, which feed the existing "3 deletes in 10s -> HALT" rule.
"""

import asyncio
import os
import tempfile
from datetime import datetime, timezone

from suy_sideguy.warden import (
    ActionType,
    AgentAction,
    ProcessObserver,
    Verdict,
    Warden,
)


class _FakeScope:
    """Minimal scope stand-in — the observer only needs allowed_paths."""

    def __init__(self, allowed_paths):
        self.allowed_paths = allowed_paths


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _observer(allowed_paths):
    obs = ProcessObserver(os.getpid(), scope=_FakeScope(allowed_paths))
    obs._snapshot_min_interval = 0.0  # disable cadence gate for deterministic tests
    return obs


# ── scope-root computation ───────────────────────────────────────────────────

def test_scope_roots_are_literal_prefixes_of_allowed_globs():
    obs = _observer(["/tmp/foo/**", "/tmp/bar/*.txt", "/tmp/foo/**"])
    # duplicates collapse; prefix is everything before the first glob metachar
    assert obs._scope_roots == ["/tmp/foo", "/tmp/bar"]


def test_filesystem_root_glob_is_excluded():
    # '/**' -> '/' must be skipped: snapshotting the whole filesystem would melt.
    obs = _observer(["/**", "/tmp/keep/**"])
    assert obs._scope_roots == ["/tmp/keep"]


def test_symlink_aliased_roots_dedup_to_one(tmp_path):
    # A symlink alias (the macOS '/tmp' -> '/private/tmp' case) listed twice must
    # collapse to ONE walked root — otherwise every FS event double-counts and the
    # HALT threshold is effectively halved (a false-positive-kill vector).
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    obs = _observer([f"{real}/**", f"{link}/**"])
    assert obs._scope_roots == [str(real)]  # first spelling kept, alias dropped


def test_no_scope_means_no_roots_and_diff_is_a_noop():
    obs = ProcessObserver(os.getpid())  # backward-compatible: scope optional
    assert obs._scope_roots == []
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)
    assert actions == []


# ── baseline / delete / create diff logic ────────────────────────────────────

def test_baseline_poll_emits_nothing(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    obs = _observer([f"{tmp_path}/**"])
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)  # first call = baseline
    assert actions == []
    assert obs._scope_snapshot is not None


def test_delete_set_emits_file_delete(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("x")
    obs = _observer([f"{tmp_path}/**"])
    obs._diff_scope_filesystem(_now_iso(), [])  # baseline (file present)
    victim.unlink()  # in-process delete — opens no fd
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)
    deletes = [a for a in actions if a.action_type == ActionType.FILE_DELETE]
    assert len(deletes) == 1
    assert deletes[0].target == str(victim)
    assert deletes[0].details.get("detected_by") == "scope_diff"
    assert deletes[0].source_pid == obs.agent_pid


def test_create_set_emits_file_write(tmp_path):
    obs = _observer([f"{tmp_path}/**"])
    obs._diff_scope_filesystem(_now_iso(), [])  # baseline (empty)
    (tmp_path / "new.txt").write_text("x")
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)
    writes = [a for a in actions if a.action_type == ActionType.FILE_WRITE]
    assert len(writes) == 1
    assert writes[0].target == str(tmp_path / "new.txt")
    assert writes[0].details.get("detected_by") == "scope_diff"


def test_mass_delete_emits_one_delete_per_file(tmp_path):
    paths = [tmp_path / f"f{i}.tmp" for i in range(50)]
    for p in paths:
        p.write_text("x")
    obs = _observer([f"{tmp_path}/**"])
    obs._diff_scope_filesystem(_now_iso(), [])  # baseline: 50 files
    for p in paths:
        p.unlink()  # in-process mass-delete
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)
    deletes = [a for a in actions if a.action_type == ActionType.FILE_DELETE]
    assert len(deletes) == 50


# ── count cap ────────────────────────────────────────────────────────────────

def test_count_cap_emits_single_flag_and_no_per_file_actions(tmp_path):
    for i in range(20):
        (tmp_path / f"f{i}.txt").write_text("x")
    obs = _observer([f"{tmp_path}/**"])
    obs._snapshot_file_cap = 5  # force the cap
    files, capped = obs._snapshot_scope_files()
    assert capped is True
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)
    assert len(actions) == 1
    assert actions[0].action_type == ActionType.UNKNOWN
    assert actions[0].target == "scope too large to snapshot"
    # a capped/truncated snapshot must NOT establish a baseline (would emit
    # spurious deletes on the next poll)
    assert obs._scope_snapshot is None


# ── fail-open ────────────────────────────────────────────────────────────────

def test_fail_open_on_missing_dir_does_not_raise(tmp_path):
    missing = tmp_path / "does_not_exist"
    obs = _observer([f"{missing}/**"])
    files, capped = obs._snapshot_scope_files()  # must not raise
    assert files == set()
    assert capped is False
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)  # baseline, no crash
    obs._diff_scope_filesystem(_now_iso(), actions)  # diff, no crash
    assert actions == []


def test_diff_survives_a_root_that_vanishes_between_polls(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    (root / "a.txt").write_text("x")
    obs = _observer([f"{root}/**"])
    obs._diff_scope_filesystem(_now_iso(), [])  # baseline
    # entire root disappears (e.g. rmdir): per-dir try/except keeps the warden up
    (root / "a.txt").unlink()
    root.rmdir()
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)  # must not raise
    deletes = [a for a in actions if a.action_type == ActionType.FILE_DELETE]
    assert len(deletes) == 1


# ── cadence gate ─────────────────────────────────────────────────────────────

def test_cadence_gate_skips_walk_until_min_interval_elapses(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    obs = ProcessObserver(os.getpid(), scope=_FakeScope([f"{tmp_path}/**"]))
    obs._snapshot_min_interval = 999.0  # effectively never re-snapshot
    obs._diff_scope_filesystem(_now_iso(), [])  # first call baselines
    baseline = obs._scope_snapshot
    (tmp_path / "b.txt").write_text("x")  # change the tree
    actions: list = []
    obs._diff_scope_filesystem(_now_iso(), actions)  # gated out -> no walk
    assert actions == []
    assert obs._scope_snapshot is baseline  # snapshot untouched


# ── routing: diff deletes HALT, never instant-KILL ───────────────────────────

_ROUTING_SCOPE = """
filesystem:
  allowed_paths:
    - "/tmp/work/**"
  forbidden_paths:
    - "/tmp/work/secrets/**"
  forbidden_extensions:
    - ".pem"
network:
  allowed_domains: ["example.com"]
  allowed_ports: [443]
process:
  allowed_commands: ["python3"]
  forbidden_commands: ["curl"]
behavior:
  flag_threshold: 5
  flag_window: 60
  max_actions_per_minute: 240
"""


def _routing_warden() -> Warden:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(_ROUTING_SCOPE)
        path = f.name
    return Warden(scope_path=path, agent_pid=os.getpid(), poll_interval=0.01)


def _diff_delete(target: str) -> AgentAction:
    return AgentAction(
        timestamp=_now_iso(), action_type=ActionType.FILE_DELETE,
        target=target, details={"detected_by": "scope_diff"},
        source_pid=os.getpid(),
    )


def test_three_diff_deletes_route_to_halt():
    w = _routing_warden()
    w.judge.available = False
    verdicts = [
        asyncio.run(w.evaluate_action(_diff_delete(f"/tmp/work/f{i}.txt")))
        for i in range(3)
    ]
    assert verdicts[-1].verdict == Verdict.HALT
    assert "deletion" in verdicts[-1].reason.lower()


def test_single_benign_diff_delete_is_safe_not_halt_or_kill():
    w = _routing_warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_diff_delete("/tmp/work/note.txt")))
    assert v.verdict == Verdict.SAFE  # under the 3-in-10s threshold, in-scope


def test_diff_delete_of_forbidden_path_is_halt_not_kill():
    # A dir diff can't attribute the delete to a pid, so even a protected-path
    # delete must NOT instant-SIGKILL (a non-agent writer would be a false kill).
    w = _routing_warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_diff_delete("/tmp/work/secrets/key.txt")))
    assert v.verdict == Verdict.HALT
    assert v.verdict != Verdict.KILL


def test_attributed_forbidden_delete_still_kills_when_not_from_diff():
    # Regression guard: the diff carve-out must NOT weaken attributed actions.
    w = _routing_warden()
    w.judge.available = False
    attributed = AgentAction(
        timestamp=_now_iso(), action_type=ActionType.FILE_READ,
        target="/tmp/work/secrets/key.txt",
    )
    v = asyncio.run(w.evaluate_action(attributed))
    assert v.verdict == Verdict.KILL
