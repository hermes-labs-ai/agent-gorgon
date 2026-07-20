"""Regression tests: HALT has teeth (reversible SIGSTOP) + deterministic
credential-exfil KILL.

Two fixes are covered:

Part A — a HALT verdict was a pure no-op (the run loop only logged it). It now
SIGSTOPs the agent process tree: a *reversible* pause (not SIGKILL). The signal
is sent ONCE per agent (idempotent), the process is left stopped, and a forensic
halt report records the reversible control.

Part B — a credential read followed by a network-out within a short window is the
real exfil signature and now KILLs. A bare network-out with NO preceding
credential read must NOT kill (benign curl/pip stay HALT/FLAG).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import psutil

from agent_warden.warden import (
    ActionType,
    AgentAction,
    Killswitch,
    Verdict,
    Warden,
    WardenVerdict,
)


SCOPE_YAML = """
filesystem:
  allowed_paths:
    - "/tmp/safe/**"
  forbidden_paths:
    - "/tmp/secret/**"
  forbidden_extensions:
    - ".pem"
network:
  allowed_domains:
    - "example.com"
  forbidden_domains:
    - "evil.com"
  allowed_ports: [443]
process:
  allowed_commands: ["python3"]
  forbidden_commands: ["curl"]
behavior:
  flag_threshold: 3
  flag_window: 60
  max_actions_per_minute: 200
"""


def _scope_file() -> str:
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        f.write(SCOPE_YAML)
        return f.name


def _warden(tmp_path=None) -> Warden:
    kw = {}
    if tmp_path is not None:
        kw["log_dir"] = str(tmp_path / "logs")
    return Warden(scope_path=_scope_file(), agent_pid=os.getpid(),
                  poll_interval=0.01, **kw)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _halt_verdict() -> WardenVerdict:
    action = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.FILE_DELETE,
        target="/tmp/safe/f.txt",
    )
    return WardenVerdict(verdict=Verdict.HALT, reason="Rapid file deletion: 3 "
                         "deletes in 10s", action=action, evaluator="rule_engine")


def _read(target: str, pid: int | None = None) -> AgentAction:
    return AgentAction(timestamp=_now_iso(), action_type=ActionType.FILE_READ,
                       target=target, source_pid=pid)


def _netout(target: str = "8.8.8.8:443", pid: int | None = None) -> AgentAction:
    return AgentAction(
        timestamp=_now_iso(), action_type=ActionType.NETWORK_OUT, target=target,
        details={"remote_ip": target.split(":")[0], "remote_port": 443},
        source_pid=pid,
    )


# ══════════════════════════════════════════════════════════════════════════
# PART A — HALT SIGSTOPs the agent (reversible), once, and records it
# ══════════════════════════════════════════════════════════════════════════

def test_execute_halt_suspends_once_idempotent(monkeypatch, tmp_path):
    w = _warden(tmp_path)
    calls = {"n": 0}

    def fake_suspend():
        calls["n"] += 1
        return {"suspended": True, "pids_suspended": [4321], "errors": []}

    monkeypatch.setattr(w.killswitch, "suspend_agent", fake_suspend)

    asyncio.run(w.execute_halt(_halt_verdict()))
    assert w.suspended is True
    assert calls["n"] == 1
    # Second HALT must NOT re-signal (no per-poll SIGSTOP spam).
    asyncio.run(w.execute_halt(_halt_verdict()))
    assert calls["n"] == 1


def test_execute_halt_retries_after_failed_no_pid_suspend(monkeypatch, tmp_path):
    w = _warden(tmp_path)
    results = iter([
        {"suspended": False, "pids_suspended": [], "errors": ["gone"]},
        {"suspended": True, "pids_suspended": [4321], "errors": []},
    ])
    calls = {"n": 0}

    def fake_suspend():
        calls["n"] += 1
        return next(results)

    monkeypatch.setattr(w.killswitch, "suspend_agent", fake_suspend)

    asyncio.run(w.execute_halt(_halt_verdict()))
    assert w.suspended is False
    assert calls["n"] == 1

    asyncio.run(w.execute_halt(_halt_verdict()))
    assert w.suspended is True
    assert calls["n"] == 2

    # Only a successful suspension suppresses later duplicate signals.
    asyncio.run(w.execute_halt(_halt_verdict()))
    assert calls["n"] == 2


def test_execute_halt_retries_after_partial_child_suspend(monkeypatch, tmp_path):
    """A stopped parent plus a live child is not a completed HALT."""
    w = _warden(tmp_path)
    results = iter([
        {
            "suspended": True,
            "pids_suspended": [4321],
            "errors": ["Child 4322: denied"],
        },
        {
            "suspended": True,
            "pids_suspended": [4321, 4322],
            "errors": [],
        },
    ])
    calls = {"n": 0}

    def partial_then_complete():
        calls["n"] += 1
        return next(results)

    monkeypatch.setattr(w.killswitch, "suspend_agent", partial_then_complete)

    asyncio.run(w.execute_halt(_halt_verdict()))
    assert w.suspended is False
    assert calls["n"] == 1

    asyncio.run(w.execute_halt(_halt_verdict()))
    assert w.suspended is True
    assert calls["n"] == 2


def test_retryable_halt_reports_do_not_overwrite_in_same_second(
    monkeypatch, tmp_path
):
    w = _warden(tmp_path)
    monkeypatch.setattr(
        w.killswitch,
        "suspend_agent",
        lambda: {"suspended": False, "pids_suspended": [], "errors": ["denied"]},
    )
    monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
    monkeypatch.setattr(time, "time_ns", lambda: 1_700_000_000_000_000_000)

    asyncio.run(w.execute_halt(_halt_verdict()))
    asyncio.run(w.execute_halt(_halt_verdict()))

    reports = list((tmp_path / "logs" / "incidents").glob("halt_*.json"))
    assert len(reports) == 2
    assert reports[0].name != reports[1].name


def test_failed_halt_report_does_not_claim_agent_suspended(monkeypatch, tmp_path):
    w = _warden(tmp_path)
    monkeypatch.setattr(
        w.killswitch,
        "suspend_agent",
        lambda: {"suspended": False, "pids_suspended": [], "errors": ["gone"]},
    )

    asyncio.run(w.execute_halt(_halt_verdict()))

    import json
    reports = list((tmp_path / "logs" / "incidents").glob("halt_*.json"))
    assert reports
    doc = json.loads(reports[0].read_text(encoding="utf-8"))
    assert doc["halt_report"]["status"] == "SUSPENSION_FAILED"
    assert doc["control_action"]["suspended"] is False
    assert doc["liability_statement"]["agent_process_suspended"] is False


def test_execute_halt_is_reversible_not_a_kill(monkeypatch, tmp_path):
    w = _warden(tmp_path)
    monkeypatch.setattr(w.killswitch, "suspend_agent",
                        lambda: {"suspended": True, "pids_suspended": [1], "errors": []})
    asyncio.run(w.execute_halt(_halt_verdict()))
    # SIGSTOP is a pause, NOT a termination.
    assert w.killed is False


def test_execute_halt_writes_reversible_forensic_report(monkeypatch, tmp_path):
    w = _warden(tmp_path)
    monkeypatch.setattr(w.killswitch, "suspend_agent",
                        lambda: {"suspended": True, "pids_suspended": [1], "errors": []})
    asyncio.run(w.execute_halt(_halt_verdict()))
    reports = list((tmp_path / "logs" / "incidents").glob("halt_*.json"))
    assert reports, "a halt forensic report should be written"

    import json
    doc = json.loads(reports[0].read_text(encoding="utf-8"))
    assert doc["halt_report"]["status"] == "AGENT_SUSPENDED"
    assert doc["control_action"]["method"] == "SIGSTOP"
    assert doc["control_action"]["reversible"] is True
    assert doc["liability_statement"]["agent_process_terminated"] is False


def test_suspend_agent_really_sigstops_a_child_process():
    """End-to-end: Killswitch.suspend_agent() puts a real child into the OS
    'stopped' state (reversible), and SIGCONT resumes it."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        ks = Killswitch(proc.pid)
        result = ks.suspend_agent()
        assert result["suspended"] is True
        assert proc.pid in result["pids_suspended"]

        # Poll briefly for the kernel to reflect the stopped state.
        p = psutil.Process(proc.pid)
        stopped = False
        for _ in range(50):
            if p.status() == psutil.STATUS_STOPPED:
                stopped = True
                break
            time.sleep(0.02)
        assert stopped, f"expected STATUS_STOPPED, got {p.status()}"

        # Reversible: SIGCONT brings it back to a running/sleeping state.
        p.resume()
        for _ in range(50):
            if p.status() != psutil.STATUS_STOPPED:
                break
            time.sleep(0.02)
        assert p.status() != psutil.STATUS_STOPPED
    finally:
        try:
            proc.kill()
        except Exception:
            pass
        proc.wait(timeout=5)


def test_suspend_agent_fail_open_on_dead_pid():
    """A gone pid must not raise — the pause is best-effort/fail-open."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=5)
    ks = Killswitch(proc.pid)
    result = ks.suspend_agent()  # must not raise
    assert result["suspended"] is False
    assert result["errors"]


def test_suspend_agent_stops_parent_before_enumerating_and_drains_fork_race(
    monkeypatch,
):
    """Children appearing during suspension are discovered before completion."""
    events = []

    class FakeChild:
        def __init__(self, pid):
            self.pid = pid

        def suspend(self):
            events.append(("child_suspend", self.pid))

    first = FakeChild(2001)
    late = FakeChild(2002)

    class FakeParent:
        pid = 2000

        def __init__(self):
            self.stopped = False
            self.enumerations = 0

        def suspend(self):
            self.stopped = True
            events.append(("parent_suspend", self.pid))

        def children(self, recursive=True):
            assert recursive is True
            assert self.stopped, "parent must be stopped before child enumeration"
            self.enumerations += 1
            if self.enumerations == 1:
                return [first]
            return [first, late]

    parent = FakeParent()
    monkeypatch.setattr(psutil, "Process", lambda pid: parent)

    result = Killswitch(parent.pid).suspend_agent()

    assert result["suspended"] is True
    assert result["pids_suspended"] == [2000, 2001, 2002]
    assert events == [
        ("parent_suspend", 2000),
        ("child_suspend", 2001),
        ("child_suspend", 2002),
    ]


def test_suspend_agent_reports_partial_child_failure_as_incomplete(monkeypatch):
    """The aggregate completion bit covers every observed descendant."""

    class DeniedChild:
        pid = 2001

        def suspend(self):
            raise psutil.AccessDenied(self.pid)

    class FakeParent:
        pid = 2000

        def __init__(self):
            self.enumerations = 0

        def suspend(self):
            return None

        def children(self, recursive=True):
            self.enumerations += 1
            return [DeniedChild()]

    parent = FakeParent()
    monkeypatch.setattr(psutil, "Process", lambda pid: parent)

    result = Killswitch(parent.pid).suspend_agent()

    assert result["suspended"] is False
    assert result["pids_suspended"] == [2000]
    assert result["errors"] == ["Child 2001: (pid=2001)"]


# ══════════════════════════════════════════════════════════════════════════
# PART B — deterministic credential-read-then-network-out KILL
# ══════════════════════════════════════════════════════════════════════════

def test_is_credential_target_detects_secret_material():
    w = _warden()
    assert w._is_credential_target("/some/path/id_rsa")
    assert w._is_credential_target("/deploy/server.pem")
    assert w._is_credential_target(os.path.expanduser("~/.aws/credentials"))
    assert w._is_credential_target("/tmp/safe/app.credentials")
    assert w._is_credential_target("/tmp/secret/token.txt")  # scope forbidden
    # Ordinary files are NOT credential material.
    assert not w._is_credential_target("/tmp/safe/notes.txt")
    assert not w._is_credential_target("/tmp/safe/data.json")


def test_credential_read_then_network_out_kills():
    w = _warden()
    w.judge.available = False
    # A credential read that is itself in-scope (SAFE) but secret-shaped, so the
    # KILL comes from the EXFIL rule, not the read-time hard-kill.
    r = asyncio.run(w.evaluate_action(_read("/tmp/safe/app.credentials", pid=111)))
    assert r.verdict != Verdict.KILL  # the read alone is not a kill
    v = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443", pid=111)))
    assert v.verdict == Verdict.KILL
    assert "exfil" in v.reason.lower()


def test_bare_network_out_without_cred_read_does_not_kill():
    w = _warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443")))
    assert v.verdict != Verdict.KILL
    assert v.verdict == Verdict.FLAG  # unknown host, LLM unavailable


def test_ordinary_read_then_network_out_does_not_kill():
    """Only CREDENTIAL reads arm the rule — an ordinary read then a network-out
    is benign work and must not KILL."""
    w = _warden()
    w.judge.available = False
    asyncio.run(w.evaluate_action(_read("/tmp/safe/notes.txt", pid=222)))
    v = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443", pid=222)))
    assert v.verdict != Verdict.KILL


def test_credential_read_outside_window_does_not_kill():
    """A credential read that fell outside cred_exfil_window is pruned, so a
    later network-out is not exfil."""
    w = _warden()
    w.judge.available = False
    w.cred_exfil_window = 15.0
    # Inject a stale read (100s ago) — beyond the window.
    w.credential_reads = {333: [time.time() - 100]}
    v = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443", pid=333)))
    assert v.verdict != Verdict.KILL


def test_cred_read_then_netout_kills_across_pids_in_tree():
    """Parent reads the secret, child does the network-out: tree-scoped
    correlation must still catch it."""
    w = _warden()
    w.judge.available = False
    asyncio.run(w.evaluate_action(_read("/tmp/safe/app.credentials", pid=1000)))
    v = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443", pid=2000)))
    assert v.verdict == Verdict.KILL


def test_credential_read_then_localhost_ipc_stays_safe_but_window_remains_armed():
    """Local Ollama/IPC is not egress; later external traffic still is."""
    w = _warden()
    w.judge.available = False
    asyncio.run(w.evaluate_action(_read("/tmp/safe/app.credentials", pid=1000)))

    local = asyncio.run(w.evaluate_action(_netout("127.0.0.1:11434", pid=2000)))
    external = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443", pid=2000)))

    assert local.verdict == Verdict.SAFE
    assert "localhost" in local.reason.lower()
    assert external.verdict == Verdict.KILL

    ipv6 = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.NETWORK_OUT,
        target="[::1]:11434",
        details={"remote_ip": "::1", "remote_port": 11434},
        source_pid=2000,
    )
    assert asyncio.run(w.evaluate_action(ipv6)).verdict == Verdict.SAFE


def test_credential_read_write_handle_then_netout_kills():
    """A '+' file mode permits reading even though the observer preserves the
    stronger FILE_WRITE classification for the same handle."""
    w = _warden()
    w.judge.available = False
    read_write = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.FILE_WRITE,
        target="/tmp/safe/app.credentials",
        details={"mode": "r+", "fd": 9},
        source_pid=1000,
    )
    asyncio.run(w.evaluate_action(read_write))
    v = asyncio.run(w.evaluate_action(_netout("8.8.8.8:443", pid=2000)))
    assert v.verdict == Verdict.KILL
    assert "exfil" in v.reason.lower()


def test_same_poll_read_write_credential_precedes_network_enforcement():
    w = _warden()
    w.judge.available = False
    read_write = AgentAction(
        timestamp=_now_iso(),
        action_type=ActionType.FILE_WRITE,
        target="/tmp/safe/app.credentials",
        details={"mode": "r+", "fd": 9},
        source_pid=1000,
    )
    actions = [_netout("8.8.8.8:443", pid=2000), read_write]
    ordered = w._order_actions_for_enforcement(actions)
    verdicts = [asyncio.run(w.evaluate_action(action)) for action in ordered]
    assert ordered[0] is read_write
    assert verdicts[-1].verdict == Verdict.KILL


def test_same_poll_reversed_observer_order_still_kills_credential_exfil():
    """Observer collection order is not causal: a connection may be reported
    before the file read that armed it in the same poll. Enforcement must treat
    same-poll credential reads as preceding egress regardless of list order."""
    w = _warden()
    w.judge.available = False
    actions = [
        _netout("8.8.8.8:443", pid=2000),
        _read("/tmp/safe/app.credentials", pid=1000),
    ]

    ordered = w._order_actions_for_enforcement(actions)
    verdicts = [asyncio.run(w.evaluate_action(action)) for action in ordered]

    assert ordered[0].action_type == ActionType.FILE_READ
    assert ordered[1].action_type == ActionType.NETWORK_OUT
    assert verdicts[-1].verdict == Verdict.KILL
    assert "exfil" in verdicts[-1].reason.lower()


def test_same_poll_ordinary_read_does_not_reorder_or_arm_exfil():
    w = _warden()
    w.judge.available = False
    actions = [
        _netout("8.8.8.8:443", pid=2000),
        _read("/tmp/safe/notes.txt", pid=1000),
    ]

    ordered = w._order_actions_for_enforcement(actions)
    verdicts = [asyncio.run(w.evaluate_action(action)) for action in ordered]

    assert ordered == actions
    assert all(verdict.verdict != Verdict.KILL for verdict in verdicts)


def test_forbidden_credential_read_still_kills_on_read():
    """Regression: exfil tracking must not weaken the read-time hard-kill for a
    forbidden-path credential read."""
    w = _warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_read("/tmp/secret/token.txt")))
    assert v.verdict == Verdict.KILL


def test_failed_one_shot_kill_is_retried_without_new_observation(
    monkeypatch, tmp_path
):
    w = _warden(tmp_path)
    w.enable_llm = False
    kill_results = iter([
        {"killed": False, "pids_terminated": [], "errors": ["denied"]},
        {"killed": True, "pids_terminated": [os.getpid()], "errors": []},
    ])
    kill_calls = {"count": 0}

    def fail_then_succeed():
        kill_calls["count"] += 1
        return next(kill_results)

    class OneShotObserver:
        def __init__(self):
            self.alive_calls = 0
            self.observe_calls = 0

        def is_agent_alive(self):
            self.alive_calls += 1
            return self.alive_calls <= 2

        def observe(self):
            self.observe_calls += 1
            if self.observe_calls == 1:
                return [_read("/tmp/secret/token.txt", pid=os.getpid())]
            return []

    observer = OneShotObserver()
    w.observer = observer
    monkeypatch.setattr(w.killswitch, "kill_agent", fail_then_succeed)

    asyncio.run(w.run())

    assert kill_calls["count"] == 2
    assert observer.observe_calls == 1
    assert w.killed is True
    assert w.pending_kill is None
