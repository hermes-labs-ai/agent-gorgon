"""Safety-hygiene regression: the LLM judge is ADVISORY ONLY and OFF the hot path.

Two properties are proven here:

Property 1 — the LLM can NEVER issue KILL or trigger SIGKILL/SIGSTOP. Its verdict
is capped at SAFE / FLAG (raise monitoring posture). KILL and HALT are the
deterministic rule engine's exclusive authority (deterministic, explainable,
reproducible — as an irreversible SIGKILL must be).

Property 2 — the LLM must not block real-time enforcement. The deterministic
rule-engine verdict is computed and returned WITHOUT awaiting the model. The
judge runs fire-and-forget off the hot path, so a slow/hanging model cannot open
a blind window on the monitor (the DoS-on-the-warden risk).

Acceptance mapping:
  (a) an LLM "KILL" does NOT kill/suspend — deterministic verdict wins, LLM advisory
  (b) a deterministic KILL fires immediately regardless of LLM latency/availability
  (c) a slow/hanging LLM does not delay the deterministic verdict
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from datetime import datetime, timezone

from suy_sideguy.warden import (
    ActionType,
    AgentAction,
    LLMJudge,
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


def _warden() -> Warden:
    return Warden(scope_path=_scope_file(), agent_pid=os.getpid(),
                  poll_interval=0.01)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exec(cmd: str) -> AgentAction:
    return AgentAction(timestamp=_now_iso(),
                       action_type=ActionType.PROCESS_EXEC, target=cmd)


def _netout(target: str = "8.8.8.8:443") -> AgentAction:
    return AgentAction(
        timestamp=_now_iso(), action_type=ActionType.NETWORK_OUT, target=target,
        details={"remote_ip": target.split(":")[0], "remote_port": 443},
    )


# ── httpx test double: makes the model return whatever verdict we choose ──────
class _FakeResp:
    status_code = 200

    def __init__(self, content: str):
        self._content = content

    def json(self):
        return {"message": {"content": self._content}}


class _FakeClient:
    """Async-context-manager stand-in for httpx.AsyncClient."""

    def __init__(self, content: str, *a, **k):
        self._content = content

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        return _FakeResp(self._content)


# ══════════════════════════════════════════════════════════════════════════
# Property 1 — the LLM can never KILL/suspend
# ══════════════════════════════════════════════════════════════════════════

def test_coerce_advisory_verdict_caps_at_safe_or_flag():
    # KILL/HALT/garbage all collapse to FLAG; only SAFE survives as SAFE.
    assert LLMJudge._coerce_advisory_verdict("KILL") == Verdict.FLAG
    assert LLMJudge._coerce_advisory_verdict("HALT") == Verdict.FLAG
    assert LLMJudge._coerce_advisory_verdict(" kill ") == Verdict.FLAG
    assert LLMJudge._coerce_advisory_verdict("BOGUS") == Verdict.FLAG
    assert LLMJudge._coerce_advisory_verdict("FLAG") == Verdict.FLAG
    assert LLMJudge._coerce_advisory_verdict("SAFE") == Verdict.SAFE


def test_llm_prompt_and_schema_do_not_offer_kill():
    # The model is never even told it may KILL — enforcement is not its lane.
    assert "KILL" not in LLMJudge.SYSTEM_PROMPT


def test_llm_evaluate_returning_kill_is_coerced_to_flag(monkeypatch):
    """(a) — Even when the model literally returns verdict "KILL", the judge
    yields FLAG. The LLM cannot produce an enforcement verdict."""
    judge = LLMJudge()
    content = json.dumps(
        {"verdict": "KILL", "reason": "model tried to kill", "confidence": 0.99}
    )
    monkeypatch.setattr(
        "suy_sideguy.warden.httpx.AsyncClient",
        lambda *a, **k: _FakeClient(content),
    )
    v = asyncio.run(judge.evaluate(_netout(), "scope-summary"))
    assert v.verdict == Verdict.FLAG
    assert v.verdict != Verdict.KILL
    assert v.evaluator == "llm_judge"  # advisory, not an enforcement verdict


def test_advisory_kill_verdict_never_kills_or_suspends(monkeypatch):
    """(a) — Applying an advisory verdict that (adversarially) carries KILL must
    NOT kill or suspend the agent; it is recorded as a coerced FLAG posture bump
    and nothing more. _apply_advisory has no path to the killswitch."""
    w = _warden()

    def _boom(*a, **k):
        raise AssertionError("advisory path must NEVER call the killswitch")

    monkeypatch.setattr(w.killswitch, "kill_agent", _boom)
    monkeypatch.setattr(w.killswitch, "suspend_agent", _boom)

    kill_labeled = WardenVerdict(
        verdict=Verdict.KILL, reason="model claims exfil",
        action=_netout(), evaluator="llm_judge",
    )
    w._apply_advisory(kill_labeled)

    assert w.killed is False
    assert w.suspended is False
    assert len(w.advisories) == 1
    assert w.advisories[0]["advisory_verdict"] == "FLAG"  # coerced down


# ══════════════════════════════════════════════════════════════════════════
# Property 2 — the LLM never blocks real-time enforcement
# ══════════════════════════════════════════════════════════════════════════

def test_deterministic_kill_fires_immediately_despite_slow_llm():
    """(b) — A deterministic KILL (rm -rf on a protected root) returns instantly
    even with the judge 'available' and pathologically slow. The kill path never
    touches the judge, so no advisory task is even dispatched."""
    w = _warden()
    w.judge.available = True

    async def _hang(*a, **k):
        await asyncio.sleep(30)
        return WardenVerdict(Verdict.SAFE, "too late", _netout(), "llm_judge")

    w.judge.evaluate = _hang  # type: ignore[assignment]

    start = time.monotonic()
    v = asyncio.run(w.evaluate_action(_exec("rm -rf /")))
    elapsed = time.monotonic() - start

    assert v.verdict == Verdict.KILL
    assert v.evaluator == "rule_engine"
    assert elapsed < 0.5, f"deterministic KILL blocked on LLM ({elapsed:.2f}s)"
    assert not w._advisory_tasks  # KILL path dispatches no advisory


def test_deterministic_kill_fires_when_llm_unavailable():
    """(b) — same guarantee when the LLM is simply unavailable."""
    w = _warden()
    w.judge.available = False
    v = asyncio.run(w.evaluate_action(_exec("rm -rf /")))
    assert v.verdict == Verdict.KILL
    assert v.evaluator == "rule_engine"


def test_slow_llm_does_not_delay_deterministic_flag():
    """(c) — A FLAG action with a slow/hanging judge returns the deterministic
    FLAG immediately (off-hot-path advisory). The model is still dispatched
    (fire-and-forget) but never awaited by evaluate_action, and even if it later
    resolved to KILL it could not override the returned verdict."""
    w = _warden()
    w.judge.available = True

    async def _slow(*a, **k):
        await asyncio.sleep(30)
        return WardenVerdict(Verdict.KILL, "model says kill", _netout(), "llm_judge")

    w.judge.evaluate = _slow  # type: ignore[assignment]

    async def _drive():
        action = _exec("unknowncmd --x")  # unknown command -> deterministic FLAG
        start = time.monotonic()
        verdict = await w.evaluate_action(action)
        elapsed = time.monotonic() - start
        n_dispatched = len(w._advisory_tasks)
        # Cancel the fire-and-forget task so the loop closes cleanly.
        for t in list(w._advisory_tasks):
            t.cancel()
        return verdict, elapsed, n_dispatched

    verdict, elapsed, n_dispatched = asyncio.run(_drive())

    assert verdict.verdict == Verdict.FLAG
    assert verdict.verdict != Verdict.KILL
    assert verdict.evaluator == "rule_engine"
    assert elapsed < 0.5, f"deterministic FLAG blocked on LLM ({elapsed:.2f}s)"
    assert n_dispatched == 1, "advisory judge should run off the hot path"
