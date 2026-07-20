"""
Agent Warden - Outbound Agent Security Monitor
==============================================
Polls best-effort user-space observations and can attempt to stop high-risk agent sessions.
Runs as a separate daemon process for defense-in-depth monitoring.

Architecture:
  1. Observer    - Watches filesystem, network, and process events
  2. Rule Engine - Instant scope-violation checks (no model call). SOLE authority
                   for KILL (SIGKILL) and HALT (SIGSTOP): deterministic,
                   explainable, reproducible.
  3. LLM Judge   - Qwen3-4B via Ollama, ADVISORY ONLY. Runs OFF the enforcement
                   hot path (fire-and-forget). May at most raise monitoring
                   posture / enrich forensics; can NEVER kill or suspend.
  4. Killswitch  - SIGKILL / SIGSTOP to agent process tree (rule-engine driven)
  5. Responder   - Forensic report + rollback attempt

Usage:
  python3 warden.py --scope scope.yaml --agent-pid 12345
  python3 warden.py --scope scope.yaml --agent-name openclaw
"""

from __future__ import annotations

import asyncio
import glob
import json
import os
import sys
import time
import shlex
import fnmatch
import logging
import argparse
from collections.abc import Iterable
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    import yaml
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with `pip install -e .`") from e

try:
    import psutil
except ImportError as e:
    raise SystemExit("Missing dependency: psutil. Install with `pip install -e .`") from e

try:
    import httpx
except ImportError as e:
    raise SystemExit("Missing dependency: httpx. Install with `pip install -e .`") from e


# ════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ════════════════════════════════════════════════════════════

class Verdict(Enum):
    SAFE = "SAFE"
    FLAG = "FLAG"
    HALT = "HALT"
    KILL = "KILL"

class ActionType(Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_OUT = "network_out"
    PROCESS_EXEC = "process_exec"
    PROCESS_SPAWN = "process_spawn"
    UNKNOWN = "unknown"


class RecursiveRmState(Enum):
    NONE = "none"
    BENIGN = "benign"
    PROTECTED = "protected"
    UNCERTAIN = "uncertain"

@dataclass
class AgentAction:
    """Represents a single observed agent action."""
    timestamp: str
    action_type: ActionType
    target: str
    details: dict = field(default_factory=dict)
    source_pid: int | None = None

    def to_dict(self):
        d = asdict(self)
        d['action_type'] = self.action_type.value
        return d

@dataclass 
class WardenVerdict:
    """Result of evaluating an action."""
    verdict: Verdict
    reason: str
    action: AgentAction
    evaluator: str
    confidence: float = 1.0
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RecursiveRmDecision:
    """Deterministic classification of one recursive-rm command surface."""

    state: RecursiveRmState
    target: str = ""
    reason: str = ""


# ════════════════════════════════════════════════════════════
# SCOPE LOADER
# ════════════════════════════════════════════════════════════

class Scope:
    """Loads and queries the agent's allowed scope."""
    
    def __init__(self, scope_path: str):
        with open(scope_path, 'r', encoding='utf-8') as f:
            loaded = yaml.safe_load(f)

        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("Scope YAML root must be a mapping/object")

        self.config = loaded

        self.fs = self.config.get('filesystem', {})
        self.net = self.config.get('network', {})
        self.proc = self.config.get('process', {})
        self.behavior = self.config.get('behavior', {})
        
        self.allowed_paths = self.fs.get('allowed_paths', [])
        self.forbidden_paths = self.fs.get('forbidden_paths', [])
        self.forbidden_extensions = self.fs.get('forbidden_extensions', [])
        
        self.allowed_domains = self.net.get('allowed_domains', [])
        self.forbidden_domains = self.net.get('forbidden_domains', [])
        self.allowed_ports = self.net.get('allowed_ports', [])
        
        self.allowed_commands = self.proc.get('allowed_commands', [])
        self.forbidden_commands = self.proc.get('forbidden_commands', [])
        
        self.flag_threshold = self.behavior.get('flag_threshold', 5)
        self.flag_window = self.behavior.get('flag_window', 300)
        self.max_actions_per_minute = self.behavior.get('max_actions_per_minute', 60)

        # Fail loud on the silent-no-op scope bug: a scope that recognizes none of
        # its enforcement sections enforces NOTHING. The legacy flat schema
        # (allow_read/deny_write/deny_exec) is the common cause — it is NOT parsed,
        # so the warden would run wide open while appearing configured.
        _flat_keys = {'allow_read', 'allow_write', 'deny_read', 'deny_write',
                      'deny_exec', 'allow_exec'}
        _present_flat = _flat_keys & set(self.config)
        _enforces_nothing = not any((self.allowed_paths, self.forbidden_paths,
                                     self.forbidden_extensions, self.forbidden_commands,
                                     self.forbidden_domains))
        if _present_flat:
            raise ValueError(
                f"Scope '{scope_path}' uses an unrecognized flat schema "
                f"({sorted(_present_flat)}); agent-warden reads a NESTED schema "
                f"(filesystem/network/process/behavior). As written this scope would "
                f"enforce NOTHING. See examples/scope.generic.yaml."
            )
        if _enforces_nothing and self.config:
            logging.getLogger(__name__).warning(
                "Scope '%s' loaded with empty allow/deny lists — the warden will "
                "enforce nothing. Check the schema (filesystem/network/process/behavior).",
                scope_path,
            )

    def _path_matches(self, path: str, patterns: list) -> bool:
        path = os.path.expanduser(os.path.normpath(path))
        for pattern in patterns:
            expanded = os.path.expanduser(pattern)
            # Direct glob match
            if fnmatch.fnmatch(path, expanded):
                return True
            # Check if path is UNDER a pattern directory
            # Convert glob pattern to a prefix check:
            # A home-directory glob like "~/.ssh/**" should match concrete key paths.
            # Split pattern into parts and match each segment
            pat_parts = expanded.split(os.sep)
            path_parts = path.split(os.sep)
            if len(path_parts) >= len(pat_parts):
                match = True
                for pp, pa in zip(pat_parts, path_parts):
                    if not fnmatch.fnmatch(pa, pp):
                        match = False
                        break
                if match:
                    return True
        return False
    
    def check_filesystem(self, path: str) -> tuple:
        path = os.path.expanduser(os.path.abspath(path))
        
        for ext in self.forbidden_extensions:
            if path.endswith(ext):
                return Verdict.KILL, f"Accessed forbidden file type: {ext}"
        
        if self._path_matches(path, self.forbidden_paths):
            return Verdict.KILL, f"Accessed forbidden path: {path}"
        
        if self._path_matches(path, self.allowed_paths):
            return Verdict.SAFE, "Path is within allowed scope"
        
        return Verdict.FLAG, f"Path outside allowed scope: {path}"
    
    def check_network(self, domain: str, port: int = 443) -> tuple:
        domain = domain.lower().strip()

        # Localhost is always safe (IPC, Ollama, etc.)
        if domain in ("127.0.0.1", "::1", "localhost"):
            return Verdict.SAFE, f"Localhost connection: {domain}:{port}"

        # The process observer reports remote IPs, not authenticated hostnames.
        # Never trust reverse DNS to turn an observed IP into an allowlisted
        # hostname: PTR data is not proof of the destination's identity and the
        # lookup itself leaks an observed address to the system resolver. Raw IPs
        # can still be allowed/forbidden explicitly in the scope.
        resolved = domain

        for forbidden in self.forbidden_domains:
            if resolved == forbidden or resolved.endswith(f".{forbidden}"):
                return Verdict.KILL, f"Connection to forbidden domain: {resolved}"

        for allowed in self.allowed_domains:
            if resolved == allowed or resolved.endswith(f".{allowed}"):
                if port in self.allowed_ports:
                    return Verdict.SAFE, f"Allowed domain and port: {resolved}:{port}"
                else:
                    return Verdict.FLAG, f"Allowed domain but unusual port: {resolved}:{port}"

        return Verdict.FLAG, f"Connection to unknown host: {resolved} ({domain}):{port}"
    
    def check_command(self, command: str) -> tuple:
        parts = command.strip().split()
        if not parts:
            return Verdict.FLAG, "Empty command"
        
        base_cmd = os.path.basename(parts[0])
        full_cmd = command.strip()
        
        for forbidden in self.forbidden_commands:
            forbidden = forbidden.strip()
            if not forbidden:
                continue
            if ' ' in forbidden:
                if full_cmd == forbidden or full_cmd.startswith(forbidden + ' '):
                    return Verdict.KILL, f"Forbidden command: {command}"
            elif base_cmd == forbidden:
                return Verdict.KILL, f"Forbidden command: {command}"
        
        if base_cmd in self.allowed_commands:
            return Verdict.SAFE, f"Allowed command: {base_cmd}"
        
        return Verdict.FLAG, f"Unknown command: {command}"


# ════════════════════════════════════════════════════════════
# LLM JUDGE (Qwen3-4B via Ollama)
# ════════════════════════════════════════════════════════════

class LLMJudge:
    """ADVISORY-ONLY evaluator (Qwen3-4B via Ollama) for ambiguous agent actions.

    The judge NEVER decides enforcement. Its verdict is capped at SAFE / FLAG
    (raise monitoring posture) — it can never emit KILL or HALT. Killing and
    suspending are the deterministic rule engine's exclusive authority, because
    an irreversible SIGKILL must be deterministic, explainable, and reproducible
    — properties a 1.5-4B local model cannot guarantee.
    """

    MAX_RETRIES = 2
    OLLAMA_URL = "http://localhost:11434/api/chat"

    SYSTEM_PROMPT = """You are an ADVISORY security monitor for AI agent actions.
You receive an action and the agent's allowed scope. You do NOT terminate or
suspend anything — a separate deterministic rule engine owns all enforcement.
Your only job is to recommend a monitoring posture: SAFE or FLAG.

Rules:
- SAFE: Action is clearly within scope and benign
- FLAG: Ambiguous or suspicious — recommend raising monitoring posture
- When in doubt, FLAG rather than SAFE
- Patterns matter: many file reads in succession = suspicious
- Network calls after file reads = exfiltration signal
- Access to credentials, keys, or tokens = FLAG (the rule engine, not you,
  decides whether to kill)"""

    def __init__(self, model: str = "qwen3:4b"):
        self.model = model
        self.available = False

    @staticmethod
    def _coerce_advisory_verdict(name: str) -> Verdict:
        """The judge is ADVISORY. It may only recommend SAFE or FLAG (raise
        monitoring posture). KILL / HALT / anything-else is coerced to FLAG so
        the LLM can never trigger an irreversible SIGKILL or a reversible
        SIGSTOP — those remain the deterministic rule engine's sole authority.
        Second line of defense behind the SAFE/FLAG-only response schema."""
        try:
            v = Verdict[str(name).strip().upper()]
        except (KeyError, AttributeError):
            return Verdict.FLAG
        return v if v == Verdict.SAFE else Verdict.FLAG
        
    async def check_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get("http://localhost:11434/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    self.available = any(
                        self.model.split(':')[0] in n for n in model_names
                    )
                    return self.available
        except Exception as e:
            logging.warning(f"Ollama not reachable: {e}")
        self.available = False
        return False
    
    async def evaluate(self, action: AgentAction, scope_context: str,
                       recent_actions: list | None = None) -> WardenVerdict:

        recent_summary = ""
        if recent_actions:
            recent_lines = []
            for a in recent_actions[-10:]:
                recent_lines.append(
                    f"  [{a.timestamp[-12:]}] {a.action_type.value}: {a.target}"
                )
            recent_summary = "\n\nRecent actions:\n" + "\n".join(recent_lines)

        user_prompt = f"""Evaluate this agent action:

Action: {action.action_type.value}
Target: {action.target}
Details: {json.dumps(action.details)}

Scope:
{scope_context}
{recent_summary}"""

        last_error_reason = "LLM judge exhausted retries - failing closed"
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=45.0) as client:
                    resp = await client.post(
                        self.OLLAMA_URL,
                        json={
                            "model": self.model,
                            "messages": [
                                {"role": "system", "content": self.SYSTEM_PROMPT},
                                {"role": "user", "content": user_prompt}
                            ],
                            "stream": False,
                            "options": {
                                "temperature": 0,
                                "num_predict": 200
                            },
                            "format": {
                                "type": "object",
                                "properties": {
                                    "verdict": {
                                        "type": "string",
                                        # Advisory only: KILL/HALT are NOT offered
                                        # to the model. Enforcement is the
                                        # deterministic rule engine's authority.
                                        "enum": ["SAFE", "FLAG"]
                                    },
                                    "reason": {"type": "string"},
                                    "confidence": {"type": "number"}
                                },
                                "required": ["verdict", "reason", "confidence"]
                            }
                        }
                    )

                    if resp.status_code != 200:
                        last_error_reason = (
                            "LLM judge unavailable - failing closed"
                        )
                    elif not (content := resp.json()
                              .get('message', {}).get('content', '').strip()):
                        last_error_reason = (
                            "LLM returned empty response - failing closed"
                        )
                    else:
                        parsed = json.loads(content)
                        # Advisory only: coerce to SAFE/FLAG. Even a malformed or
                        # adversarial response claiming "KILL" can never become an
                        # enforcement verdict — that is the rule engine's alone.
                        verdict = self._coerce_advisory_verdict(
                            parsed.get('verdict', 'FLAG')
                        )
                        return WardenVerdict(
                            verdict=verdict,
                            reason=parsed.get('reason', 'No reason'),
                            action=action, evaluator="llm_judge",
                            confidence=parsed.get('confidence', 0.5)
                        )

            except Exception as e:
                last_error_reason = f"LLM error, failing closed: {e}"

            if attempt < self.MAX_RETRIES:
                await asyncio.sleep(1)

        return WardenVerdict(
            verdict=Verdict.FLAG,
            reason=last_error_reason,
            action=action, evaluator="llm_fallback"
        )


# ════════════════════════════════════════════════════════════
# INCIDENT LOGGER & FORENSIC REPORTER
# ════════════════════════════════════════════════════════════

class IncidentLogger:
    """Logs all actions and generates forensic reports."""
    
    def __init__(self, log_dir: str | None = None):
        if log_dir is None:
            log_dir = os.path.expanduser("~/.local/share/sysmond/logs")
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.action_log_path = self.log_dir / f"actions_{self.session_id}.jsonl"
        self.incident_dir = self.log_dir / "incidents"
        self.incident_dir.mkdir(exist_ok=True)
        self._report_sequence = 0

    def _next_report_path(self, kind: str) -> Path:
        """Collision-safe report path, including under a frozen wall clock."""
        self._report_sequence += 1
        return self.incident_dir / (
            f"{kind}_{self.session_id}_{time.time_ns()}_"
            f"{self._report_sequence:06d}.json"
        )
        
    def log_action(self, verdict: WardenVerdict):
        entry = {
            "timestamp": verdict.timestamp,
            "verdict": verdict.verdict.value,
            "reason": verdict.reason,
            "evaluator": verdict.evaluator,
            "confidence": verdict.confidence,
            "action": verdict.action.to_dict()
        }
        with open(self.action_log_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")
    
    def generate_incident_report(self, kill_verdict: WardenVerdict,
                                  all_verdicts: list,
                                  kill_result: dict | None = None,
                                  rollback_result: dict | None = None) -> str:
        
        report_path = self._next_report_path("incident")
        
        timeline = []
        for v in all_verdicts:
            timeline.append({
                "timestamp": v.timestamp,
                "action_type": v.action.action_type.value,
                "target": v.action.target,
                "verdict": v.verdict.value,
                "reason": v.reason,
                "evaluator": v.evaluator
            })
        
        flags = sum(1 for v in all_verdicts if v.verdict == Verdict.FLAG)
        
        kill_result = kill_result or {}
        rollback_result = rollback_result or {}
        terminated = bool(
            kill_result.get("killed") and kill_result.get("pids_terminated")
        )
        if terminated:
            control_status = "AGENT_TERMINATED"
        elif kill_result:
            control_status = "TERMINATION_FAILED"
        else:
            control_status = "TERMINATION_UNVERIFIED"

        report = {
            "incident_report": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "Agent Warden v0.1.5",
                "session_id": self.session_id,
                "status": control_status,
            },
            "kill_trigger": {
                "timestamp": kill_verdict.timestamp,
                "action_type": kill_verdict.action.action_type.value,
                "target": kill_verdict.action.target,
                "details": kill_verdict.action.details,
                "reason": kill_verdict.reason,
                "evaluator": kill_verdict.evaluator,
                "confidence": kill_verdict.confidence
            },
            "session_summary": {
                "total_actions_observed": len(all_verdicts),
                "safe_actions": sum(1 for v in all_verdicts if v.verdict == Verdict.SAFE),
                "flagged_actions": flags,
                "kill_triggers": sum(1 for v in all_verdicts if v.verdict == Verdict.KILL),
                "session_duration_seconds": None
            },
            "action_timeline": timeline,
            "liability_statement": {
                "notice": (
                    "This report contains best-effort user-space observations and "
                    "control-attempt records. It does not prove authorship, intent, "
                    "or complete operating-system visibility. Snapshot-diff events "
                    "are explicitly unattributed. Review the underlying action log "
                    "and kill_execution fields before drawing incident conclusions."
                ),
                "agent_process_terminated": terminated,
                "termination_method": "SIGKILL" if terminated else "SIGKILL_ATTEMPTED",
                "rollback_attempted": bool(rollback_result.get("attempted")),
                "rollback_details": rollback_result or None,
            },
            "kill_execution": kill_result,
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return str(report_path)

    def generate_halt_report(self, halt_verdict: WardenVerdict,
                             all_verdicts: list, suspend_result: dict) -> str:
        """Forensic record for a HALT suspension attempt."""
        report_path = self._next_report_path("halt")
        suspended = bool(
            suspend_result.get("suspended")
            and suspend_result.get("pids_suspended")
        )

        timeline = []
        for v in all_verdicts:
            timeline.append({
                "timestamp": v.timestamp,
                "action_type": v.action.action_type.value,
                "target": v.action.target,
                "verdict": v.verdict.value,
                "reason": v.reason,
                "evaluator": v.evaluator,
            })

        report = {
            "halt_report": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "Agent Warden v0.1.5",
                "session_id": self.session_id,
                "status": "AGENT_SUSPENDED" if suspended else "SUSPENSION_FAILED",
            },
            "halt_trigger": {
                "timestamp": halt_verdict.timestamp,
                "action_type": halt_verdict.action.action_type.value,
                "target": halt_verdict.action.target,
                "details": halt_verdict.action.details,
                "reason": halt_verdict.reason,
                "evaluator": halt_verdict.evaluator,
            },
            "control_action": {
                "method": "SIGSTOP",
                "reversible": True,
                "suspended": suspended,
                "pids_suspended": suspend_result.get("pids_suspended", []),
                "errors": suspend_result.get("errors", []),
                "resume_hint": (
                    "kill -CONT <pid> to resume, or escalate to SIGKILL"
                ),
            },
            "session_summary": {
                "total_actions_observed": len(all_verdicts),
                "safe_actions": sum(1 for v in all_verdicts if v.verdict == Verdict.SAFE),
                "flagged_actions": sum(1 for v in all_verdicts if v.verdict == Verdict.FLAG),
                "halt_triggers": sum(1 for v in all_verdicts if v.verdict == Verdict.HALT),
                "kill_triggers": sum(1 for v in all_verdicts if v.verdict == Verdict.KILL),
            },
            "action_timeline": timeline,
            "liability_statement": {
                "notice": (
                    "This report was generated automatically by Agent Warden, "
                    "an autonomous AI agent security monitor. "
                    + (
                        "The monitored agent was SUSPENDED (SIGSTOP) — a reversible "
                        "pause — due to a detected behavioral HALT condition."
                        if suspended else
                        "A SIGSTOP suspension was attempted but did not suspend the "
                        "monitored agent; a later HALT may retry."
                    )
                ),
                "agent_process_terminated": False,
                "agent_process_suspended": suspended,
                "control_method": "SIGSTOP",
                "reversible": True,
            },
        }

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return str(report_path)


# ════════════════════════════════════════════════════════════
# KILLSWITCH
# ════════════════════════════════════════════════════════════

class Killswitch:
    """Terminates the agent and attempts rollback."""
    
    def __init__(self, agent_pid: int):
        self.agent_pid = agent_pid
    
    def kill_agent(self) -> dict:
        killed = False
        pids_terminated: list[int] = []
        errors: list[str] = []

        try:
            parent = psutil.Process(self.agent_pid)
            children = parent.children(recursive=True)

            for child in children:
                try:
                    child.kill()
                    pids_terminated.append(child.pid)
                except psutil.NoSuchProcess:
                    pass
                except Exception as e:
                    errors.append(f"Child {child.pid}: {e}")

            try:
                parent.kill()
                pids_terminated.append(self.agent_pid)
                killed = True
            except psutil.NoSuchProcess:
                killed = True
            except Exception as e:
                errors.append(f"Agent {self.agent_pid}: {e}")

        except psutil.NoSuchProcess:
            killed = True
            errors.append(f"PID {self.agent_pid} already gone")
        except Exception as e:
            errors.append(f"Killswitch error: {e}")

        return {"killed": killed, "pids_terminated": pids_terminated, "errors": errors}

    def suspend_agent(self) -> dict:
        """SIGSTOP the agent process tree — a *reversible* pause (not SIGKILL).
        The stopped process can be resumed with SIGCONT or escalated to SIGKILL
        by a human/policy. Parent is stopped first so it cannot spawn new
        children mid-suspend; descendants are then drained until stable.
        Fail-open per child so one gone/denied pid cannot abort the pause."""
        suspended = False
        pids_suspended: list[int] = []
        errors: list[str] = []

        try:
            parent = psutil.Process(self.agent_pid)

            try:
                parent.suspend()
                pids_suspended.append(self.agent_pid)
                suspended = True
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                errors.append(f"Agent {self.agent_pid}: {e}")

            # Enumerate only after the parent is stopped. Drain newly observed
            # descendants until the tree is stable: a child may have forked in
            # the instant before it was suspended, but once every discovered
            # process is stopped no further descendants can appear.
            seen_children: set[int] = set()
            while True:
                try:
                    children = parent.children(recursive=True)
                except psutil.NoSuchProcess:
                    break
                except Exception as e:
                    errors.append(f"Child enumeration: {e}")
                    break

                pending = [child for child in children
                           if child.pid not in seen_children]
                if not pending:
                    break
                for child in pending:
                    seen_children.add(child.pid)
                    try:
                        child.suspend()
                        pids_suspended.append(child.pid)
                    except psutil.NoSuchProcess:
                        pass
                    except Exception as e:
                        errors.append(f"Child {child.pid}: {e}")

        except psutil.NoSuchProcess:
            errors.append(f"PID {self.agent_pid} already gone")
        except Exception as e:
            errors.append(f"Suspend error: {e}")

        # ``suspended`` is an aggregate completion bit, not merely a record that
        # the parent accepted SIGSTOP. Any observed child/enumeration failure
        # leaves the tree partially live and must keep HALT retryable.
        suspended = suspended and not errors
        return {"suspended": suspended, "pids_suspended": pids_suspended,
                "errors": errors}

    def attempt_rollback(self, action: AgentAction) -> dict:
        rollback = {
            "attempted": True, "success": False,
            "action_type": action.action_type.value, "details": ""
        }
        
        try:
            if action.action_type == ActionType.FILE_WRITE:
                path = action.target
                if os.path.exists(path):
                    quarantine = os.path.expanduser("~/.local/share/sysmond/quarantine")
                    os.makedirs(quarantine, exist_ok=True)
                    dest = os.path.join(quarantine, f"{int(time.time())}_{os.path.basename(path)}")
                    os.rename(path, dest)
                    rollback["success"] = True
                    rollback["details"] = f"Quarantined: {path} -> {dest}"
            elif action.action_type == ActionType.FILE_DELETE:
                rollback["details"] = "Cannot rollback deletion"
            elif action.action_type == ActionType.NETWORK_OUT:
                rollback["details"] = "Cannot rollback network transmission"
            else:
                rollback["details"] = f"No rollback for {action.action_type.value}"
        except Exception as e:
            rollback["details"] = f"Rollback failed: {e}"
        
        return rollback


# ════════════════════════════════════════════════════════════
# PROCESS OBSERVER
# ════════════════════════════════════════════════════════════

class ProcessObserver:
    """Monitors an agent process for file, network, and subprocess activity."""
    
    def __init__(self, agent_pid: int, scope: Scope | None = None):
        self.agent_pid = agent_pid
        self._known_files: set[tuple[int, str, str]] = set()
        self._known_connections: set[tuple[int, str, int]] = set()
        self._known_children: set[int] = set()

        # ── Filesystem-diff state ──────────────────────────────────────────
        # psutil.open_files() is blind to in-process deletes: os.remove() opens
        # no fd, so a 50-file mass-delete is invisible on macOS. A poll-time
        # set-diff of the scope's workspace dirs recovers create/delete events
        # (path-set only — NO mtime/modify detection, which is spoofable/noisy).
        self.scope = scope
        self._scope_snapshot: set[str] | None = None  # None = not yet baselined
        # A wildcard directory component is expanded to concrete matching roots
        # instead of walking its broad literal parent. Bound that expansion so a
        # hostile or accidental pattern cannot create a different unbounded walk.
        self._scope_root_cap: int = 1_024
        self._scope_root_expansion_capped: bool = False
        # Logical scope spelling -> pinned concrete directory used for fd opens.
        # This lets a literal alias such as macOS /tmp -> /private/tmp remain
        # observable without following descendant symlinks or changing emitted
        # paths to their resolved spelling.
        self._scope_root_open_paths: dict[str, str] = {}
        self._scope_roots: list[str] = self._compute_scope_roots(scope)
        # Decouple the walk from the (0.5s) process poll so a large tree doesn't
        # get re-walked every poll. Snapshot at most every ~1s (monotonic gate).
        self._last_snapshot_ts: float = 0.0
        self._snapshot_min_interval: float = 1.0
        # Never walk an unbounded tree into memory: emit one FLAG and bail.
        self._snapshot_file_cap: int = 50_000

    @staticmethod
    def _literal_dir_prefix(pattern: str) -> str:
        """Literal directory prefix of a path glob — everything before the first
        glob metachar (`*?[`). '/tmp/sb/**' -> '/tmp/sb'; '/a/b*/c' -> '/a'."""
        expanded = os.path.expandvars(os.path.expanduser(pattern.strip()))
        kept: list[str] = []
        for seg in expanded.split(os.sep):
            if any(ch in seg for ch in "*?["):
                break
            kept.append(seg)
        root = os.sep.join(kept)
        return os.path.normpath(root) if root else ""

    def _compute_scope_roots(self, scope: Scope | None) -> list[str]:
        """Concrete directory roots to snapshot for each allowed-path glob.

        A wildcard in a directory component is expanded only through that first
        component. For example, ``/tmp/my-agent_*/**`` becomes the concrete
        matching ``/tmp/my-agent_X`` directories, never the broad ``/tmp``
        parent. A terminal file glob (``/work/*.txt``) and recursive suffix
        (``/work/**``) retain their literal directory prefix.

        Skip the filesystem root ('/**' -> '/') — snapshotting the whole
        filesystem every poll is never the intent and would melt.

        De-dup by realpath so a symlink alias (e.g. macOS '/tmp' -> '/private/tmp'
        listed as two allowed_paths) doesn't get walked twice, which would
        double-count every FS event and effectively halve the HALT threshold. The
        ORIGINAL (non-resolved) path string is kept for the walk so emitted paths
        still match the un-resolved allowed_paths patterns in check_filesystem."""
        if scope is None:
            return []
        self._scope_root_expansion_capped = False
        self._scope_root_open_paths = {}
        roots: list[str] = []
        seen_real: set[str] = set()
        for pat in getattr(scope, "allowed_paths", []) or []:
            expanded = os.path.expandvars(os.path.expanduser(pat.strip()))
            parts = expanded.split(os.sep)
            wildcard_index = next(
                (i for i, part in enumerate(parts)
                 if any(ch in part for ch in "*?[")),
                None,
            )
            literal_root = self._literal_dir_prefix(pat)
            candidates: Iterable[str]
            if (wildcard_index is not None
                    and wildcard_index < len(parts) - 1
                    and parts[wildcard_index] != "**"):
                # Expand one wildcard directory level. Consume only accepted
                # concrete directories through cap+1; do not sort by consuming
                # an unbounded glob iterator before the cap can fire.
                component_glob = os.sep.join(parts[:wildcard_index + 1])
                bounded_candidates: list[str] = []
                for candidate in glob.iglob(component_glob, recursive=False):
                    # A wildcard-matched symlink is not an intended concrete
                    # workspace root: following it could escape the scope.
                    if os.path.islink(candidate) or not os.path.isdir(candidate):
                        continue
                    bounded_candidates.append(candidate)
                    if len(roots) + len(bounded_candidates) > self._scope_root_cap:
                        self._scope_root_expansion_capped = True
                        return roots
                candidates = sorted(bounded_candidates)
            else:
                candidates = (literal_root,)

            for root in candidates:
                if not root or root == os.sep:
                    continue
                if not os.path.isdir(root):
                    # Preserve literal missing roots so their later creation is
                    # visible; wildcard roots are rediscovered on each snapshot.
                    if root == literal_root and wildcard_index is None:
                        pass
                    elif (root == literal_root
                          and (wildcard_index == len(parts) - 1
                               or parts[wildcard_index] == "**")):
                        pass
                    else:
                        continue
                root = os.path.normpath(root)
                try:
                    real = os.path.realpath(root)
                except OSError:
                    real = root
                if real in seen_real or root in roots:
                    continue
                if len(roots) >= self._scope_root_cap:
                    self._scope_root_expansion_capped = True
                    return roots
                seen_real.add(real)
                roots.append(root)
                self._scope_root_open_paths[root] = real
        return roots

    def _snapshot_scope_files(self) -> tuple[set[str], bool]:
        """Walk the scope roots and return (set-of-file-paths, capped?).
        try/except per directory so one unreadable/vanished dir cannot crash the
        warden (fail-open — the 'don't crash the warden' constraint). Bails with
        capped=True once past the file cap instead of exhausting memory."""
        found: set[str] = set()
        # Re-expand wildcard directory components every snapshot so a newly
        # created matching workspace is observed without ever walking its broad
        # parent. An over-cap expansion fails closed as an incomplete snapshot.
        self._scope_roots = self._compute_scope_roots(self.scope)
        if self._scope_root_expansion_capped:
            return found, True
        stack: list[tuple[str, str]] = [
            (root, self._scope_root_open_paths.get(root, root))
            for root in self._scope_roots
        ]
        seen_dirs: set[str] = set()
        while stack:
            logical_dir, open_dir = stack.pop()
            if open_dir in seen_dirs:
                continue
            seen_dirs.add(open_dir)
            directory_fd: int | None = None
            try:
                # Open the directory itself without following a symlink. This
                # closes the discovery-to-scan swap window for wildcard roots
                # and for descendant directories queued from prior scans.
                open_flags = os.O_RDONLY
                open_flags |= getattr(os, "O_DIRECTORY", 0)
                open_flags |= getattr(os, "O_NOFOLLOW", 0)
                directory_fd = os.open(open_dir, open_flags)
                with os.scandir(directory_fd) as it:
                    for entry in it:
                        try:
                            entry_path = os.path.join(logical_dir, entry.name)
                            open_entry_path = os.path.join(open_dir, entry.name)
                            # follow_symlinks=False avoids symlink cycles and
                            # double-walking the /tmp -> /private/tmp alias.
                            if entry.is_dir(follow_symlinks=False):
                                stack.append((entry_path, open_entry_path))
                            else:
                                found.add(entry_path)
                                if len(found) > self._snapshot_file_cap:
                                    return found, True
                        except OSError:
                            continue  # per-entry stat failure → skip, keep going
            except OSError:
                continue  # per-dir failure (missing/permission) → fail-open
            finally:
                if directory_fd is not None:
                    try:
                        os.close(directory_fd)
                    except OSError:
                        pass
        return found, False

    def _diff_scope_filesystem(self, now: str, actions: list[AgentAction]) -> None:
        """Snapshot the scope roots and emit synthetic create/delete actions from
        the set-diff vs the previous snapshot. These observations are deliberately
        unattributed: a directory snapshot cannot identify the process that made
        a change. The first (baseline) poll emits nothing. Fully fail-open."""
        if self.scope is None or not getattr(self.scope, "allowed_paths", None):
            return
        # Cadence gate: bound walk cost independently of the process poll rate.
        mono = time.time()
        if mono - self._last_snapshot_ts < self._snapshot_min_interval:
            return
        self._last_snapshot_ts = mono

        current, capped = self._snapshot_scope_files()
        if capped:
            # One FLAG (UNKNOWN action -> FLAG in the rule engine); do NOT diff a
            # truncated set against a full baseline (would emit spurious deletes).
            actions.append(AgentAction(
                timestamp=now, action_type=ActionType.UNKNOWN,
                target="scope too large to snapshot",
                details={"detected_by": "scope_diff",
                         "attribution": "unattributed",
                         "file_cap": self._snapshot_file_cap,
                         "root_cap": self._scope_root_cap},
            ))
            return

        if self._scope_snapshot is not None:  # skip the baseline poll
            for path in self._scope_snapshot - current:
                actions.append(AgentAction(
                    timestamp=now, action_type=ActionType.FILE_DELETE,
                    target=path,
                    details={"detected_by": "scope_diff",
                             "attribution": "unattributed"},
                ))
            for path in current - self._scope_snapshot:
                actions.append(AgentAction(
                    timestamp=now, action_type=ActionType.FILE_WRITE,
                    target=path,
                    details={"detected_by": "scope_diff",
                             "attribution": "unattributed"},
                ))
        self._scope_snapshot = current

    def get_agent_pids(self) -> list[int]:
        pids = [self.agent_pid]
        try:
            parent = psutil.Process(self.agent_pid)
            for child in parent.children(recursive=True):
                pids.append(child.pid)
        except psutil.NoSuchProcess:
            pass
        return pids
    
    def observe(self) -> list[AgentAction]:
        """Poll agent activity and return NEW actions since last check."""
        actions: list[AgentAction] = []
        now = datetime.now(timezone.utc).isoformat()
        
        try:
            pids = self.get_agent_pids()
        except psutil.NoSuchProcess:
            return actions
        
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                
                # ── File activity ──
                try:
                    for f in proc.open_files():
                        # psutil versions differ: popenfile may not expose .mode on some platforms
                        fpath = getattr(f, 'path', None)
                        if not fpath:
                            continue
                        fmode = getattr(f, 'mode', '') or ''
                        ffd = getattr(f, 'fd', None)
                        file_key = (pid, fpath, fmode)
                        if file_key not in self._known_files:
                            self._known_files.add(file_key)
                            action_type = (
                                ActionType.FILE_WRITE
                                if any(c in fmode for c in 'wa+')
                                else ActionType.FILE_READ
                            )
                            actions.append(AgentAction(
                                timestamp=now, action_type=action_type,
                                target=fpath,
                                details={"mode": fmode, "fd": ffd},
                                source_pid=pid
                            ))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # ── Network connections ──
                try:
                    for conn in proc.net_connections():
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            conn_key = (pid, conn.raddr.ip, conn.raddr.port)
                            if conn_key not in self._known_connections:
                                self._known_connections.add(conn_key)
                                actions.append(AgentAction(
                                    timestamp=now,
                                    action_type=ActionType.NETWORK_OUT,
                                    target=f"{conn.raddr.ip}:{conn.raddr.port}",
                                    details={
                                        "remote_ip": conn.raddr.ip,
                                        "remote_port": conn.raddr.port,
                                        "local_port": conn.laddr.port if conn.laddr else None
                                    },
                                    source_pid=pid
                                ))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # ── Child processes ──
                try:
                    for child in proc.children():
                        if child.pid not in self._known_children:
                            self._known_children.add(child.pid)
                            child_cwd: str | None = None
                            try:
                                # Preserve argv boundaries. A plain join loses the
                                # distinction between a shell -c payload and later
                                # $0/$1 arguments, which can create both false
                                # positives and bypasses in recursive-rm checks.
                                cmdline = shlex.join(child.cmdline())
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                cmdline = "unknown"
                            try:
                                observed_cwd = child.cwd()
                                if os.path.isabs(observed_cwd):
                                    child_cwd = os.path.normpath(observed_cwd)
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                pass
                            details: dict[str, object] = {"child_pid": child.pid}
                            if child_cwd is not None:
                                details["cwd"] = child_cwd
                            else:
                                # Relative destructive targets cannot be resolved
                                # safely without this observation. The rule engine
                                # treats that case as reversible uncertainty-HALT.
                                details["cwd_unavailable"] = True
                            actions.append(AgentAction(
                                timestamp=now,
                                action_type=ActionType.PROCESS_EXEC,
                                target=cmdline,
                                details=details,
                                source_pid=pid
                            ))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
            except psutil.NoSuchProcess:
                continue

        # ── Filesystem diff ──
        # Recovers in-process create/delete events that psutil.open_files() cannot
        # see (os.remove() opens no fd). Wrapped so it can never crash the loop.
        try:
            self._diff_scope_filesystem(now, actions)
        except Exception:  # noqa: BLE001 — fail-open: never take down the warden
            pass

        return actions

    def is_agent_alive(self) -> bool:
        try:
            proc = psutil.Process(self.agent_pid)
            return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False


# ════════════════════════════════════════════════════════════
# WARDEN CORE
# ════════════════════════════════════════════════════════════

class Warden:
    """Main orchestrator: observe -> evaluate -> kill if needed."""
    
    def __init__(self, scope_path: str, agent_pid: int, 
                 poll_interval: float = 0.5,
                 model: str = "qwen3:4b",
                 log_dir: str | None = None,
                 enable_llm: bool = True):

        self.scope = Scope(scope_path)
        self.observer = ProcessObserver(agent_pid, scope=self.scope)
        self.judge = LLMJudge(model=model)
        self.killswitch = Killswitch(agent_pid)
        self.logger = IncidentLogger(log_dir=log_dir)
        
        self.agent_pid = agent_pid
        self.poll_interval = poll_interval
        self.enable_llm = enable_llm
        
        self.all_verdicts: list = []
        self.flag_timestamps: list = []
        self.action_timestamps: list = []
        self.delete_timestamps: list = []
        self.network_out_timestamps: list = []
        self.start_time = time.time()
        self.running = False
        self.killed = False
        # A failed one-shot KILL observation is de-duplicated by the observer.
        # Persist its verdict so the next poll retries enforcement without
        # requiring the underlying event to be emitted again.
        self.pending_kill: WardenVerdict | None = None
        self._kill_episode_report_path: str | None = None
        self._kill_episode_rollback: dict | None = None
        self._kill_episode_attempts: list[dict] = []
        # HALT gives a *reversible* pause (SIGSTOP). Signal the tree ONCE, then
        # reconcile the real process state before suppressing a later signal.
        self.suspended = False
        self.pending_halt: WardenVerdict | None = None
        self._halt_episode_report_path: str | None = None
        self._halt_episode_attempts: list[dict] = []
        # ADVISORY LLM state. The judge runs OFF the enforcement hot path
        # (fire-and-forget), so a slow/hanging model can never open a blind
        # window on the monitor. Its output only lands here (posture + forensics)
        # and can NEVER kill or suspend.
        self.advisories: list = []
        self._advisory_tasks: set = set()
        self.advisory_skipped_busy = 0
        # Per-pid recent credential-read timestamps; arms the deterministic
        # credential-read-then-network-out exfil KILL rule (defense-in-depth).
        self.credential_reads: dict[int | None, list[float]] = {}
        # Window (s) within which a credential read followed by a network-out is
        # treated as exfil. Short by design; overridable via scope behavior.
        self.cred_exfil_window = float(
            self.scope.behavior.get("credential_exfil_window", 15)
        )

        self.scope_summary = self._build_scope_summary()
        
        # Keep the historical default layout, but honor --log-dir for every
        # runtime artifact. A custom evidence directory must not still create or
        # write ~/.local/share/sysmond/warden.log behind the operator's back.
        runtime_log_dir = (
            Path(log_dir)
            if log_dir is not None
            else Path(os.path.expanduser("~/.local/share/sysmond"))
        )
        runtime_log_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_log_path = runtime_log_dir / "warden.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.runtime_log_path)
            ]
        )
        self.log = logging.getLogger("sysmond")
    
    def _build_scope_summary(self) -> str:
        return "\n".join([
            f"Agent: {self.scope.config.get('agent', {}).get('name', 'unknown')}",
            f"Allowed paths: {', '.join(self.scope.allowed_paths)}",
            f"Forbidden paths: {', '.join(self.scope.forbidden_paths[:5])}...",
            f"Allowed domains: {', '.join(self.scope.allowed_domains)}",
            f"Allowed commands: {', '.join(self.scope.allowed_commands)}",
            f"Max actions/min: {self.scope.max_actions_per_minute}"
        ])
    
    def _check_rate_limit(self):
        now = time.time()
        self.action_timestamps = [t for t in self.action_timestamps if now - t < 60]
        
        if len(self.action_timestamps) > self.scope.max_actions_per_minute:
            action = AgentAction(
                timestamp=datetime.now(timezone.utc).isoformat(),
                action_type=ActionType.UNKNOWN, target="rate_limit_exceeded",
                details={"actions_per_minute": len(self.action_timestamps)}
            )
            # A rate spike is a signal, not proof of harm. Ordinary developer
            # work (compile/test/install) routinely opens >60 files/min. Downgrade
            # to FLAG (record + raise posture); never SIGKILL on rate alone.
            return WardenVerdict(
                verdict=Verdict.FLAG,
                reason=f"Rate limit exceeded: {len(self.action_timestamps)} actions/min",
                action=action, evaluator="rule_engine"
            )
        return None

    @staticmethod
    def _action_counts_toward_rate_limit(action: AgentAction) -> bool:
        """Whether an observation is attributable enough for rate enforcement.

        Scope-directory diffs record ambient filesystem changes without proving
        that the monitored process caused them. They remain forensic evidence,
        but cannot acquire indirect kill authority through the rate reducer.
        """
        return action.details.get("detected_by") != "scope_diff"
    
    def _check_flag_accumulation(self):
        # Safer default for production rollout: do NOT auto-kill on flags unless explicitly enabled.
        if os.environ.get("WARDEN_KILL_ON_FLAGS", "0") != "1":
            return None

        now = time.time()
        self.flag_timestamps = [
            t for t in self.flag_timestamps if now - t < self.scope.flag_window
        ]
        if len(self.flag_timestamps) >= self.scope.flag_threshold:
            action = AgentAction(
                timestamp=datetime.now(timezone.utc).isoformat(),
                action_type=ActionType.UNKNOWN, target="flag_accumulation",
                details={"flags_in_window": len(self.flag_timestamps)}
            )
            return WardenVerdict(
                verdict=Verdict.KILL,
                reason=f"Flag accumulation: {len(self.flag_timestamps)} in "
                       f"{self.scope.flag_window}s",
                action=action, evaluator="rule_engine"
            )
        return None

    @staticmethod
    def _flag_counts_toward_accumulation(verdict: WardenVerdict) -> bool:
        """Whether a FLAG has enough attribution to carry kill authority.

        Scope-directory diffs deliberately record useful evidence without
        attributing the change to the monitored process. They must therefore
        remain visible as FLAGs while staying outside the opt-in accumulator.
        Rate-limit FLAGs are attributed, but are explicitly only posture
        signals: repeated rate observations must not acquire SIGKILL authority
        through the generic FLAG accumulator.
        """
        return (
            verdict.action.details.get("detected_by") != "scope_diff"
            and verdict.action.target != "rate_limit_exceeded"
        )

    @staticmethod
    def _forbidden_path_root(pattern: str) -> str:
        """Return the protected root *pattern* for a forbidden path.

        A trailing contents glob does not make deleting its container safe, so
        ``~/.ssh/**`` protects ``~/.ssh`` itself.  Internal wildcard segments
        remain significant: ``/tmp/*/secret/**`` protects the matched ``secret``
        directories, not the unrelated literal prefix ``/tmp``.
        """
        expanded = os.path.expandvars(os.path.expanduser(pattern.strip()))
        segments = expanded.split(os.sep)
        while segments and segments[-1] in {"*", "**"}:
            segments.pop()
        root = os.sep.join(segments)
        return os.path.normpath(root) if root else ""

    @staticmethod
    def _path_covers(a: str, b: str) -> bool:
        """True if a == b or a is an ancestor of b (a contains b)."""
        if a == b:
            return True
        return b.startswith(a.rstrip(os.sep) + os.sep)

    @staticmethod
    def _path_ancestors(path: str) -> list[str]:
        """Return ``path`` followed by each of its filesystem ancestors."""
        current = os.path.normpath(path)
        ancestors = [current]
        while True:
            parent = os.path.dirname(current)
            if parent == current or not parent:
                break
            ancestors.append(parent)
            current = parent
        return ancestors

    @staticmethod
    def _glob_path_matches(pattern: str, path: str) -> bool:
        """Match a filesystem path with segment-aware ``**`` glob semantics."""
        pattern = os.path.normpath(pattern)
        path = os.path.normpath(path)
        if os.path.isabs(pattern) != os.path.isabs(path):
            return False
        pattern_parts = tuple(part for part in pattern.split(os.sep) if part)
        path_parts = tuple(part for part in path.split(os.sep) if part)
        memo: dict[tuple[int, int], bool] = {}

        def matches(pattern_index: int, path_index: int) -> bool:
            key = (pattern_index, path_index)
            if key in memo:
                return memo[key]
            if pattern_index == len(pattern_parts):
                result = path_index == len(path_parts)
            elif pattern_parts[pattern_index] == "**":
                result = matches(pattern_index + 1, path_index) or (
                    path_index < len(path_parts)
                    and matches(pattern_index, path_index + 1)
                )
            else:
                result = (
                    path_index < len(path_parts)
                    and fnmatch.fnmatchcase(
                        path_parts[path_index], pattern_parts[pattern_index]
                    )
                    and matches(pattern_index + 1, path_index + 1)
                )
            memo[key] = result
            return result

        return matches(0, 0)

    @staticmethod
    def _glob_patterns_may_cover(first: str, second: str) -> bool:
        """Conservatively test whether two path patterns can overlap by prefix.

        This is intentionally symbolic: it never walks the filesystem. A True
        result means overlap is possible, not proven, and therefore carries
        reversible HALT authority only unless an exact check proves protection.
        """
        first = os.path.normpath(first)
        second = os.path.normpath(second)
        if os.path.isabs(first) != os.path.isabs(second):
            return False
        first_parts = tuple(part for part in first.split(os.sep) if part)
        second_parts = tuple(part for part in second.split(os.sep) if part)
        for left, right in zip(first_parts, second_parts):
            if left == "**" or right == "**":
                return True
            left_magic = glob.has_magic(left)
            right_magic = glob.has_magic(right)
            if not left_magic and not right_magic:
                if left != right:
                    return False
            elif left_magic and not right_magic:
                if not fnmatch.fnmatchcase(right, left):
                    return False
            elif right_magic and not left_magic:
                if not fnmatch.fnmatchcase(left, right):
                    return False
            # Two wildcard segments need a full glob-language intersection
            # solver to disprove overlap, so retain reversible uncertainty.
        return True

    @staticmethod
    def _literal_prefix_remainder(
        literal: str, pattern: str
    ) -> tuple[bool, tuple[str, ...] | None]:
        """Match a literal path prefix to a glob without filesystem expansion.

        The remainder is returned only when the match is unambiguous. ``None``
        means ``**`` made the suffix position ambiguous.
        """
        literal = os.path.normpath(literal)
        pattern = os.path.normpath(pattern)
        if os.path.isabs(literal) != os.path.isabs(pattern):
            return False, ()
        literal_parts = tuple(part for part in literal.split(os.sep) if part)
        pattern_parts = tuple(part for part in pattern.split(os.sep) if part)
        if len(literal_parts) > len(pattern_parts):
            return False, ()
        for index, part in enumerate(literal_parts):
            pattern_part = pattern_parts[index]
            if pattern_part == "**":
                return True, None
            if not fnmatch.fnmatchcase(part, pattern_part):
                return False, ()
        return True, pattern_parts[len(literal_parts):]

    @classmethod
    def _delete_target_intersects_forbidden(
        cls, target: str, protected_pattern: str
    ) -> bool | None:
        """Whether recursive deletion of ``target`` intersects a forbidden root.

        Shell operand globs and scope globs describe path sets, not literal
        prefixes.  A protected literal matched by an operand glob is always an
        intersection (``~/.ssh*`` vs ``~/.ssh``).  For an internal wildcard in
        the protected root, an ancestor delete is fatal only when the wildcard
        currently materializes beneath that ancestor; this avoids treating
        ``/tmp/*/secret`` as if all of ``/tmp`` were protected.
        """
        target = os.path.normpath(target)
        protected_pattern = os.path.normpath(protected_pattern)
        target_has_magic = glob.has_magic(target)
        protected_has_magic = glob.has_magic(protected_pattern)

        # A literal target at or below a protected root pattern is destructive.
        # Checking every ancestor also recognizes descendants of an internal
        # wildcard root, e.g. /tmp/job/secret/token below /tmp/*/secret.
        if not target_has_magic and any(
            cls._glob_path_matches(protected_pattern, ancestor)
            for ancestor in cls._path_ancestors(target)
        ):
            return True

        # A shell operand glob that includes a concrete protected root is
        # destructive even if that root does not currently exist.  The shell
        # spelling is irrelevant; the two path sets intersect.
        if target_has_magic and not protected_has_magic:
            if cls._glob_path_matches(target, protected_pattern):
                return True

        # Literal paths can be compared exactly without filesystem work.
        if not target_has_magic and not protected_has_magic:
            return cls._path_covers(target, protected_pattern) or cls._path_covers(
                protected_pattern, target
            )

        # A target glob that names a protected literal, one of its ancestors,
        # or descendants below it is deterministically protected.
        if target_has_magic and not protected_has_magic:
            if any(
                cls._glob_path_matches(target, ancestor)
                for ancestor in cls._path_ancestors(protected_pattern)
            ):
                return True
            literal_prefix = target
            while glob.has_magic(literal_prefix):
                parent = os.path.dirname(literal_prefix)
                if parent == literal_prefix:
                    break
                literal_prefix = parent
            if not glob.has_magic(literal_prefix) and cls._path_covers(
                protected_pattern, literal_prefix
            ):
                return True
            return (
                None
                if cls._glob_patterns_may_cover(target, protected_pattern)
                else False
            )

        # A literal ancestor of an internal forbidden glob is a proven match
        # only when its remaining literal suffix exists. A wildcard or ``**``
        # remainder is not enumerated: it becomes reversible uncertainty.
        if not target_has_magic and protected_has_magic:
            compatible, remainder = cls._literal_prefix_remainder(
                target, protected_pattern
            )
            if not compatible:
                return False
            if remainder is None or any(glob.has_magic(part) for part in remainder):
                return None
            candidate = os.path.join(target, *remainder)
            return os.path.lexists(candidate)

        # Two glob languages can often be proven to overlap without expanding
        # either one. Ambiguous-but-possible intersections HALT reversibly.
        if target == protected_pattern:
            return True
        if cls._glob_path_matches(target, protected_pattern) or cls._glob_path_matches(
            protected_pattern, target
        ):
            return True
        return (
            None
            if cls._glob_patterns_may_cover(target, protected_pattern)
            else False
        )

    def _is_protected_root(
        self, path: str, working_directory: str | None = None
    ) -> bool | None:
        """A recursive delete of this path is catastrophic and non-recoverable:
        filesystem root, the user's home directory, or a scope forbidden_path
        (its contents, the dir itself, OR an ancestor that contains it — deleting
        a directory that CONTAINS credentials is as dangerous as deleting them).
        Non-protected project paths (node_modules, build/, dist, .venv,
        __pycache__) are NOT protected."""
        raw = path.strip()
        # A recursive delete of every child of a protected root is equivalent
        # to deleting that root's contents. Keep this deliberately exact:
        # project-scoped globs such as ``build/*`` and ``~/project/*`` remain
        # ordinary cleanup targets.
        protected_roots = (
            "~", "$HOME", "${HOME}", "/*",
            "~/*", "$HOME/*", "${HOME}/*",
            "~/.*", "$HOME/.*", "${HOME}/.*",
        )
        if raw in protected_roots:
            return True
        # ${HOME:?word} and ${HOME?word} either expand to HOME or abort the
        # shell command. Therefore deleting that expansion itself (or every
        # direct child, including dot entries) is the same protected-root
        # operation as ``rm -rf ~``. Keep the accepted suffixes exact so
        # project-scoped descendants and similarly named variables do not
        # become false-positive KILLs.
        shell_home_candidate: str | None = None
        for prefix in ("${HOME:?", "${HOME?"):
            if raw.startswith(prefix):
                closing_brace = raw.rfind("}")
                if (
                    closing_brace >= len(prefix)
                    and raw[closing_brace + 1:] in {"", "/", "/*", "/.*"}
                ):
                    return True
                if closing_brace >= len(prefix):
                    # A successful ${HOME:?word}/${HOME?word} expansion is
                    # necessarily HOME. Reconstruct only that known branch so
                    # descendants can flow through the ordinary forbidden-root
                    # matcher; do not attempt to interpret general shell
                    # parameter expansion syntax here.
                    shell_home_candidate = "~" + raw[closing_brace + 1:]
                break
        # Shell default/assignment expansions resolve to HOME under the normal
        # supported environment where HOME is set. Preserve the prior literal
        # root-fallback check, and also reconstruct that known HOME branch so a
        # descendant reaches the same forbidden-root matcher as ``~/.ssh``.
        for prefix in ("${HOME:-", "${HOME-", "${HOME:=", "${HOME="):
            if raw.startswith(prefix):
                closing_brace = raw.find("}", len(prefix))
                if (
                    closing_brace >= len(prefix)
                    and raw[len(prefix):closing_brace] == "/"
                    and raw[closing_brace + 1:] in {"", "/", "/*", "/.*"}
                ):
                    return True
                if closing_brace >= len(prefix):
                    shell_home_candidate = "~" + raw[closing_brace + 1:]
                break
        match_path = shell_home_candidate or raw
        expanded = os.path.expandvars(os.path.expanduser(match_path))
        normed = os.path.normpath(expanded)

        # Apply built-in root/home protection to the path the child actually
        # resolves. This closes both relative-parent forms (``~/..`` or ``..``
        # from HOME) and glob forms that erase entries immediately below a
        # protected root (``/**``, ``/.*``, ``~/**``). A wildcard below a
        # literal project component, such as ``~/project/*`` or
        # ``/tmp/project/*``, remains ordinary project cleanup.
        resolved = normed
        if not os.path.isabs(resolved) and working_directory is not None:
            resolved = os.path.normpath(os.path.join(working_directory, resolved))

        # Filesystem root
        if resolved == os.sep:
            return True
        # Home itself or any literal ancestor that contains it. Descendants of
        # HOME are handled only by declared forbidden paths.
        home = os.path.normpath(os.path.expanduser("~"))
        if (
            os.path.isabs(resolved)
            and not glob.has_magic(resolved)
            and self._path_covers(resolved, home)
        ):
            return True
        if os.path.isabs(resolved) and glob.has_magic(resolved):
            # A wildcard that can name HOME itself (for example ``$HOME*``)
            # can delete the complete home tree.
            if self._glob_path_matches(resolved, home):
                return True
            for protected_root in (os.sep, home):
                try:
                    relative = os.path.relpath(resolved, protected_root)
                except ValueError:
                    continue
                if relative == os.pardir or relative.startswith(os.pardir + os.sep):
                    continue
                first_component = relative.split(os.sep, 1)[0]
                if glob.has_magic(first_component):
                    return True

        # Scope-declared forbidden paths. Compare delete and protected path sets
        # without collapsing internal wildcard segments to their literal prefix.
        # Resolve relative operands against the OBSERVED child cwd, never the
        # Warden process cwd. If no child cwd is available, the caller classifies
        # the relative recursive delete as uncertain rather than benign.
        targets = {normed}
        if not os.path.isabs(normed) and working_directory is not None:
            targets.add(os.path.normpath(os.path.join(working_directory, normed)))
        uncertain_intersection = False
        for pat in self.scope.forbidden_paths:
            root = self._forbidden_path_root(pat)
            if not root or root == os.sep:
                continue
            protected_patterns = {root}
            if not os.path.isabs(root) and working_directory is not None:
                protected_patterns.add(
                    os.path.normpath(os.path.join(working_directory, root))
                )
            for tgt in targets:
                for protected_pattern in protected_patterns:
                    intersection = self._delete_target_intersects_forbidden(
                        tgt, protected_pattern
                    )
                    if intersection is True:
                        return True
                    if intersection is None:
                        uncertain_intersection = True
        return None if uncertain_intersection else False

    @staticmethod
    def _is_shell_assignment_word(token: str) -> bool:
        """True for a leading POSIX-style ``NAME=value`` assignment word."""
        name, separator, _value = token.partition("=")
        if not separator or not name:
            return False
        if not (name[0] == "_" or "A" <= name[0] <= "Z" or "a" <= name[0] <= "z"):
            return False
        return all(
            char == "_" or "A" <= char <= "Z" or "a" <= char <= "z"
            or "0" <= char <= "9"
            for char in name[1:]
        )

    @classmethod
    def _strip_shell_command_prefixes(cls, tokens: list[str]) -> list[str]:
        """Expose the executable in one shell simple command.

        This intentionally handles only the realistic prefixes admitted by the
        protected-delete threat model: leading assignment words and the
        ``exec``/``command`` builtins. It is not a general shell parser.
        """
        index = 0
        while index < len(tokens) and cls._is_shell_assignment_word(tokens[index]):
            index += 1

        if index < len(tokens) and os.path.basename(tokens[index]) == "exec":
            index += 1
            while index < len(tokens):
                if tokens[index] == "--":
                    index += 1
                    break
                if tokens[index] in {"-c", "-l"}:
                    index += 1
                    continue
                if tokens[index] == "-a" and index + 1 < len(tokens):
                    index += 2
                    continue
                break
        elif index < len(tokens) and os.path.basename(tokens[index]) == "command":
            index += 1
            if index < len(tokens) and tokens[index] == "-p":
                index += 1
            if index < len(tokens) and tokens[index] == "--":
                index += 1

        return tokens[index:]

    @classmethod
    def _unwrap_env_command(
        cls, tokens: list[str], working_directory: str | None
    ) -> tuple[list[str], str | None, str | None]:
        """Unwrap one supported ``env`` execution prefix.

        GNU/POSIX ``env`` is an executable wrapper, not evidence that later
        argv is inert text. Parse its common options exactly so
        ``env rm -rf /`` cannot bypass the protected-delete rule. Unsupported
        options or dynamic chdir operands retain the remaining argv but mark
        the result uncertain, which permits reversible HALT but never SAFE or
        speculative KILL.
        """
        if not tokens or os.path.basename(tokens[0]) != "env":
            return tokens, working_directory, None

        index = 1
        effective_cwd = working_directory
        uncertainty: str | None = None
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                index += 1
                break
            if cls._is_shell_assignment_word(token):
                name = token.partition("=")[0]
                if name == "HOME":
                    uncertainty = "env wrapper changes HOME for recursive-rm evaluation"
                index += 1
                continue
            if token in {"-i", "--ignore-environment", "-0", "--null", "-v", "--debug"}:
                index += 1
                continue
            if token in {"-u", "--unset"}:
                if index + 1 >= len(tokens):
                    return [], effective_cwd, None
                if tokens[index + 1] == "HOME":
                    uncertainty = "env wrapper unsets HOME for recursive-rm evaluation"
                index += 2
                continue
            if token.startswith("--unset="):
                if token.partition("=")[2] == "HOME":
                    uncertainty = "env wrapper unsets HOME for recursive-rm evaluation"
                index += 1
                continue

            chdir_arg: str | None = None
            if token in {"-C", "--chdir"}:
                if index + 1 >= len(tokens):
                    return [], effective_cwd, None
                chdir_arg = tokens[index + 1]
                index += 2
            elif token.startswith("--chdir="):
                chdir_arg = token.partition("=")[2]
                index += 1
            elif token.startswith("-C") and len(token) > 2:
                chdir_arg = token[2:]
                index += 1
            if chdir_arg is not None:
                if cls._rm_target_has_unresolved_expansion(chdir_arg):
                    uncertainty = "env wrapper chdir contains unresolved expansion"
                    continue
                expanded = os.path.expandvars(os.path.expanduser(chdir_arg))
                if os.path.isabs(expanded):
                    effective_cwd = os.path.normpath(expanded)
                elif effective_cwd is not None:
                    effective_cwd = os.path.normpath(
                        os.path.join(effective_cwd, expanded)
                    )
                else:
                    uncertainty = "relative env wrapper chdir has no observed child cwd"
                continue

            if token in {"-S", "--split-string"} or token.startswith("--split-string="):
                if token in {"-S", "--split-string"}:
                    if index + 1 >= len(tokens):
                        return [], effective_cwd, None
                    split_text = tokens[index + 1]
                    remaining = tokens[index + 2:]
                else:
                    split_text = token.partition("=")[2]
                    remaining = tokens[index + 1:]
                try:
                    split_tokens = shlex.split(split_text)
                except ValueError:
                    split_tokens = []
                return (
                    split_tokens + remaining,
                    effective_cwd,
                    "env split-string wrapper is not reduced exactly",
                )
            if token.startswith("-"):
                uncertainty = f"unsupported env wrapper option: {token}"
                index += 1
                continue
            break

        return tokens[index:], effective_cwd, uncertainty

    @staticmethod
    def _apply_wrapper_uncertainty(
        decision: RecursiveRmDecision, uncertainty: str | None
    ) -> RecursiveRmDecision:
        """Keep uncertain wrappers reversible when recursive rm is present."""
        if uncertainty is None or decision.state == RecursiveRmState.NONE:
            return decision
        if uncertainty in {
            "env wrapper changes HOME for recursive-rm evaluation",
            "env wrapper unsets HOME for recursive-rm evaluation",
        }:
            target = decision.target or ""
            try:
                target_tokens = shlex.split(target)
            except ValueError:
                target_tokens = [target]
            depends_on_home = (
                "$HOME" in target
                or "${HOME" in target
                or any(token.startswith("~") for token in target_tokens)
            )
            if not depends_on_home:
                # An exact HOME assignment/unset cannot change literal `/`, an
                # absolute forbidden path, or ordinary literal project cleanup.
                # Preserve the already-proven decision instead of weakening a
                # protected-root KILL to HALT.
                return decision
        return RecursiveRmDecision(
            RecursiveRmState.UNCERTAIN,
            target=decision.target,
            reason=uncertainty,
        )

    def _rm_rf_protected_target(
        self, command: str, working_directory: str | None = None
    ) -> str | None:
        """If `command` is a recursive rm whose target is a protected root,
        return that target (→ KILL). Otherwise None. Routine recursive deletes
        of project directories are intentionally allowed to fall through to a
        FLAG at most — they are not proof of harm. Unwrap a shell ``-c`` payload
        first so an allowed shell cannot bypass this deterministic protection."""
        # This private compatibility helper historically classified commands in
        # the Warden cwd. Runtime enforcement does not use this default: it calls
        # _recursive_rm_decision with the observed child cwd explicitly.
        effective_cwd = working_directory or os.getcwd()
        decision = self._recursive_rm_decision(command, effective_cwd)
        if decision.state == RecursiveRmState.PROTECTED:
            return decision.target
        return None

    @staticmethod
    def _rm_target_has_unresolved_expansion(target: str) -> bool:
        """Whether a target depends on shell state other than the known HOME."""
        raw = target.strip()
        if "`" in raw or "$(" in raw:
            return True
        # Bash/zsh brace expansion happens after observation but before exec.
        # shlex intentionally does not retain enough quoting context to reduce
        # it without false irreversible authority, so comma/range forms HALT.
        for opening in range(len(raw)):
            if raw[opening] != "{":
                continue
            closing = raw.find("}", opening + 1)
            if closing > opening and (
                "," in raw[opening + 1:closing]
                or ".." in raw[opening + 1:closing]
            ):
                return True
        if "$" not in raw:
            return False
        if raw.startswith("$HOME") and (
            len(raw) == len("$HOME") or raw[len("$HOME")] in "/.*?["
        ):
            return "$" in raw[len("$HOME"):]
        if raw.startswith("${HOME}"):
            return "$" in raw[len("${HOME}"):]
        for prefix in ("${HOME:?", "${HOME?", "${HOME:-", "${HOME-", "${HOME:=", "${HOME="):
            if not raw.startswith(prefix):
                continue
            closing = raw.find("}", len(prefix))
            if closing >= len(prefix):
                # The known HOME expansion is safe to reduce only when neither
                # its parameter word nor the remaining operand contains another
                # expansion. For example, $HOME/${BAD} must HALT rather than
                # becoming a confidently benign literal project path.
                return "$" in raw[len(prefix):]
        return True

    @staticmethod
    def _rm_target_depends_on_cwd(target: str) -> bool:
        """Whether the shell resolves this target relative to its current cwd."""
        raw = target.strip()
        expanded = os.path.expandvars(os.path.expanduser(raw))
        if os.path.isabs(expanded):
            return False
        if raw.startswith("${HOME}"):
            return False
        if raw.startswith((
            "${HOME:?", "${HOME?", "${HOME:-", "${HOME-", "${HOME:=", "${HOME=",
        )) and "}" in raw:
            return False
        return True

    def _classify_rm_tokens(
        self, tokens: list[str], working_directory: str | None = None
    ) -> RecursiveRmDecision:
        """Classify one argv-like simple command without executing it."""
        tokens = self._strip_shell_command_prefixes(tokens)
        tokens, working_directory, wrapper_uncertainty = self._unwrap_env_command(
            tokens, working_directory
        )
        if not tokens:
            return RecursiveRmDecision(RecursiveRmState.NONE)

        command_word = tokens[0]
        command_stem = os.path.basename(command_word.rstrip(os.sep))
        command_unresolved = self._rm_target_has_unresolved_expansion(command_word)
        recursive_hint = any(
            token.startswith("-")
            and token != "--"
            and (
                token == "--recursive"
                or (not token.startswith("--") and ("r" in token[1:] or "R" in token[1:]))
            )
            for token in tokens[1:]
        )
        if os.path.basename(command_word) != "rm":
            if command_unresolved and (
                command_stem.startswith("rm") or recursive_hint
            ):
                return RecursiveRmDecision(
                    RecursiveRmState.UNCERTAIN,
                    target=command_word,
                    reason="recursive-rm command word contains unresolved shell expansion",
                )
            return RecursiveRmDecision(RecursiveRmState.NONE)

        recursive = False
        path_args: list[str] = []
        unresolved_option: str | None = None
        options_ended = False
        for tok in tokens[1:]:
            if not options_ended and tok == "--":
                options_ended = True
                continue
            if not options_ended and tok.startswith("--"):
                if self._rm_target_has_unresolved_expansion(tok):
                    unresolved_option = tok
                if tok == "--recursive":
                    recursive = True
                continue
            if not options_ended and tok.startswith("-") and len(tok) > 1:
                if self._rm_target_has_unresolved_expansion(tok):
                    unresolved_option = tok
                # short-flag cluster, e.g. -rf / -fr / -Rf / -r
                if "r" in tok[1:] or "R" in tok[1:]:
                    recursive = True
                continue
            path_args.append(tok)

        if not recursive:
            return RecursiveRmDecision(RecursiveRmState.NONE)
        if unresolved_option is not None:
            return RecursiveRmDecision(
                RecursiveRmState.UNCERTAIN,
                target=unresolved_option,
                reason="recursive-rm option contains unresolved shell expansion",
            )
        for p in path_args:
            if self._rm_target_has_unresolved_expansion(p):
                return RecursiveRmDecision(
                    RecursiveRmState.UNCERTAIN,
                    target=p,
                    reason="recursive-rm target contains unresolved shell expansion",
                )
        uncertain_protection: str | None = None
        for p in path_args:
            protection = self._is_protected_root(p, working_directory)
            if protection is True:
                return self._apply_wrapper_uncertainty(
                    RecursiveRmDecision(
                        RecursiveRmState.PROTECTED,
                        target=p,
                        reason="recognized protected recursive-rm target",
                    ),
                    wrapper_uncertainty,
                )
            if protection is None:
                uncertain_protection = p
        if uncertain_protection is not None:
            return RecursiveRmDecision(
                RecursiveRmState.UNCERTAIN,
                target=uncertain_protection,
                reason="recursive-rm target may intersect a configured forbidden glob",
            )
        for p in path_args:
            if working_directory is None and self._rm_target_depends_on_cwd(p):
                return RecursiveRmDecision(
                    RecursiveRmState.UNCERTAIN,
                    target=p,
                    reason="relative recursive-rm target has no observed child cwd",
                )
        return self._apply_wrapper_uncertainty(
            RecursiveRmDecision(
                RecursiveRmState.BENIGN,
                target=" ".join(path_args),
                reason="recursive-rm targets are confidently non-protected literals",
            ),
            wrapper_uncertainty,
        )

    def _recursive_rm_decision(
        self, command: str, working_directory: str | None = None
    ) -> RecursiveRmDecision:
        """Classify supported shell ``-c`` recursive-rm behavior tri-state.

        Simple commands are reduced exactly. In compound segments, an embedded
        protected or dynamic recursive rm cannot be assigned irreversible KILL
        authority without a full shell parser, so it becomes a reversible HALT.
        Embedded literal project cleanup remains benign. Quoted strings remain
        one token, while the output-only echo/printf controls treat later tokens
        as data rather than commands.
        """
        try:
            tokens = shlex.split(command)
        except ValueError:
            return RecursiveRmDecision(RecursiveRmState.NONE)
        tokens = self._strip_shell_command_prefixes(tokens)
        tokens, working_directory, wrapper_uncertainty = self._unwrap_env_command(
            tokens, working_directory
        )
        if not tokens:
            return RecursiveRmDecision(RecursiveRmState.NONE)

        base_cmd = os.path.basename(tokens[0])
        if base_cmd not in {"bash", "dash", "ksh", "sh", "zsh"}:
            decision = self._classify_rm_tokens(tokens, working_directory)
            if decision.state == RecursiveRmState.NONE and base_cmd not in {
                "echo", "printf"
            }:
                # Do not guess irreversible execution semantics for arbitrary
                # wrappers. If a later argv suffix is itself a recursive rm,
                # pause reversibly instead of allowing wrapper PID de-duplication
                # to turn a destructive child into SAFE/FLAG evidence only.
                for rm_index in range(1, len(tokens)):
                    if os.path.basename(tokens[rm_index]) != "rm":
                        continue
                    embedded = self._classify_rm_tokens(
                        tokens[rm_index:], working_directory
                    )
                    if embedded.state != RecursiveRmState.NONE:
                        decision = RecursiveRmDecision(
                            RecursiveRmState.UNCERTAIN,
                            target=embedded.target,
                            reason="execution wrapper obscures recursive-rm semantics",
                        )
                        break
            return self._apply_wrapper_uncertainty(decision, wrapper_uncertainty)

        payload = ""
        for index, token in enumerate(tokens[1:], start=1):
            if token.startswith("-") and not token.startswith("--") and "c" in token[1:]:
                # Exactly one argv item after -c is executable shell text. Later
                # items are positional data and never enter this classifier.
                payload = tokens[index + 1] if index + 1 < len(tokens) else ""
                break
        if not payload:
            return RecursiveRmDecision(RecursiveRmState.NONE)

        saw_benign = False
        uncertain: RecursiveRmDecision | None = None
        for segment in self._shell_command_segments(payload):
            direct = self._classify_rm_tokens(segment, working_directory)
            if direct.state == RecursiveRmState.PROTECTED:
                return self._apply_wrapper_uncertainty(
                    direct, wrapper_uncertainty
                )
            if direct.state == RecursiveRmState.UNCERTAIN:
                uncertain = direct
            elif direct.state == RecursiveRmState.BENIGN:
                saw_benign = True

            normalized = self._strip_shell_command_prefixes(segment)
            if not normalized or direct.state != RecursiveRmState.NONE:
                continue
            # These commands render their remaining argv as text; an `rm` token
            # there is evidence content, not an executable command.
            if os.path.basename(normalized[0]) in {"echo", "printf"}:
                continue
            for rm_index in range(1, len(normalized)):
                if os.path.basename(normalized[rm_index]) != "rm":
                    continue
                embedded = self._classify_rm_tokens(
                    normalized[rm_index:], working_directory
                )
                if embedded.state in {
                    RecursiveRmState.PROTECTED,
                    RecursiveRmState.UNCERTAIN,
                }:
                    uncertain = RecursiveRmDecision(
                        RecursiveRmState.UNCERTAIN,
                        target=embedded.target,
                        reason="compound shell syntax obscures recursive-rm command position",
                    )
                elif embedded.state == RecursiveRmState.BENIGN:
                    saw_benign = True

        if uncertain is not None:
            return self._apply_wrapper_uncertainty(
                uncertain, wrapper_uncertainty
            )
        if saw_benign:
            return self._apply_wrapper_uncertainty(
                RecursiveRmDecision(
                    RecursiveRmState.BENIGN,
                    reason="compound shell recursive-rm targets are confidently benign",
                ),
                wrapper_uncertainty,
            )
        return RecursiveRmDecision(RecursiveRmState.NONE)

    @staticmethod
    def _strip_shell_comments(payload: str) -> str:
        """Remove POSIX-style shell comments without rewriting shell words.

        An unquoted, unescaped ``#`` starts a comment only at the beginning of
        a word. Newlines are retained because they still terminate the current
        simple command. This intentionally leaves quoted and escaped ``#``
        bytes for :mod:`shlex` to interpret as ordinary argument content.
        """
        stripped: list[str] = []
        quote: str | None = None
        escaped = False
        at_word_start = True
        index = 0

        while index < len(payload):
            char = payload[index]

            if escaped:
                stripped.append(char)
                escaped = False
                at_word_start = False
                index += 1
                continue

            if quote is not None:
                stripped.append(char)
                if char == quote:
                    quote = None
                elif char == "\\" and quote == '"':
                    escaped = True
                index += 1
                continue

            if char == "\\":
                stripped.append(char)
                escaped = True
                at_word_start = False
                index += 1
                continue

            if char in {"'", '"'}:
                stripped.append(char)
                quote = char
                at_word_start = False
                index += 1
                continue

            if char == "#" and at_word_start:
                while index < len(payload) and payload[index] != "\n":
                    index += 1
                continue

            stripped.append(char)
            if char == "\n" or char in ";&|()":
                at_word_start = True
            elif char in " \t\r":
                at_word_start = True
            else:
                at_word_start = False
            index += 1

        return "".join(stripped)

    @staticmethod
    def _shell_command_segments(payload: str) -> list[list[str]]:
        """Tokenize simple shell compounds without confusing quoted operators.

        This is intentionally not an execution parser. It only preserves the
        security boundary needed by the recursive-delete rule: unquoted shell
        control operators split commands, while quoted punctuation remains a
        normal argument byte. The resulting argv-like segments are inspected,
        never executed.
        """
        payload = Warden._strip_shell_comments(payload)
        try:
            lexer = shlex.shlex(
                payload, posix=True, punctuation_chars=";&|()\n"
            )
            lexer.whitespace_split = True
            lexer.whitespace = " \t\r"
            lexer.commenters = ""
            shell_tokens = list(lexer)
        except ValueError:
            return []

        segments: list[list[str]] = []
        current: list[str] = []
        for token in shell_tokens:
            if token and all(char in ";&|()\n" for char in token):
                if current:
                    segments.append(current)
                    current = []
                continue
            current.append(token)
        if current:
            segments.append(current)
        return segments

    # Credential-material detectors for the exfil rule. Basename globs catch
    # key/cert material; path substrings catch well-known secret stores.
    _CRED_BASENAME_GLOBS = (
        "*id_rsa*", "*id_ed25519*", "*id_ecdsa*", "*id_dsa*",
        "*.pem", "*.key", "*.p12", "*.pfx", "*.ppk",
        "credentials", "*.credentials", "*_credentials",
    )
    _CRED_PATH_SUBSTRINGS = (
        "/.aws/credentials", "/.aws/config",
        "/.ssh/", "/.gnupg/", "/.config/gcloud/",
    )

    def _is_credential_target(self, path: str) -> bool:
        """True if *path* names credential material: a scope forbidden_path, a
        secret-looking basename (id_rsa / *.pem / …), or a well-known secret
        store (~/.aws/credentials, ~/.ssh/…). This only ARMS the exfil rule — it
        does not by itself KILL."""
        if not path:
            return False
        expanded = os.path.expanduser(os.path.expandvars(path))
        norm = os.path.normpath(expanded)
        base = os.path.basename(norm)
        for g in self._CRED_BASENAME_GLOBS:
            if fnmatch.fnmatch(base, g):
                return True
        low = norm.replace(os.sep, "/").lower()
        for sub in self._CRED_PATH_SUBSTRINGS:
            if sub in low:
                return True
        # Scope-declared forbidden paths are secret material by declaration.
        try:
            if self.scope._path_matches(norm, self.scope.forbidden_paths):
                return True
        except Exception:  # noqa: BLE001 — never crash eval on a match error
            pass
        return False

    def _track_and_check_exfil(self, action: AgentAction) -> WardenVerdict | None:
        """Record credential reads per pid; on a non-local NETWORK_OUT that
        FOLLOWS a credential read within ``cred_exfil_window`` seconds, return
        KILL — the real exfil signature (read a secret, then ship it out).

        A bare network-out with NO preceding credential read returns None, so
        benign curl/pip stay HALT/FLAG per the existing rules. Tree-scoped: the
        warden monitors ONE agent tree, so a read on any pid paired with a
        network-out on any pid is a legitimate correlation (covers the
        parent-reads / child-curls exfil shape)."""
        now = time.time()
        window = self.cred_exfil_window

        # Prune every tracked pid's history to the window; drop empties.
        for pid in list(self.credential_reads):
            fresh = [t for t in self.credential_reads[pid] if now - t <= window]
            if fresh:
                self.credential_reads[pid] = fresh
            else:
                del self.credential_reads[pid]

        if self._is_credential_read_action(action):
            self.credential_reads.setdefault(action.source_pid, []).append(now)
            return None

        if action.action_type == ActionType.NETWORK_OUT and self.credential_reads:
            remote_value = action.details.get("remote_ip")
            if remote_value is None:
                if action.target.startswith("[") and "]" in action.target:
                    remote_value = action.target[1:action.target.index("]")]
                else:
                    remote_value = action.target.rsplit(":", 1)[0]
            remote = str(remote_value)
            port = action.details.get("remote_port", 443)
            _network_verdict, network_reason = self.scope.check_network(remote, port)
            # Localhost is IPC, not egress. Keep the credential-read window
            # armed so a later non-local connection is still caught.
            if network_reason.startswith("Localhost connection:"):
                return None
            last_read = max(
                t for reads in self.credential_reads.values() for t in reads
            )
            return WardenVerdict(
                verdict=Verdict.KILL,
                reason=(
                    f"Credential-exfil signature: credential read "
                    f"{now - last_read:.1f}s before network egress to "
                    f"{action.target}"
                ),
                action=action, evaluator="rule_engine",
            )
        return None

    def _is_credential_read_action(self, action: AgentAction) -> bool:
        """Whether an observation proves a credential could be read.

        psutil reports read/write handles (``r+``, ``w+``, ``a+``) as one
        mode.  The observer classifies them as FILE_WRITE to preserve their
        mutation authority, but ``+`` also permits reads and must arm the
        exfiltration correlation.
        """
        if not self._is_credential_target(action.target):
            return False
        if action.action_type == ActionType.FILE_READ:
            return True
        mode = str(action.details.get("mode", ""))
        return action.action_type == ActionType.FILE_WRITE and "+" in mode

    def _order_actions_for_enforcement(
        self, actions: list[AgentAction]
    ) -> list[AgentAction]:
        """Return a stable safety order for one observer poll.

        psutil file and connection collectors are grouped independently, so
        their list order is not an event chronology. Treat credential reads and
        network egress reported in the same poll as a read-then-egress pair by
        moving only credential reads to the front. Ordinary actions retain their
        relative order and cannot arm the exfil rule.
        """
        credential_reads: list[AgentAction] = []
        others: list[AgentAction] = []
        for action in actions:
            if self._is_credential_read_action(action):
                credential_reads.append(action)
            else:
                others.append(action)
        return credential_reads + others

    def _check_hardcoded_kill(self, action: AgentAction) -> WardenVerdict | None:
        """Hardcoded KILL and reversible uncertainty-HALT safety rules."""
        target = action.target

        # SSH key access
        if action.action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            expanded = os.path.expanduser(os.path.abspath(target))
            ssh_dir = os.path.expanduser("~/.ssh")
            if expanded.startswith(ssh_dir + os.sep) or expanded == ssh_dir:
                return WardenVerdict(
                    verdict=Verdict.KILL, reason=f"SSH directory access: {target}",
                    action=action, evaluator="rule_engine"
                )
            basename = os.path.basename(target)
            for pat in ("*id_rsa*", "*id_ed25519*"):
                if fnmatch.fnmatch(basename, pat):
                    return WardenVerdict(
                        verdict=Verdict.KILL, reason=f"SSH key file access: {target}",
                        action=action, evaluator="rule_engine"
                    )

        # Modifying ~/.openclaw/openclaw.json
        if action.action_type == ActionType.FILE_WRITE:
            expanded = os.path.expanduser(os.path.abspath(target))
            openclaw_cfg = os.path.expanduser("~/.openclaw/openclaw.json")
            if expanded == os.path.abspath(openclaw_cfg):
                return WardenVerdict(
                    verdict=Verdict.KILL, reason=f"Modifying openclaw config: {target}",
                    action=action, evaluator="rule_engine"
                )

        # rm -rf: KILL only when the recursive delete targets a PROTECTED root
        # (filesystem root, home, or a scope forbidden_path). A recursive rm of a
        # non-protected project path (node_modules, build/, dist, .venv,
        # __pycache__) is routine developer cleanup — it falls through to at most
        # a FLAG, never an instant SIGKILL.
        if action.action_type in (ActionType.PROCESS_EXEC, ActionType.PROCESS_SPAWN):
            observed_cwd = action.details.get("cwd")
            if not isinstance(observed_cwd, str) or not os.path.isabs(observed_cwd):
                observed_cwd = None
            rm_decision = self._recursive_rm_decision(action.target, observed_cwd)
            if rm_decision.state == RecursiveRmState.PROTECTED:
                return WardenVerdict(
                    verdict=Verdict.KILL,
                    reason=f"rm -rf targeting protected root: {rm_decision.target}",
                    action=action, evaluator="rule_engine"
                )
            if rm_decision.state == RecursiveRmState.UNCERTAIN:
                return WardenVerdict(
                    verdict=Verdict.HALT,
                    reason=(
                        "Uncertain compound shell recursive rm: "
                        f"{rm_decision.reason}; target={rm_decision.target or 'unknown'}"
                    ),
                    action=action,
                    evaluator="rule_engine",
                )

        return None

    def _check_halt_triggers(self, action: AgentAction) -> WardenVerdict | None:
        """Behavioral HALT triggers — suspicious but not kill-worthy."""
        now = time.time()

        # 3+ file deletions in 10 seconds
        if action.action_type == ActionType.FILE_DELETE:
            self.delete_timestamps.append(now)
            self.delete_timestamps = [t for t in self.delete_timestamps if now - t <= 10]
            if len(self.delete_timestamps) >= 3:
                return WardenVerdict(
                    verdict=Verdict.HALT,
                    reason=f"Rapid file deletion: {len(self.delete_timestamps)} "
                           f"deletes in 10s",
                    action=action, evaluator="rule_engine"
                )

        # curl or wget process spawned
        if action.action_type in (ActionType.PROCESS_EXEC, ActionType.PROCESS_SPAWN):
            base_cmd = os.path.basename(action.target.strip().split()[0]) if action.target.strip() else ""
            if base_cmd in ("curl", "wget"):
                return WardenVerdict(
                    verdict=Verdict.HALT,
                    reason=f"Suspicious process spawned: {base_cmd}",
                    action=action, evaluator="rule_engine"
                )

        # Writing outside allowed workspace
        if action.action_type == ActionType.FILE_WRITE:
            v, _ = self.scope.check_filesystem(action.target)
            if v == Verdict.FLAG:
                return WardenVerdict(
                    verdict=Verdict.HALT,
                    reason=f"Write outside allowed workspace: {action.target}",
                    action=action, evaluator="rule_engine"
                )

        # 50+ network_out events in 60 seconds
        if action.action_type == ActionType.NETWORK_OUT:
            self.network_out_timestamps.append(now)
            self.network_out_timestamps = [
                t for t in self.network_out_timestamps if now - t <= 60
            ]
            if len(self.network_out_timestamps) >= 50:
                return WardenVerdict(
                    verdict=Verdict.HALT,
                    reason=f"Mass API calls: {len(self.network_out_timestamps)} "
                           f"network events in 60s",
                    action=action, evaluator="rule_engine"
                )

        return None

    async def evaluate_action(self, action: AgentAction) -> WardenVerdict:
        """Rule engine first, then LLM for ambiguous cases."""

        # A filesystem-diff action cannot be attributed to a specific pid — the
        # diff only sees that a path appeared/vanished, not who did it. Preserve
        # the observation, but never use it to suspend or kill the monitored
        # process. Protected-path observations are downgraded to FLAG.
        is_diff = action.details.get("detected_by") == "scope_diff"
        if is_diff:
            verdict, reason = self.scope.check_filesystem(action.target)
            if verdict == Verdict.KILL:
                verdict = Verdict.FLAG
            return WardenVerdict(
                verdict=verdict,
                reason=f"Unattributed scope-diff observation: {reason}",
                action=action,
                evaluator="rule_engine",
            )

        # Hardcoded KILL checks (highest priority) — attributed actions only.
        # Defense-in-depth: record credential reads + fire the deterministic
        # credential-read-then-non-local-network-out exfil KILL. Runs first so
        # an otherwise allowed external destination cannot erase the correlated
        # signal; the exfil reducer itself explicitly exempts localhost IPC.
        exfil_verdict = self._track_and_check_exfil(action)
        if exfil_verdict is not None:
            return exfil_verdict

        kill_verdict = self._check_hardcoded_kill(action)
        if kill_verdict is not None:
            return kill_verdict

        # Behavioral HALT checks apply only to process-attributed observations.
        halt_verdict = self._check_halt_triggers(action)
        if halt_verdict is not None:
            return halt_verdict

        if action.action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE,
                                   ActionType.FILE_DELETE):
            verdict, reason = self.scope.check_filesystem(action.target)
        elif action.action_type == ActionType.NETWORK_OUT:
            ip = action.details.get('remote_ip', action.target.split(':')[0])
            port = action.details.get('remote_port', 443)
            verdict, reason = self.scope.check_network(ip, port)
        elif action.action_type in (ActionType.PROCESS_EXEC, ActionType.PROCESS_SPAWN):
            verdict, reason = self.scope.check_command(action.target)
        else:
            verdict, reason = Verdict.FLAG, "Unknown action type"

        # Definitive answers don't need LLM
        if verdict in (Verdict.SAFE, Verdict.KILL):
            return WardenVerdict(
                verdict=verdict, reason=reason,
                action=action, evaluator="rule_engine"
            )

        # FLAG is the deterministic verdict and it is AUTHORITATIVE: it is
        # returned IMMEDIATELY. The LLM judge is ADVISORY ONLY and runs OFF the
        # hot path (fire-and-forget), so it can neither (1) block real-time
        # enforcement — the blind-window/DoS-on-the-monitor risk when observe()
        # would run on nothing while we awaited a ~137s worst-case model call —
        # nor (2) escalate to KILL/HALT. Its influence is capped at raising
        # monitoring posture + enriching forensics (see _apply_advisory).
        det_verdict = WardenVerdict(
            verdict=Verdict.FLAG, reason=reason,
            action=action, evaluator="rule_engine",
        )
        if self.judge.available:
            self._dispatch_advisory(action)
        else:
            llm_state = "disabled" if not self.enable_llm else "unavailable"
            det_verdict.reason = f"{reason} (LLM {llm_state})"
        return det_verdict

    def _dispatch_advisory(self, action: AgentAction) -> None:
        """Fire the LLM judge OFF the enforcement hot path as advisory-only
        enrichment. Never awaited by evaluate_action, so a slow/hanging model can
        never delay deterministic enforcement (no blind window). Best-effort: if
        there is no running event loop, the advisory is simply skipped."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        # One in-flight advisory is enough: deterministic evaluation is the hot
        # path, and an unavailable/slow Ollama endpoint must not create an
        # unbounded task/socket fanout during a burst of FLAG actions.
        if self._advisory_tasks:
            self.advisory_skipped_busy += 1
            self.log.debug("Advisory skipped: one evaluation is already in flight")
            return
        recent = [v.action for v in self.all_verdicts[-20:]]
        task = loop.create_task(self._run_advisory(action, recent))
        self._advisory_tasks.add(task)
        task.add_done_callback(self._advisory_tasks.discard)

    async def _run_advisory(self, action: AgentAction,
                            recent: list) -> None:
        """Await the advisory LLM verdict and fold it into monitoring posture.
        Fully guarded: an advisory failure must never crash the warden and must
        never terminate or suspend the agent."""
        try:
            advisory = await self.judge.evaluate(
                action, self.scope_summary, recent
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — advisory is strictly best-effort
            self.log.debug(f"Advisory judge error (ignored): {e}")
            return
        self._apply_advisory(advisory)

    def _apply_advisory(self, advisory: WardenVerdict) -> None:
        """Fold an ADVISORY judge verdict into monitoring posture. HARD CAP: the
        LLM can only raise posture (record for review + forensics). It can NEVER
        cause a KILL or a SIGSTOP — those are the deterministic rule engine's
        sole authority. Any KILL/HALT the model emits is coerced to FLAG here as
        a second line of defense behind the SAFE/FLAG-only response schema. This
        method deliberately has NO path to execute_kill / execute_halt / the
        kill-capable flag_timestamps accumulator."""
        verdict = LLMJudge._coerce_advisory_verdict(advisory.verdict.value)
        persisted = WardenVerdict(
            verdict=verdict,
            reason=advisory.reason,
            action=advisory.action,
            evaluator="llm_judge",
            confidence=advisory.confidence,
            timestamp=advisory.timestamp,
        )
        self.advisories.append({
            "timestamp": advisory.timestamp,
            "advisory_verdict": verdict.value,
            "reason": advisory.reason,
            "confidence": advisory.confidence,
            "action": advisory.action.to_dict(),
        })
        # Advisory output is forensic evidence even though it has no enforcement
        # authority. Persist completed results in the same JSONL evidence stream,
        # clearly labeled by evaluator, instead of losing them on process exit.
        try:
            self.logger.log_action(persisted)
        except Exception as e:  # noqa: BLE001 — evidence failure must be visible
            self.log.error(f"Advisory evidence persistence failed: {e}")
        if verdict == Verdict.FLAG:
            self.log.warning(
                f"🔎 Advisory (raise posture, non-enforcing): {advisory.reason}"
            )
    
    def _agent_tree_is_suspended(self) -> bool:
        """Return true only when every visible live process in the tree is stopped."""
        try:
            root = psutil.Process(self.agent_pid)
            processes = [root, *root.children(recursive=True)]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

        visible = False
        for process in processes:
            try:
                if not process.is_running():
                    continue
                visible = True
                if process.status() != psutil.STATUS_STOPPED:
                    return False
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
        return visible

    async def execute_halt(self, verdict: WardenVerdict, *, retry: bool = False):
        """Give a HALT verdict teeth: SIGSTOP the agent tree — a *reversible*
        pause — then log + write one forensic report per HALT episode. A later
        HALT reconciles the visible process tree before treating the prior pause
        as still active. Failed one-shot attempts remain pending for run-loop
        retry without duplicating their report."""
        if not retry:
            self._halt_episode_report_path = None
            self._halt_episode_attempts = []

        if self.suspended:
            self.suspended = self._agent_tree_is_suspended()
            if self.suspended:
                self.pending_halt = None
                self.log.warning(
                    f"🟡 HALT (agent tree still suspended, no re-signal): "
                    f"{verdict.reason}"
                )
                return
            self.log.warning("Prior HALT state is stale; re-attempting SIGSTOP.")

        self.log.warning(f"🟡 HALT: {verdict.reason}")
        self.log.warning(
            f"   Action: {verdict.action.action_type.value} -> "
            f"{verdict.action.target}"
        )
        suspend_result = self.killswitch.suspend_agent()
        pids_suspended = suspend_result.get("pids_suspended", [])
        self.suspended = bool(
            suspend_result.get("suspended")
            and pids_suspended
            and not suspend_result.get("errors")
        )
        suspend_result["suspended"] = self.suspended
        self.pending_halt = None if self.suspended else verdict
        self._halt_episode_attempts.append(dict(suspend_result))
        if self.suspended:
            self.log.critical(
                f"   ⏸️  Agent SIGSTOPed (reversible pause): "
                f"pids={pids_suspended} errors={suspend_result['errors']}"
            )
        else:
            self.log.error(
                f"   Suspension failed (will retry on next HALT): "
                f"pids={pids_suspended} errors={suspend_result['errors']}"
            )
        try:
            if not retry or self._halt_episode_report_path is None:
                report_path = self.logger.generate_halt_report(
                    verdict, self.all_verdicts, suspend_result
                )
                self._halt_episode_report_path = report_path
            else:
                report_path = self._halt_episode_report_path
            with open(report_path, 'r') as f:
                report = json.load(f)
            report["halt_report"]["status"] = (
                "AGENT_SUSPENDED" if self.suspended else "SUSPENSION_FAILED"
            )
            report["control_action"].update({
                "suspended": self.suspended,
                "pids_suspended": pids_suspended,
                "errors": suspend_result.get("errors", []),
            })
            report["liability_statement"][
                "agent_process_suspended"
            ] = self.suspended
            report["liability_statement"]["notice"] = (
                "The monitored agent is SUSPENDED (SIGSTOP), a reversible "
                "pause, after the latest HALT control attempt."
                if self.suspended
                else "The latest SIGSTOP attempt did not suspend the monitored "
                "agent; the HALT episode remains pending for retry."
            )
            report["halt_attempts"] = self._halt_episode_attempts
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            self.log.warning(f"   📋 Halt report: {report_path}")
        except Exception as e:  # noqa: BLE001 — never crash the loop on reporting
            self.log.error(f"   Halt report failed: {e}")

    async def execute_kill(self, verdict: WardenVerdict, *, retry: bool = False):
        """Attempt termination; rollback/report exactly once per kill episode."""
        self.pending_halt = None
        if not retry:
            self._kill_episode_report_path = None
            self._kill_episode_rollback = None
            self._kill_episode_attempts = []
        
        self.log.critical(f"🔴 KILL: {verdict.reason}")
        self.log.critical(f"   Action: {verdict.action.action_type.value} -> {verdict.action.target}")
        
        kill_result = self.killswitch.kill_agent()
        self.log.critical(
            "   SIGKILL attempt: "
            f"success={kill_result['killed']} "
            f"pids={kill_result.get('pids_terminated', [])} "
            f"errors={kill_result.get('errors', [])}"
        )
        self.killed = bool(
            kill_result.get("killed") and kill_result.get("pids_terminated")
        )
        self.pending_kill = None if self.killed else verdict
        self._kill_episode_attempts.append(kill_result)

        report_path: str | None
        if not retry:
            rollback_result = self.killswitch.attempt_rollback(verdict.action)
            self._kill_episode_rollback = rollback_result
            self.log.info(f"   Rollback: {rollback_result['details']}")
            report_path = None
        else:
            rollback_result = self._kill_episode_rollback or {
                "attempted": False,
                "success": False,
                "details": "No initial rollback receipt available",
            }
            report_path = self._kill_episode_report_path

        try:
            if report_path is None:
                report_path = self.logger.generate_incident_report(
                    verdict, self.all_verdicts, kill_result, rollback_result
                )
                self._kill_episode_report_path = str(report_path)

            # Update the one episode report with the latest control outcome.
            with open(report_path, 'r') as f:
                report = json.load(f)
            report["session_summary"]["session_duration_seconds"] = (
                time.time() - self.start_time
            )
            report["liability_statement"]["rollback_details"] = rollback_result
            report["kill_execution"] = kill_result
            report["kill_attempts"] = self._kill_episode_attempts
            report["incident_report"]["status"] = (
                "AGENT_TERMINATED" if self.killed else "TERMINATION_FAILED"
            )
            report["liability_statement"][
                "agent_process_terminated"
            ] = self.killed
            report["liability_statement"]["termination_method"] = (
                "SIGKILL" if self.killed else "SIGKILL_ATTEMPTED"
            )
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            self.log.critical(f"   📋 Report: {report_path}")
        except Exception as e:  # noqa: BLE001 — enforcement retry must survive evidence I/O
            self.log.error(f"   Incident report update failed: {e}")

    async def run(self):
        """Main monitoring loop."""
        
        self.log.info("🛡️  Agent Warden active")
        self.log.info(f"   PID: {self.agent_pid}")
        self.log.info(f"   Poll: {self.poll_interval}s")
        self.log.info(f"   Agent: {self.scope.config.get('agent', {}).get('name', 'unknown')}")
        
        if self.enable_llm:
            await self.judge.check_available()
        else:
            self.judge.available = False
        llm_status = (
            "disabled (rules only)"
            if not self.enable_llm
            else ("✅" if self.judge.available else "❌ (rules only)")
        )
        self.log.info(f"   LLM: {self.judge.model} {llm_status}")
        self.log.info(f"   Log: {self.logger.action_log_path}")
        self.log.info("   ─────────────────────────────")
        
        self.running = True
        self.start_time = time.time()
        
        while self.running:
            try:
                if not self.observer.is_agent_alive():
                    self.pending_kill = None
                    self.pending_halt = None
                    self.log.info("Agent ended. Warden shutting down.")
                    break

                if self.pending_kill is not None:
                    self.log.warning(
                        "Retrying prior failed KILL without waiting for a new "
                        "observer event."
                    )
                    await self.execute_kill(self.pending_kill, retry=True)
                    if self.killed:
                        break
                    await asyncio.sleep(self.poll_interval)
                    continue

                if self.pending_halt is not None:
                    self.log.warning(
                        "Retrying prior failed HALT without waiting for a new "
                        "observer event."
                    )
                    await self.execute_halt(self.pending_halt, retry=True)
                
                # Check behavioral triggers
                for check in (self._check_rate_limit, self._check_flag_accumulation):
                    v = check()
                    if not v:
                        continue
                    self.all_verdicts.append(v)
                    self.logger.log_action(v)
                    if v.verdict == Verdict.KILL:
                        await self.execute_kill(v)
                        break
                    # Non-kill behavioral signal (e.g. rate spike): record + raise
                    # posture. Never SIGKILL on a rate spike alone.
                    if self._flag_counts_toward_accumulation(v):
                        self.flag_timestamps.append(time.time())
                    self.log.warning(
                        f"⚠️  FLAG [{len(self.flag_timestamps)}/"
                        f"{self.scope.flag_threshold}]: {v.reason}"
                    )
                
                if self.killed:
                    break
                if self.pending_kill is not None:
                    await asyncio.sleep(self.poll_interval)
                    continue
                
                # Observe and evaluate
                actions = self._order_actions_for_enforcement(
                    self.observer.observe()
                )
                for action in actions:
                    if self._action_counts_toward_rate_limit(action):
                        self.action_timestamps.append(time.time())
                    verdict = await self.evaluate_action(action)
                    self.all_verdicts.append(verdict)
                    self.logger.log_action(verdict)
                    
                    if verdict.verdict == Verdict.SAFE:
                        self.log.debug(f"✅ {action.action_type.value}: {action.target[:60]}")
                    elif verdict.verdict == Verdict.FLAG:
                        if self._flag_counts_toward_accumulation(verdict):
                            self.flag_timestamps.append(time.time())
                        self.log.warning(
                            f"⚠️  FLAG [{len(self.flag_timestamps)}/"
                            f"{self.scope.flag_threshold}]: "
                            f"{action.action_type.value}: {action.target[:60]}"
                        )
                    elif verdict.verdict == Verdict.HALT:
                        # HALT now has teeth: SIGSTOP the agent (reversible).
                        # Idempotent inside execute_halt. Keep monitoring after
                        # — a held agent can still escalate to KILL.
                        await self.execute_halt(verdict)
                    elif verdict.verdict == Verdict.KILL:
                        await self.execute_kill(verdict)
                        break
                
                if self.killed:
                    break
                
                await asyncio.sleep(self.poll_interval)
                
            except KeyboardInterrupt:
                self.log.info("Warden stopped by operator.")
                break
            except Exception as e:
                self.log.error(f"Loop error: {e}")
                await asyncio.sleep(self.poll_interval)

        # Cancel any in-flight advisory tasks (best-effort, non-enforcing).
        for t in list(self._advisory_tasks):
            t.cancel()

        # Summary
        duration = time.time() - self.start_time
        safe = sum(1 for v in self.all_verdicts if v.verdict == Verdict.SAFE)
        flags = sum(1 for v in self.all_verdicts if v.verdict == Verdict.FLAG)
        halts = sum(1 for v in self.all_verdicts if v.verdict == Verdict.HALT)
        kills = sum(1 for v in self.all_verdicts if v.verdict == Verdict.KILL)

        self.log.info("")
        self.log.info(f"🛡️  Session complete ({duration:.1f}s)")
        self.log.info(f"   Observed: {len(self.all_verdicts)} | "
                      f"Safe: {safe} | Flags: {flags} | Halts: {halts} | "
                      f"Kills: {kills}")
        if self.killed:
            self.log.info("   ⚠️  AGENT WAS TERMINATED")


# ════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════

def find_process_by_name(name: str):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info.get('cmdline', []) or [])
            if name.lower() in cmdline.lower():
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


async def main():
    parser = argparse.ArgumentParser(
        description=(
            "Agent Warden - best-effort user-space polling guard for an agent process tree"
        ),
        epilog=(
            "Reactive polling is not syscall interception or a sandbox. HALT/KILL are signal "
            "attempts. There is no audit-only or confirm mode in 0.1.5."
        ),
    )
    parser.add_argument('--scope', required=True, help='Path to scope YAML')
    parser.add_argument('--agent-pid', type=int, help='Exact agent PID (recommended)')
    parser.add_argument(
        '--agent-name', type=str,
        help='Use the first process whose command line contains this text (can over-match)',
    )
    parser.add_argument('--model', default='qwen3:4b', help='Ollama model (default: qwen3:4b)')
    parser.add_argument(
        '--no-llm', action='store_true',
        help='Disable the localhost Ollama probe and advisory calls',
    )
    parser.add_argument(
        '--poll', type=float, default=0.5,
        help='Poll interval seconds; shorter-lived activity can still be missed (default: 0.5)',
    )
    parser.add_argument('--log-dir', type=str, help='Override log directory')
    parser.add_argument('--verbose', action='store_true', help='Show SAFE actions too')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger("sysmond").setLevel(logging.DEBUG)
    
    agent_pid = args.agent_pid
    if not agent_pid and args.agent_name:
        agent_pid = find_process_by_name(args.agent_name)
        if not agent_pid:
            print(f"❌ No process matching '{args.agent_name}'")
            sys.exit(1)
        print(f"Found: PID {agent_pid}")
    
    if not agent_pid:
        print("❌ Provide --agent-pid or --agent-name")
        sys.exit(1)
    
    try:
        proc = psutil.Process(agent_pid)
        print(f"Target: {' '.join(proc.cmdline()[:3])}")
    except psutil.NoSuchProcess:
        print(f"❌ PID {agent_pid} not found")
        sys.exit(1)
    
    warden = Warden(
        scope_path=args.scope,
        agent_pid=agent_pid,
        poll_interval=args.poll,
        model=args.model,
        log_dir=args.log_dir,
        enable_llm=not args.no_llm,
    )
    
    await warden.run()


def entrypoint() -> int:
    asyncio.run(main())
    return 0


if __name__ == "__main__":
    raise SystemExit(entrypoint())
