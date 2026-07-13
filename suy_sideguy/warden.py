"""
Suy Sideguy - Outbound Agent Security Monitor
==============================================
Monitors AI agent behavior in real-time and can terminate high-risk agent sessions.
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
import json
import os
import sys
import time
import shlex
import fnmatch
import logging
import argparse
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
                f"({sorted(_present_flat)}); suy-sideguy reads a NESTED schema "
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
        import socket

        domain = domain.lower().strip()

        # Localhost is always safe (IPC, Ollama, etc.)
        if domain in ("127.0.0.1", "::1", "localhost"):
            return Verdict.SAFE, f"Localhost connection: {domain}:{port}"

        # If it looks like a raw IP, try reverse DNS to get a hostname
        is_ip = all(c.isdigit() or c == "." or c == ":" for c in domain)
        if is_ip:
            try:
                resolved = socket.gethostbyaddr(domain)[0].lower()
            except Exception:
                resolved = domain
        else:
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
                                  all_verdicts: list) -> str:
        
        report_path = self.incident_dir / f"incident_{self.session_id}_{int(time.time())}.json"
        
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
        
        report = {
            "incident_report": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "Suy Sideguy v0.1.2",
                "session_id": self.session_id,
                "status": "AGENT_TERMINATED"
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
                    "This report was generated automatically by Suy Sideguy, "
                    "an autonomous AI agent security monitor. The monitored agent "
                    "was terminated due to detected behavioral deviation from its "
                    "authorized scope. All actions listed in the timeline were "
                    "observed and logged in real-time. This document may be used "
                    "as evidence that the agent's actions were unauthorized and "
                    "that automated countermeasures were active."
                ),
                "agent_process_terminated": True,
                "termination_method": "SIGKILL",
                "rollback_attempted": True,
                "rollback_details": None
            }
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return str(report_path)

    def generate_halt_report(self, halt_verdict: WardenVerdict,
                             all_verdicts: list, suspend_result: dict) -> str:
        """Forensic record for a HALT suspension attempt."""
        report_path = (
            self.incident_dir / f"halt_{self.session_id}_{int(time.time())}.json"
        )
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
                "generator": "Suy Sideguy v0.1.2",
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
                    "This report was generated automatically by Suy Sideguy, "
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
        children mid-suspend; already-enumerated children are stopped next.
        Fail-open per child so one gone/denied pid cannot abort the pause."""
        suspended = False
        pids_suspended: list[int] = []
        errors: list[str] = []

        try:
            parent = psutil.Process(self.agent_pid)
            children = parent.children(recursive=True)

            try:
                parent.suspend()
                pids_suspended.append(self.agent_pid)
                suspended = True
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                errors.append(f"Agent {self.agent_pid}: {e}")

            for child in children:
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
        """Concrete directory roots to snapshot: the literal prefix of each
        allowed_paths glob. Skip the filesystem root ('/**' -> '/') — snapshotting
        the whole filesystem every poll is never the intent and would melt.

        De-dup by realpath so a symlink alias (e.g. macOS '/tmp' -> '/private/tmp'
        listed as two allowed_paths) doesn't get walked twice, which would
        double-count every FS event and effectively halve the HALT threshold. The
        ORIGINAL (non-resolved) path string is kept for the walk so emitted paths
        still match the un-resolved allowed_paths patterns in check_filesystem."""
        if scope is None:
            return []
        roots: list[str] = []
        seen_real: set[str] = set()
        for pat in getattr(scope, "allowed_paths", []) or []:
            root = self._literal_dir_prefix(pat)
            if not root or root == os.sep:
                continue
            try:
                real = os.path.realpath(root)
            except OSError:
                real = root
            if real in seen_real or root in roots:
                continue
            seen_real.add(real)
            roots.append(root)
        return roots

    def _snapshot_scope_files(self) -> tuple[set[str], bool]:
        """Walk the scope roots and return (set-of-file-paths, capped?).
        try/except per directory so one unreadable/vanished dir cannot crash the
        warden (fail-open — the 'don't crash the warden' constraint). Bails with
        capped=True once past the file cap instead of exhausting memory."""
        found: set[str] = set()
        stack: list[str] = list(self._scope_roots)
        seen_dirs: set[str] = set()
        while stack:
            d = stack.pop()
            if d in seen_dirs:
                continue
            seen_dirs.add(d)
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        try:
                            # follow_symlinks=False avoids symlink cycles and
                            # double-walking the /tmp -> /private/tmp alias.
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            else:
                                found.add(entry.path)
                                if len(found) > self._snapshot_file_cap:
                                    return found, True
                        except OSError:
                            continue  # per-entry stat failure → skip, keep going
            except OSError:
                continue  # per-dir failure (missing/permission) → fail-open
        return found, False

    def _diff_scope_filesystem(self, now: str, actions: list[AgentAction]) -> None:
        """Snapshot the scope roots and emit synthetic create/delete actions from
        the set-diff vs the previous snapshot. These observations are deliberately
        unattributed: a directory snapshot cannot identify the process that made
        a change. The first (baseline) poll emits nothing. Fully fail-open."""
        if not self._scope_roots:
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
                         "file_cap": self._snapshot_file_cap},
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
                            try:
                                cmdline = ' '.join(child.cmdline())
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                cmdline = "unknown"
                            actions.append(AgentAction(
                                timestamp=now,
                                action_type=ActionType.PROCESS_EXEC,
                                target=cmdline,
                                details={"child_pid": child.pid},
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
                 log_dir: str | None = None):

        self.scope = Scope(scope_path)
        self.observer = ProcessObserver(agent_pid, scope=self.scope)
        self.judge = LLMJudge(model=model)
        self.killswitch = Killswitch(agent_pid)
        self.logger = IncidentLogger(log_dir=log_dir)
        
        self.agent_pid = agent_pid
        self.poll_interval = poll_interval
        
        self.all_verdicts: list = []
        self.flag_timestamps: list = []
        self.action_timestamps: list = []
        self.delete_timestamps: list = []
        self.network_out_timestamps: list = []
        self.start_time = time.time()
        self.running = False
        self.killed = False
        # HALT gives a *reversible* pause (SIGSTOP). Signal the tree ONCE, then
        # only log on later HALTs — no per-poll signal spam.
        self.suspended = False
        # ADVISORY LLM state. The judge runs OFF the enforcement hot path
        # (fire-and-forget), so a slow/hanging model can never open a blind
        # window on the monitor. Its output only lands here (posture + forensics)
        # and can NEVER kill or suspend.
        self.advisories: list = []
        self._advisory_tasks: set = set()
        # Per-pid recent credential-read timestamps; arms the deterministic
        # credential-read-then-network-out exfil KILL rule (defense-in-depth).
        self.credential_reads: dict[int | None, list[float]] = {}
        # Window (s) within which a credential read followed by a network-out is
        # treated as exfil. Short by design; overridable via scope behavior.
        self.cred_exfil_window = float(
            self.scope.behavior.get("credential_exfil_window", 15)
        )

        self.scope_summary = self._build_scope_summary()
        
        # Non-obvious log location and process identity
        os.makedirs(os.path.expanduser("~/.local/share/sysmond"), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(
                    os.path.expanduser("~/.local/share/sysmond/warden.log")
                )
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
    def _forbidden_path_root(pattern: str) -> str:
        """The concrete directory root of a forbidden_path glob. A CONTENTS glob
        like `~/.ssh/**` protects everything *inside* ~/.ssh but not the ~/.ssh
        directory itself — deleting the whole directory is at least as dangerous.
        Strip the trailing glob segments to recover the protected root
        (`~/.ssh/**` -> `~/.ssh`, `/data/*/secret` -> `/data`)."""
        expanded = os.path.expandvars(os.path.expanduser(pattern.strip()))
        kept: list[str] = []
        for seg in expanded.split(os.sep):
            if any(ch in seg for ch in "*?["):
                break
            kept.append(seg)
        root = os.sep.join(kept)
        return os.path.normpath(root) if root else ""

    @staticmethod
    def _path_covers(a: str, b: str) -> bool:
        """True if a == b or a is an ancestor of b (a contains b)."""
        if a == b:
            return True
        return b.startswith(a.rstrip(os.sep) + os.sep)

    def _is_protected_root(self, path: str) -> bool:
        """A recursive delete of this path is catastrophic and non-recoverable:
        filesystem root, the user's home directory, or a scope forbidden_path
        (its contents, the dir itself, OR an ancestor that contains it — deleting
        a directory that CONTAINS credentials is as dangerous as deleting them).
        Non-protected project paths (node_modules, build/, dist, .venv,
        __pycache__) are NOT protected."""
        raw = path.strip()
        if raw in ("~", "$HOME", "${HOME}"):
            return True
        expanded = os.path.expandvars(os.path.expanduser(raw))
        normed = os.path.normpath(expanded)

        # Filesystem root
        if normed == os.sep:
            return True
        # Home directory itself (but NOT subdirectories of it)
        home = os.path.normpath(os.path.expanduser("~"))
        if normed == home:
            return True

        # Scope-declared forbidden paths. Kill if the target equals, is UNDER, or
        # is an ANCESTOR of any forbidden root. Match both the given (possibly
        # relative) form and its absolute form.
        targets = {normed}
        if not os.path.isabs(normed):
            targets.add(os.path.normpath(os.path.abspath(normed)))
        for pat in self.scope.forbidden_paths:
            root = self._forbidden_path_root(pat)
            if not root or root == os.sep:
                continue
            for tgt in targets:
                # target is under/equal-to the forbidden root (deleting content),
                # or target is an ancestor of it (deleting the container).
                if self._path_covers(root, tgt) or self._path_covers(tgt, root):
                    return True
        return False

    def _rm_rf_protected_target(self, command: str) -> str | None:
        """If `command` is a recursive rm whose target is a protected root,
        return that target (→ KILL). Otherwise None. Routine recursive deletes
        of project directories are intentionally allowed to fall through to a
        FLAG at most — they are not proof of harm. Unwrap a shell ``-c`` payload
        first so an allowed shell cannot bypass this deterministic protection."""
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        if not tokens:
            return None

        base_cmd = os.path.basename(tokens[0])
        if base_cmd in {"bash", "dash", "ksh", "sh", "zsh"}:
            for index, token in enumerate(tokens[1:], start=1):
                if (token.startswith("-") and not token.startswith("--")
                        and "c" in token[1:]):
                    payload = " ".join(tokens[index + 1:])
                    return self._rm_rf_protected_target(payload) if payload else None
            return None
        if base_cmd != "rm":
            return None

        recursive = False
        path_args = []
        for tok in tokens[1:]:
            if tok == "--":
                continue
            if tok.startswith("--"):
                if tok == "--recursive":
                    recursive = True
                continue
            if tok.startswith("-") and len(tok) > 1:
                # short-flag cluster, e.g. -rf / -fr / -Rf / -r
                if "r" in tok[1:] or "R" in tok[1:]:
                    recursive = True
                continue
            path_args.append(tok)

        if not recursive:
            return None
        for p in path_args:
            if self._is_protected_root(p):
                return p
        return None

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
        """Record credential reads per pid; on a NETWORK_OUT that FOLLOWS a
        credential read within ``cred_exfil_window`` seconds, return KILL — the
        real exfil signature (read a secret, then ship it out).

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

        if (action.action_type == ActionType.FILE_READ
                and self._is_credential_target(action.target)):
            self.credential_reads.setdefault(action.source_pid, []).append(now)
            return None

        if action.action_type == ActionType.NETWORK_OUT and self.credential_reads:
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

    def _check_hardcoded_kill(self, action: AgentAction) -> WardenVerdict | None:
        """Hardcoded KILL rules for critical threats."""
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
            protected = self._rm_rf_protected_target(action.target)
            if protected is not None:
                return WardenVerdict(
                    verdict=Verdict.KILL,
                    reason=f"rm -rf targeting protected root: {protected}",
                    action=action, evaluator="rule_engine"
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
        # credential-read-then-network-out exfil KILL. Runs first so a
        # network-out that follows a credential touch is caught BEFORE the
        # (benign) localhost / allowed-domain network check would clear it.
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
            det_verdict.reason = reason + " (LLM unavailable)"
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
        self.advisories.append({
            "timestamp": advisory.timestamp,
            "advisory_verdict": verdict.value,
            "reason": advisory.reason,
            "confidence": advisory.confidence,
            "action": advisory.action.to_dict(),
        })
        if verdict == Verdict.FLAG:
            self.log.warning(
                f"🔎 Advisory (raise posture, non-enforcing): {advisory.reason}"
            )
    
    async def execute_halt(self, verdict: WardenVerdict):
        """Give a HALT verdict teeth: SIGSTOP the agent tree — a *reversible*
        pause — then log + write the forensic halt report. Idempotent: the tree
        is signalled ONCE (guarded by self.suspended); later HALTs only log, so
        we never re-signal every poll. The warden keeps monitoring afterwards so
        it can still escalate to KILL (e.g. exfil) while the agent is held."""
        if self.suspended:
            self.log.warning(
                f"🟡 HALT (agent already suspended, no re-signal): {verdict.reason}"
            )
            return

        self.log.warning(f"🟡 HALT: {verdict.reason}")
        self.log.warning(
            f"   Action: {verdict.action.action_type.value} -> "
            f"{verdict.action.target}"
        )
        suspend_result = self.killswitch.suspend_agent()
        pids_suspended = suspend_result.get("pids_suspended", [])
        self.suspended = bool(suspend_result.get("suspended") and pids_suspended)
        suspend_result["suspended"] = self.suspended
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
            report_path = self.logger.generate_halt_report(
                verdict, self.all_verdicts, suspend_result
            )
            self.log.warning(f"   📋 Halt report: {report_path}")
        except Exception as e:  # noqa: BLE001 — never crash the loop on reporting
            self.log.error(f"   Halt report failed: {e}")

    async def execute_kill(self, verdict: WardenVerdict):
        """Full kill sequence: terminate + rollback + forensic report."""
        
        self.log.critical(f"🔴 KILL: {verdict.reason}")
        self.log.critical(f"   Action: {verdict.action.action_type.value} -> {verdict.action.target}")
        
        kill_result = self.killswitch.kill_agent()
        self.log.critical(f"   Agent terminated: {kill_result['killed']}")
        
        rollback_result = self.killswitch.attempt_rollback(verdict.action)
        self.log.info(f"   Rollback: {rollback_result['details']}")
        
        report_path = self.logger.generate_incident_report(verdict, self.all_verdicts)
        
        # Update report with execution details
        with open(report_path, 'r') as f:
            report = json.load(f)
        report["session_summary"]["session_duration_seconds"] = time.time() - self.start_time
        report["liability_statement"]["rollback_details"] = rollback_result
        report["kill_execution"] = kill_result
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log.critical(f"   📋 Report: {report_path}")
        self.killed = True
    
    async def run(self):
        """Main monitoring loop."""
        
        self.log.info("🛡️  Suy Sideguy active")
        self.log.info(f"   PID: {self.agent_pid}")
        self.log.info(f"   Poll: {self.poll_interval}s")
        self.log.info(f"   Agent: {self.scope.config.get('agent', {}).get('name', 'unknown')}")
        
        await self.judge.check_available()
        self.log.info(f"   LLM: {self.judge.model} {'✅' if self.judge.available else '❌ (rules only)'}")
        self.log.info(f"   Log: {self.logger.action_log_path}")
        self.log.info("   ─────────────────────────────")
        
        self.running = True
        self.start_time = time.time()
        
        while self.running:
            try:
                if not self.observer.is_agent_alive():
                    self.log.info("Agent ended. Warden shutting down.")
                    break
                
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
                    self.flag_timestamps.append(time.time())
                    self.log.warning(
                        f"⚠️  FLAG [{len(self.flag_timestamps)}/"
                        f"{self.scope.flag_threshold}]: {v.reason}"
                    )
                
                if self.killed:
                    break
                
                # Observe and evaluate
                for action in self.observer.observe():
                    self.action_timestamps.append(time.time())
                    verdict = await self.evaluate_action(action)
                    self.all_verdicts.append(verdict)
                    self.logger.log_action(verdict)
                    
                    if verdict.verdict == Verdict.SAFE:
                        self.log.debug(f"✅ {action.action_type.value}: {action.target[:60]}")
                    elif verdict.verdict == Verdict.FLAG:
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
        description="Suy Sideguy - AI Agent Security Monitor"
    )
    parser.add_argument('--scope', required=True, help='Path to scope YAML')
    parser.add_argument('--agent-pid', type=int, help='Agent PID')
    parser.add_argument('--agent-name', type=str, help='Find agent by name')
    parser.add_argument('--model', default='qwen3:4b', help='Ollama model (default: qwen3:4b)')
    parser.add_argument('--poll', type=float, default=0.5, help='Poll interval sec')
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
        log_dir=args.log_dir
    )
    
    await warden.run()


def entrypoint() -> int:
    asyncio.run(main())
    return 0


if __name__ == "__main__":
    raise SystemExit(entrypoint())
