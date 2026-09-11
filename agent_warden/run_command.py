"""``agent-gorgon run`` -- launch a command and watch the process tree it creates.

The historical CLI only accepts an already-running ``--agent-pid``, so watching a
real agent session means finding its PID by hand first. This subcommand removes
that step: it spawns the command itself, uses the spawned PID as the root of the
watched tree, forwards the command's exit status, and writes the same evidence
JSONL the PID mode writes.

Safety posture:

* **Audit-only is the default.** Active SIGSTOP/SIGKILL controls require an
  explicit ``--enforce``; nothing here changes the kill path itself.
* **The command is never run unwatched.** If the scope fails to load or the
  watcher cannot start, the spawned command is terminated instead of being left
  running without a monitor.
* **The child gets its own process group** so terminal signals reach it and not
  the watcher. When stdin is a TTY the child's group is made the foreground
  group, which is what keeps interactive agents usable under the wrapper.
* **A signal never leaves a stopped child.** Every relay and the exit path send
  SIGCONT before anything else, so a HALTed tree cannot be orphaned in
  ``STATUS_STOPPED``.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import psutil

from .warden import (
    Scope,
    Verdict,
    Warden,
    _open_private_text,
    _positive_finite_float,
    resolve_scope_path,
)

#: Seconds to wait for the command to exit after a relayed SIGINT/SIGTERM
#: before the watcher stops watching and returns.
DEFAULT_SHUTDOWN_GRACE = 10.0

_EXIT_COMMAND_NOT_FOUND = 127
_EXIT_COMMAND_NOT_EXECUTABLE = 126

_SIGNAL_NAMES = {
    int(signal.SIGINT): "SIGINT",
    int(signal.SIGTERM): "SIGTERM",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the ``agent-gorgon run`` parser (options only; the command follows ``--``)."""
    parser = argparse.ArgumentParser(
        prog="agent-gorgon run",
        description=(
            "Launch a command and watch its process tree with Agent Gorgon. "
            "Audit-only by default: verdicts are recorded and no SIGSTOP or "
            "SIGKILL is sent unless --enforce is given."
        ),
        epilog=(
            "Separate Agent Gorgon options from the watched command with '--', e.g. "
            "`agent-gorgon run --scope starter -- python3 my_agent.py`. "
            "Reactive polling is not syscall interception or a sandbox; activity "
            "shorter than --poll can still be missed."
        ),
    )
    parser.add_argument(
        "--scope",
        default="starter",
        help=(
            "Path to scope YAML, or a packaged scope name: 'coding-agent' for a "
            "coding-agent starter, 'starter' for the low-disruption scope "
            "(default: starter)"
        ),
    )
    control = parser.add_mutually_exclusive_group()
    control.add_argument(
        "--audit-only",
        action="store_true",
        help="Record verdicts without sending SIGSTOP or SIGKILL (default)",
    )
    control.add_argument(
        "--enforce",
        action="store_true",
        help=(
            "Enable active controls: HALT sends SIGSTOP and KILL sends SIGKILL "
            "to the watched tree. Review the scope in audit-only first."
        ),
    )
    parser.add_argument(
        "--out",
        type=str,
        help=(
            "Write the action evidence JSONL to this path (overwritten at start, "
            "created 0600). Incident reports and warden.log still go to --log-dir."
        ),
    )
    parser.add_argument("--log-dir", type=str, help="Override the evidence directory")
    parser.add_argument(
        "--poll",
        type=_positive_finite_float,
        default=0.5,
        help="Poll interval seconds (default: 0.5)",
    )
    parser.add_argument("--model", default="qwen3:4b", help="Ollama model (default: qwen3:4b)")
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable the localhost Ollama probe and advisory calls",
    )
    parser.add_argument(
        "--shutdown-grace",
        type=_positive_finite_float,
        default=DEFAULT_SHUTDOWN_GRACE,
        help=(
            "Seconds to wait for the command to exit after a relayed "
            f"SIGINT/SIGTERM (default: {DEFAULT_SHUTDOWN_GRACE:g})"
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Show SAFE actions too")
    return parser


def split_argv(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split ``run`` arguments into watcher options and the watched command.

    The first bare ``--`` separates them, so the watched command keeps its own
    flags verbatim.
    """
    items = list(argv)
    if "--" not in items:
        return items, []
    index = items.index("--")
    return items[:index], items[index + 1:]


def _child_process_group(child: subprocess.Popen) -> int | None:
    """Return the child's process group id, or None if it already exited."""
    try:
        return os.getpgid(child.pid)
    except (ProcessLookupError, PermissionError, OSError):
        return None


def _signal_group(pgid: int | None, sig: int) -> None:
    """Best-effort signal to a process group; a vanished group is not an error."""
    if pgid is None:
        return
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _resume_and_signal(pgid: int | None, sig: int) -> None:
    """SIGCONT first, then relay ``sig``.

    A SIGSTOPed process cannot act on SIGTERM until it is continued, so relaying
    without the SIGCONT is how wrappers leave stopped orphans behind.
    """
    _signal_group(pgid, signal.SIGCONT)
    _signal_group(pgid, sig)


class _TerminalForeground:
    """Give the watched command the controlling terminal, then take it back.

    Without this the command runs in a background process group and an
    interactive agent cannot read stdin. Every step is best-effort: when stdin
    is not a TTY (CI, pipelines) this is a no-op.
    """

    def __init__(self, pgid: int | None) -> None:
        self._pgid = pgid
        self._fd: int | None = None
        self._previous: int | None = None

    def __enter__(self) -> _TerminalForeground:
        if self._pgid is None:
            return self
        try:
            if not sys.stdin.isatty():
                return self
            fd = sys.stdin.fileno()
            self._previous = os.tcgetpgrp(fd)
            self._set_foreground(fd, self._pgid)
            self._fd = fd
        except (OSError, ValueError, AttributeError):
            self._fd = None
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._fd is None or self._previous is None:
            return
        try:
            self._set_foreground(self._fd, self._previous)
        except (OSError, ValueError):
            pass

    @staticmethod
    def _set_foreground(fd: int, pgid: int) -> None:
        # tcsetpgrp from a background group raises SIGTTOU at ourselves.
        handler = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        try:
            os.tcsetpgrp(fd, pgid)
        finally:
            signal.signal(signal.SIGTTOU, handler)


class _ShutdownState:
    """Tracks a relayed shutdown signal so the exit code can reflect it."""

    def __init__(self) -> None:
        self.signum: int | None = None

    @property
    def requested(self) -> bool:
        return self.signum is not None


def _spawn(command: list[str]) -> subprocess.Popen:
    """Spawn the watched command in its own process group, inheriting stdio."""
    # setpgrp (not setsid): a new process group in the SAME session, so the
    # command keeps the controlling terminal and can still be made foreground.
    return subprocess.Popen(command, preexec_fn=os.setpgrp)


def inherited_stdio_paths() -> dict[int, str]:
    """Map our own stdio fds to real files so the child is not blamed for them.

    `agent-gorgon run ... > session.log` hands the watched command fd 1 pointing
    at the operator's own log file. Without this the watcher reports that write
    as out-of-workspace activity by the agent. Only regular files appear here; a
    TTY or pipe has nothing to attribute.
    """
    mapping: dict[int, str] = {}
    try:
        for handle in psutil.Process().open_files():
            fd = getattr(handle, "fd", None)
            path = getattr(handle, "path", None)
            if fd in (0, 1, 2) and path:
                try:
                    mapping[fd] = os.path.realpath(path)
                except OSError:
                    mapping[fd] = path
    except (psutil.Error, OSError):
        return {}
    return mapping


def _terminate_unwatched(child: subprocess.Popen, pgid: int | None) -> None:
    """Stop a command we spawned but cannot watch. Never leave it running blind."""
    _resume_and_signal(pgid, signal.SIGTERM)
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _signal_group(pgid, signal.SIGKILL)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _redirect_action_log(warden: Warden, out: str) -> Path:
    """Point the action JSONL at an explicit path, truncated and 0600."""
    path = Path(out).expanduser()
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    with _open_private_text(path, "w"):
        pass
    warden.logger.action_log_path = path
    return path


def summary_line(warden: Warden, evidence_path: Path, exit_code: int | None) -> str:
    """One-line, machine-greppable session summary."""
    counts = {verdict: 0 for verdict in Verdict}
    for recorded in warden.all_verdicts:
        counts[recorded.verdict] = counts.get(recorded.verdict, 0) + 1
    prefix = "would-" if warden.audit_only else ""
    exit_text = "unknown (command still running)" if exit_code is None else str(exit_code)
    return (
        "agent-gorgon run: "
        f"mode={'audit-only' if warden.audit_only else 'enforce'} "
        f"exit={exit_text} "
        f"observed={len(warden.all_verdicts)} "
        f"safe={counts[Verdict.SAFE]} "
        f"flags={counts[Verdict.FLAG]} "
        f"{prefix}halt={counts[Verdict.HALT]} "
        f"{prefix}kill={counts[Verdict.KILL]} "
        f"evidence={evidence_path}"
    )


def _exit_status(returncode: int | None, state: _ShutdownState) -> int:
    """POSIX-shaped exit status: signal deaths become 128+N."""
    if returncode is None:
        return 128 + (state.signum or 0) if state.requested else 1
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


async def _wait_for_child(child: subprocess.Popen, timeout: float) -> int | None:
    """Reap the child without blocking the event loop."""
    loop = asyncio.get_running_loop()

    def _wait() -> int | None:
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    return await loop.run_in_executor(None, _wait)


async def _watch(args: argparse.Namespace, command: list[str], scope_path: str) -> int:
    stdio = inherited_stdio_paths()
    try:
        child = _spawn(command)
    except FileNotFoundError:
        print(f"agent-gorgon run: command not found: {command[0]}", file=sys.stderr)
        return _EXIT_COMMAND_NOT_FOUND
    except (PermissionError, OSError) as exc:
        print(f"agent-gorgon run: cannot execute {command[0]}: {exc}", file=sys.stderr)
        return _EXIT_COMMAND_NOT_EXECUTABLE
    pgid = _child_process_group(child)
    state = _ShutdownState()

    try:
        warden = Warden(
            scope_path=scope_path,
            agent_pid=child.pid,
            poll_interval=args.poll,
            model=args.model,
            log_dir=args.log_dir,
            enable_llm=not args.no_llm,
            audit_only=not args.enforce,
            inherited_stdio=stdio,
        )
    except Exception as exc:  # noqa: BLE001 -- never leave the command unwatched
        _terminate_unwatched(child, pgid)
        print(f"agent-gorgon run: could not start the watcher: {exc}", file=sys.stderr)
        return 1

    evidence_path = (
        _redirect_action_log(warden, args.out) if args.out else warden.logger.action_log_path
    )
    if args.verbose:
        warden.log.setLevel(logging.DEBUG)

    loop = asyncio.get_running_loop()

    def _on_signal(signum: int) -> None:
        name = _SIGNAL_NAMES.get(signum, str(signum))
        if state.signum is None:
            state.signum = signum
        print(
            f"agent-gorgon run: received {name}; relaying to the watched command",
            file=sys.stderr,
        )
        _resume_and_signal(_child_process_group(child), signum)
        loop.create_task(_stop_after_grace(warden, child, args.shutdown_grace))

    async def _stop_after_grace(
        watcher: Warden, proc: subprocess.Popen, grace: float
    ) -> None:
        await asyncio.sleep(grace)
        if proc.poll() is None:
            print(
                "agent-gorgon run: the watched command is still running after "
                f"{grace:g}s; stopping the watcher and leaving it alone",
                file=sys.stderr,
            )
        watcher.running = False

    installed = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal, int(sig))
            installed.append(sig)
        except (NotImplementedError, RuntimeError, ValueError):
            pass

    returncode: int | None = None
    try:
        with _TerminalForeground(pgid):
            await warden.run()
            returncode = await _wait_for_child(child, timeout=args.shutdown_grace)
    finally:
        for sig in installed:
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
        # A watcher that exits must never leave a SIGSTOPed tree behind.
        if child.poll() is None:
            _signal_group(_child_process_group(child), signal.SIGCONT)

    print(summary_line(warden, evidence_path, returncode), file=sys.stderr)
    return _exit_status(returncode, state)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``agent-gorgon run`` (argv excludes the ``run`` token)."""
    raw = list(sys.argv[1:] if argv is None else argv)
    own, command = split_argv(raw)
    parser = build_parser()
    args = parser.parse_args(own)

    if not command:
        parser.error(
            "provide the command to watch after '--', e.g. "
            "`agent-gorgon run --audit-only -- python3 my_agent.py`"
        )

    try:
        scope_path = resolve_scope_path(args.scope)
        Scope(scope_path)
    except (OSError, ValueError) as exc:
        parser.error(f"--scope: {exc}")

    return asyncio.run(_watch(args, command, scope_path))


if __name__ == "__main__":
    raise SystemExit(main())
