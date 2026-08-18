#!/usr/bin/env python3
"""Generate consolidated incident/liability report from Warden + Canary logs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

UTC = timezone.utc


def parse_ts(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        return None


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Inputs:
    workspace: Path
    sysmond_logs: Path
    last_hours: int


def gather(inp: Inputs) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(hours=inp.last_hours)

    action_files = sorted(Path(inp.sysmond_logs).glob("actions_*.jsonl"))
    incident_files = sorted((Path(inp.sysmond_logs) / "incidents").glob("*.json"))
    canary_audit = inp.workspace / "security" / "canary-audit.jsonl"
    canary_alerts = inp.workspace / "security" / "canary-alerts.jsonl"

    actions: list[dict[str, Any]] = []
    for f in action_files:
        for row in read_jsonl(f):
            ts = parse_ts(row.get("timestamp") or row.get("ts"))
            if ts and ts >= since:
                row["_source"] = str(f)
                actions.append(row)

    canary_rows = []
    for row in read_jsonl(canary_audit):
        ts = parse_ts(row.get("ts"))
        if ts and ts >= since:
            row["_source"] = str(canary_audit)
            canary_rows.append(row)

    canary_alert_rows = []
    for row in read_jsonl(canary_alerts):
        ts = parse_ts(row.get("ts"))
        if ts and ts >= since:
            row["_source"] = str(canary_alerts)
            canary_alert_rows.append(row)

    incidents = []
    for f in incident_files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
            ts = None
            for report_key in ("incident_report", "halt_report"):
                report = doc.get(report_key)
                if isinstance(report, dict):
                    ts = parse_ts(report.get("generated_at"))
                    if ts:
                        break
            if ts and ts >= since:
                doc["_source"] = str(f)
                incidents.append(doc)
        except Exception:
            continue

    evidence_files = [*action_files, canary_audit, canary_alerts, *incident_files]
    evidence = []
    for f in evidence_files:
        if f.exists():
            evidence.append({"path": str(f), "sha256": file_sha256(f)})

    kill_actions = [
        action
        for action in actions
        if action.get("verdict") == "KILL"
        and action.get("control_mode", "active") != "audit_only"
    ]
    would_kill_actions = [
        action
        for action in actions
        if action.get("verdict") == "KILL"
        and action.get("control_mode") == "audit_only"
    ]
    halt_actions = [
        action
        for action in actions
        if action.get("verdict") == "HALT"
        and action.get("control_mode", "active") != "audit_only"
    ]
    would_halt_actions = [
        action
        for action in actions
        if action.get("verdict") == "HALT"
        and action.get("control_mode") == "audit_only"
    ]

    return {
        "window_hours": inp.last_hours,
        "since": since.isoformat(),
        "counts": {
            "warden_actions": len(actions),
            "warden_incidents": len(incidents),
            "canary_audit_events": len(canary_rows),
            "canary_alerts": len(canary_alert_rows),
            "warden_kill_events": len(kill_actions),
            "warden_would_kill_events": len(would_kill_actions),
            "warden_halt_events": len(halt_actions),
            "warden_would_halt_events": len(would_halt_actions),
        },
        "highlights": {
            "recent_kill_reasons": [a.get("reason") for a in kill_actions[:10]],
            "recent_would_kill_reasons": [a.get("reason") for a in would_kill_actions[:10]],
            "recent_halt_reasons": [a.get("reason") for a in halt_actions[:10]],
            "recent_would_halt_reasons": [a.get("reason") for a in would_halt_actions[:10]],
            "recent_canary_blocks": [r.get("summary") for r in canary_rows if r.get("safe") is False][:10],
        },
        "evidence_manifest": evidence,
        "incidents": incidents,
        "sample_actions": actions[-50:],
        "sample_canary_alerts": canary_alert_rows[-50:],
    }


def _write_private_json(path: Path, report: dict[str, Any]) -> None:
    """Write a report without exposing sensitive evidence to other local users."""
    try:
        path.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError:
        # Never change permissions on an operator-selected existing directory.
        pass
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if parent_mode & 0o022:
        raise PermissionError(
            f"Refusing to write sensitive evidence in group/world-writable directory: "
            f"{path.parent}"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f"Forensic output must be a regular file: {path}")
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    path.chmod(0o600)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Summarize Agent Gorgon evidence from an explicit log directory."
    )
    ap.add_argument(
        "--workspace",
        default=str(Path.cwd()),
        help="Optional workspace containing security/canary logs (default: current directory)",
    )
    ap.add_argument(
        "--evidence-dir",
        "--sysmond-logs",
        dest="sysmond_logs",
        default=str(Path.home() / ".local" / "share" / "agent-gorgon" / "logs"),
        help="Directory containing actions_*.jsonl and incidents/",
    )
    ap.add_argument("--last-hours", type=int, default=24)
    ap.add_argument(
        "--out",
        default=None,
        help="Write private JSON to this path; without --out, print JSON to stdout",
    )
    args = ap.parse_args()

    inp = Inputs(workspace=Path(args.workspace), sysmond_logs=Path(args.sysmond_logs), last_hours=args.last_hours)
    report = gather(inp)

    if args.out:
        out_path = Path(args.out)
        _write_private_json(out_path, report)
        print(str(out_path))
    else:
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
