#!/usr/bin/env python3
"""Generate consolidated incident/liability report from Warden + Canary logs."""

from __future__ import annotations
import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Any


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
            ts = parse_ts(doc.get("incident_report", {}).get("generated_at"))
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

    return {
        "window_hours": inp.last_hours,
        "since": since.isoformat(),
        "counts": {
            "warden_actions": len(actions),
            "warden_incidents": len(incidents),
            "canary_audit_events": len(canary_rows),
            "canary_alerts": len(canary_alert_rows),
            "warden_kill_events": sum(1 for a in actions if (a.get("verdict") == "KILL")),
        },
        "highlights": {
            "recent_kill_reasons": [a.get("reason") for a in actions if a.get("verdict") == "KILL"][:10],
            "recent_canary_blocks": [r.get("summary") for r in canary_rows if r.get("safe") is False][:10],
        },
        "evidence_manifest": evidence,
        "incidents": incidents,
        "sample_actions": actions[-50:],
        "sample_canary_alerts": canary_alert_rows[-50:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", default=str(Path.home() / ".openclaw" / "workspace"))
    ap.add_argument("--sysmond-logs", default=str(Path.home() / ".local" / "share" / "sysmond" / "logs"))
    ap.add_argument("--last-hours", type=int, default=24)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    inp = Inputs(workspace=Path(args.workspace), sysmond_logs=Path(args.sysmond_logs), last_hours=args.last_hours)
    report = gather(inp)

    out_path = Path(args.out) if args.out else inp.workspace / "security" / f"INCIDENT_REPORT_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
