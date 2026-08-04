import json
from datetime import datetime, timedelta, timezone

from agent_warden.forensic_report import Inputs, gather, main, parse_ts


def test_parse_ts_accepts_iso_and_zulu():
    assert parse_ts("2026-01-01T00:00:00+00:00") is not None
    assert parse_ts("2026-01-01T00:00:00Z") is not None


def test_parse_ts_invalid_returns_none():
    assert parse_ts("not-a-timestamp") is None
    assert parse_ts(None) is None


def test_gather_accepts_current_halt_reports_and_preserves_incidents(tmp_path):
    logs = tmp_path / "sysmond"
    incidents = logs / "incidents"
    incidents.mkdir(parents=True)

    now = datetime.now(timezone.utc)
    (incidents / "incident.json").write_text(
        json.dumps({"incident_report": {"generated_at": now.isoformat()}}),
        encoding="utf-8",
    )
    (incidents / "halt.json").write_text(
        json.dumps({"halt_report": {"generated_at": now.isoformat()}}),
        encoding="utf-8",
    )
    (incidents / "stale-halt.json").write_text(
        json.dumps(
            {"halt_report": {"generated_at": (now - timedelta(hours=2)).isoformat()}}
        ),
        encoding="utf-8",
    )

    report = gather(
        Inputs(workspace=tmp_path / "workspace", sysmond_logs=logs, last_hours=1)
    )

    assert report["counts"]["warden_incidents"] == 2
    current_halts = {
        item["halt_report"]["generated_at"]
        for item in report["incidents"]
        if "halt_report" in item
    }
    assert current_halts == {now.isoformat()}


def test_gather_separates_active_controls_from_audit_only_outcomes(tmp_path):
    logs = tmp_path / "sysmond"
    logs.mkdir()
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        {"timestamp": now, "verdict": "KILL", "reason": "legacy active kill"},
        {
            "timestamp": now,
            "verdict": "KILL",
            "reason": "active kill",
            "control_mode": "active",
        },
        {
            "timestamp": now,
            "verdict": "KILL",
            "reason": "audit-only would kill",
            "control_mode": "audit_only",
        },
        {
            "timestamp": now,
            "verdict": "HALT",
            "reason": "active halt",
            "control_mode": "active",
        },
        {
            "timestamp": now,
            "verdict": "HALT",
            "reason": "audit-only would halt",
            "control_mode": "audit_only",
        },
    ]
    (logs / "actions_test.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )

    report = gather(
        Inputs(workspace=tmp_path / "workspace", sysmond_logs=logs, last_hours=1)
    )

    assert report["counts"]["warden_kill_events"] == 2
    assert report["counts"]["warden_would_kill_events"] == 1
    assert report["highlights"]["recent_kill_reasons"] == [
        "legacy active kill",
        "active kill",
    ]
    assert report["highlights"]["recent_would_kill_reasons"] == [
        "audit-only would kill"
    ]
    assert report["counts"]["warden_halt_events"] == 1
    assert report["counts"]["warden_would_halt_events"] == 1
    assert report["highlights"]["recent_halt_reasons"] == ["active halt"]
    assert report["highlights"]["recent_would_halt_reasons"] == [
        "audit-only would halt"
    ]


def test_cli_prints_json_without_creating_an_openclaw_report(monkeypatch, tmp_path, capsys):
    logs = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    logs.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent-gorgon-forensic",
            "--workspace",
            str(workspace),
            "--sysmond-logs",
            str(logs),
        ],
    )

    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["warden_actions"] == 0
    assert not (workspace / "security").exists()


def test_cli_writes_private_report_when_out_is_explicit(monkeypatch, tmp_path, capsys):
    logs = tmp_path / "evidence"
    logs.mkdir()
    out = tmp_path / "private" / "report.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent-gorgon-forensic",
            "--workspace",
            str(tmp_path / "workspace"),
            "--sysmond-logs",
            str(logs),
            "--out",
            str(out),
        ],
    )

    assert main() == 0
    assert capsys.readouterr().out.strip() == str(out)
    assert out.exists()
    assert out.stat().st_mode & 0o777 == 0o600
    assert out.parent.stat().st_mode & 0o777 == 0o700


def test_cli_does_not_chmod_existing_output_directory(monkeypatch, tmp_path, capsys):
    logs = tmp_path / "evidence"
    logs.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    out = shared / "report.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent-gorgon-forensic",
            "--workspace",
            str(tmp_path / "workspace"),
            "--evidence-dir",
            str(logs),
            "--out",
            str(out),
        ],
    )

    assert main() == 0
    assert capsys.readouterr().out.strip() == str(out)
    assert out.stat().st_mode & 0o777 == 0o600
    assert shared.stat().st_mode & 0o777 == 0o755
