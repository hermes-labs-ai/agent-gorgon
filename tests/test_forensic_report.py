from agent_warden.forensic_report import parse_ts


def test_parse_ts_accepts_iso_and_zulu():
    assert parse_ts("2026-01-01T00:00:00+00:00") is not None
    assert parse_ts("2026-01-01T00:00:00Z") is not None


def test_parse_ts_invalid_returns_none():
    assert parse_ts("not-a-timestamp") is None
    assert parse_ts(None) is None
