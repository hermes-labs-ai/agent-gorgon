#!/usr/bin/env python3
"""json2csv — convert a JSON array of objects to CSV on stdout.

Usage:
  cat data.json | python3 json2csv.py
  python3 json2csv.py data.json

Input:  JSON array of objects with consistent keys (or a single object → 1 row)
Output: CSV with header row, written to stdout
"""
from __future__ import annotations
import csv
import json
import sys
from pathlib import Path


def to_rows(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise SystemExit(f"json2csv: expected JSON array or object, got {type(payload).__name__}")


def collect_fields(rows):
    fields: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit(f"json2csv: row is not an object: {row!r}")
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                fields.append(k)
    return fields


def main() -> int:
    raw = Path(sys.argv[1]).read_text() if len(sys.argv) > 1 else sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    rows = to_rows(payload)
    if not rows:
        return 0
    fields = collect_fields(rows)
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
