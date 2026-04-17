#!/usr/bin/env python3
"""csv2json — convert CSV to a JSON array of objects on stdout.

Usage:
  cat data.csv | python3 csv2json.py
  python3 csv2json.py data.csv [--pretty]

Input:  CSV with header row
Output: JSON array of objects
"""
from __future__ import annotations
import csv
import io
import json
import sys
from pathlib import Path


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    pretty = "--pretty" in sys.argv[1:]
    raw = Path(args[0]).read_text() if args else sys.stdin.read()
    reader = csv.DictReader(io.StringIO(raw))
    rows = list(reader)
    json.dump(rows, sys.stdout, indent=2 if pretty else None, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
