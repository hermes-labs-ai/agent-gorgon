#!/usr/bin/env python3
"""json2text — extract a text field from JSON on stdout.

Usage:
  cat data.json | python3 json2text.py [--key text] [--separator '\\n---\\n']
  python3 json2text.py data.json --key body

Input:  JSON object {"<key>": "..."} OR array of such objects
Output: raw text. For arrays, joins with --separator (default: blank line).
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path


def extract(item, key: str) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        if key in item:
            v = item[key]
            return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        # Fallback: pick the first string-valued field
        for v in item.values():
            if isinstance(v, str):
                return v
        return json.dumps(item, ensure_ascii=False)
    return json.dumps(item, ensure_ascii=False)


def main() -> int:
    parser = argparse.ArgumentParser(prog="json2text")
    parser.add_argument("path", nargs="?", default=None)
    parser.add_argument("--key", default="text", help="field name to extract (default: text)")
    parser.add_argument("--separator", default="\n\n", help="separator for arrays (default: blank line)")
    args = parser.parse_args()

    raw = Path(args.path).read_text() if args.path else sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    items = payload if isinstance(payload, list) else [payload]
    pieces = [extract(it, args.key) for it in items]
    sys.stdout.write(args.separator.join(pieces))
    if not pieces or not pieces[-1].endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
