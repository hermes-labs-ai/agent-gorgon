#!/usr/bin/env python3
"""text2json — wrap raw text into {"text": "..."} JSON on stdout.

Usage:
  cat input.txt | python3 text2json.py
  python3 text2json.py input.txt [--key body] [--pretty]

Input:  any UTF-8 text
Output: {"<key>": "<text>"} (default key: "text")
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(prog="text2json")
    parser.add_argument("path", nargs="?", default=None, help="input file (omit for stdin)")
    parser.add_argument("--key", default="text", help="JSON key for the wrapped text (default: text)")
    parser.add_argument("--pretty", action="store_true", help="pretty-print output")
    args = parser.parse_args()

    raw = Path(args.path).read_text() if args.path else sys.stdin.read()
    payload = {args.key: raw}
    json.dump(payload, sys.stdout, indent=2 if args.pretty else None, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
