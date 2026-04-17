#!/usr/bin/env python3
"""find_tool.py — Discovery engine for the Hermes Labs tool vault.

Reads ~/ai-infra/manifests/*.yaml and returns matching tools with exact,
copy-paste-ready execution syntax. See DISCOVERY_ENGINE_BLUEPRINT.md.

Usage:
  python3 ~/ai-infra/find_tool.py "score a company on EU AI Act"
  python3 ~/ai-infra/find_tool.py "audit" --tag compliance --installed-only
  python3 ~/ai-infra/find_tool.py --category gtm
  python3 ~/ai-infra/find_tool.py --chain "company -> score -> email"
  python3 ~/ai-infra/find_tool.py --list
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "find_tool.py requires PyYAML. Install: pip install pyyaml\n"
    )
    sys.exit(2)


MANIFEST_DIR = Path.home() / "ai-infra" / "manifests"
CHAINS_DIR = Path.home() / "ai-infra" / "chains"

REQUIRED_FIELDS = ("name", "path", "entry", "description")


def load_manifests() -> list[dict[str, Any]]:
    """Load every *.yaml manifest, skipping the template and malformed files."""
    if not MANIFEST_DIR.exists():
        return []

    manifests: list[dict[str, Any]] = []
    for fp in sorted(MANIFEST_DIR.glob("*.yaml")):
        if fp.name.startswith("_"):
            continue
        try:
            data = yaml.safe_load(fp.read_text())
        except yaml.YAMLError as e:
            sys.stderr.write(f"warn: skipping {fp.name}: {e}\n")
            continue
        if not isinstance(data, dict):
            continue
        if any(data.get(f) in (None, "") for f in REQUIRED_FIELDS):
            sys.stderr.write(f"warn: {fp.name} missing required field\n")
            continue
        data["_manifest_path"] = str(fp)
        manifests.append(data)
    return manifests


def score_match(tool: dict[str, Any], query: str) -> float:
    """Heuristic relevance score in [0, 1]. Higher = better match."""
    if not query:
        return 0.0
    q = query.lower().strip()
    q_terms = [t for t in re.split(r"\W+", q) if t]

    tags = [str(t).lower() for t in tool.get("tags", []) or []]
    name = str(tool.get("name", "")).lower()
    desc = str(tool.get("description", "")).lower()
    one_liner = str(tool.get("one_liner", "")).lower()
    when = str(tool.get("when_to_use", "")).lower()
    haystack = " ".join([name, desc, one_liner, when, " ".join(tags)])

    score = 0.0
    if q in tags:
        score += 0.6
    if q in name:
        score += 0.4
    if q in desc or q in one_liner:
        score += 0.3

    matched_terms = sum(1 for t in q_terms if t in haystack)
    if q_terms:
        score += 0.4 * (matched_terms / len(q_terms))

    tag_term_hits = sum(1 for t in q_terms if any(t in tag for tag in tags))
    if q_terms:
        score += 0.2 * (tag_term_hits / len(q_terms))

    return min(score, 1.0)


def filter_tools(
    tools: list[dict[str, Any]],
    *,
    tag: str | None = None,
    category: str | None = None,
    accepts: str | None = None,
    outputs: str | None = None,
    installed_only: bool = False,
    autonomous: bool = True,
) -> list[dict[str, Any]]:
    out = []
    for t in tools:
        if tag and tag.lower() not in [str(x).lower() for x in t.get("tags", []) or []]:
            continue
        if category and str(t.get("category", "")).lower() != category.lower():
            continue
        if accepts and str(t.get("input", {}).get("format", "")).lower() != accepts.lower():
            continue
        if outputs and str(t.get("output", {}).get("format", "")).lower() != outputs.lower():
            continue
        if installed_only and not t.get("dependencies", {}).get("installed", False):
            continue
        if autonomous and t.get("interactive", False):
            continue
        out.append(t)
    return out


def summarize(tool: dict[str, Any], relevance: float | None = None) -> dict[str, Any]:
    deps = tool.get("dependencies", {}) or {}
    inp = tool.get("input", {}) or {}
    outp = tool.get("output", {}) or {}
    summary = {
        "name": tool.get("name"),
        "entry": tool.get("entry"),
        "input_format": inp.get("format"),
        "output_format": outp.get("format"),
        "example": inp.get("example"),
        "example_output": outp.get("example_output"),
        "installed": deps.get("installed", False),
        "interactive": tool.get("interactive", False),
        "tags": tool.get("tags", []),
        "category": tool.get("category"),
        "one_liner": tool.get("one_liner") or tool.get("description"),
    }
    if relevance is not None:
        summary["relevance"] = round(relevance, 3)
    if not deps.get("installed", False) and deps.get("install_command"):
        summary["install_command"] = deps["install_command"]
        summary["auto_fix_safe"] = deps.get("auto_fix_safe", False)
    return summary


def cmd_search(args: argparse.Namespace, tools: list[dict[str, Any]]) -> dict[str, Any]:
    pool = filter_tools(
        tools,
        tag=args.tag,
        category=args.category,
        accepts=args.accepts,
        outputs=args.outputs,
        installed_only=args.installed_only,
        autonomous=args.autonomous,
    )
    if args.query:
        scored = [(score_match(t, args.query), t) for t in pool]
        scored = [(s, t) for s, t in scored if s > 0]
        scored.sort(key=lambda x: x[0], reverse=True)
        matches = [summarize(t, s) for s, t in scored[: args.limit]]
    else:
        matches = [summarize(t) for t in pool[: args.limit]]

    return {
        "query": args.query,
        "filters": {
            "tag": args.tag,
            "category": args.category,
            "accepts": args.accepts,
            "outputs": args.outputs,
            "installed_only": args.installed_only,
            "autonomous": args.autonomous,
        },
        "match_count": len(matches),
        "matches": matches,
        "chain_suggestion": None,
    }


def cmd_chain(chain_str: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Construct a chain by matching each step description to a tool."""
    parts = [p.strip() for p in re.split(r"->|→", chain_str) if p.strip()]
    if not parts:
        return {"error": "empty chain", "chain": []}

    by_name = {str(t.get("name", "")).lower(): t for t in tools}
    steps: list[dict[str, Any]] = []
    warnings: list[str] = []

    for i, desc in enumerate(parts, 1):
        candidate = by_name.get(desc.lower())
        if candidate is None:
            scored = [(score_match(t, desc), t) for t in tools]
            scored = [(s, t) for s, t in scored if s > 0]
            scored.sort(key=lambda x: x[0], reverse=True)
            candidate = scored[0][1] if scored else None

        if candidate is None:
            steps.append({
                "step": i,
                "description": desc,
                "tool": None,
                "error": "no matching tool found",
            })
            warnings.append(f"step {i}: no tool matches '{desc}'")
            continue

        steps.append({
            "step": i,
            "description": desc,
            "tool": candidate.get("name"),
            "entry": candidate.get("entry"),
            "input_format": candidate.get("input", {}).get("format"),
            "output_format": candidate.get("output", {}).get("format"),
        })

    for i in range(len(steps) - 1):
        cur, nxt = steps[i], steps[i + 1]
        out_fmt = cur.get("output_format")
        in_fmt = nxt.get("input_format")
        if out_fmt and in_fmt and out_fmt != in_fmt:
            warnings.append(
                f"step {cur['step']} outputs '{out_fmt}' but step {nxt['step']} expects '{in_fmt}' — "
                f"insert ~/ai-infra/converters/{out_fmt}2{in_fmt}.py"
            )

    return {
        "chain": steps,
        "compatible": not warnings,
        "format_warnings": warnings,
    }


def cmd_list(tools: list[dict[str, Any]]) -> dict[str, Any]:
    by_cat: dict[str, list[str]] = {}
    for t in tools:
        cat = str(t.get("category", "uncategorized"))
        by_cat.setdefault(cat, []).append(str(t.get("name")))
    return {
        "total": len(tools),
        "by_category": {k: sorted(v) for k, v in sorted(by_cat.items())},
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="find_tool.py",
        description="Discovery engine for the Hermes Labs tool vault.",
    )
    p.add_argument("query", nargs="?", default="",
                   help="Natural-language description of what you need.")
    p.add_argument("--tag", help="Filter by tag (exact match).")
    p.add_argument("--category", help="Filter by category (gtm | research | security | ...).")
    p.add_argument("--accepts", help="Filter by input format (json | csv | text | ...).")
    p.add_argument("--outputs", help="Filter by output format.")
    p.add_argument("--installed-only", action="store_true",
                   help="Only return tools whose dependencies.installed == true.")
    p.add_argument("--autonomous", action=argparse.BooleanOptionalAction, default=True,
                   help="Exclude interactive tools (default: true). Use --no-autonomous to include.")
    p.add_argument("--chain", metavar="DESC",
                   help="Find/construct a tool chain. Steps separated by '->' or '→'.")
    p.add_argument("--list", action="store_true",
                   help="List every loaded tool grouped by category.")
    p.add_argument("--limit", type=int, default=10,
                   help="Max number of matches to return (default: 10).")
    p.add_argument("--pretty", action="store_true",
                   help="Pretty-print JSON output (default: compact).")
    return p


def main() -> int:
    args = build_parser().parse_args()
    tools = load_manifests()

    if not tools:
        out = {"error": "no manifests found", "manifest_dir": str(MANIFEST_DIR)}
    elif args.list:
        out = cmd_list(tools)
    elif args.chain:
        out = cmd_chain(args.chain, tools)
    else:
        out = cmd_search(args, tools)

    indent = 2 if args.pretty or sys.stdout.isatty() else None
    print(json.dumps(out, indent=indent, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
