# Discovery Engine Blueprint — Hermes Labs AI Infrastructure
**Date:** April 16, 2026
**Author:** Agent 0 (coordinator session) + Gemini architectural review
**Purpose:** Enable any Claude Code agent to dynamically discover and chain 170+ tools without context window pollution

---

## Philosophy

- **LLMs for cognition and decision-making.** Python for deterministic state and retrieval.
- **10 primitives always in context.** 160+ specialized tools discovered on demand.
- **Tools don't explain themselves in prompts.** They explain themselves in manifests that a Python script reads.

---

## The 10 Primitives (always in CLAUDE.md)

These are the tools every agent needs to survive. They stay in the base prompt permanently.

| # | Tool | What | Invocation |
|---|------|------|-----------|
| 1 | **supersearch** | Web research, scraping, raw data collection | `cd ~/Documents/projects/supersearch && python3 -m supersearch '<query>' --raw --out=<dir>` |
| 2 | **cogito** | Semantic memory retrieval + storage (1,450+ memories) | `cogito recall "query"` / `cogito add "fact"` / `cogito health` |
| 3 | **himalaya** | Email: read inbox, send, save drafts (rbosch@lpci.ai) | `himalaya envelope list` / `himalaya message save --folder "[Gmail]/Drafts"` |
| 4 | **extract.py** | Linguistic feature extraction (13 dimensions from text) | `sys.path.insert(0, '~/Documents/projects/psychographic-pipeline/src'); from extract import extract_features` |
| 5 | **lintlang** | Static analysis of AI agent configs (H1-H7 + scaffold rules) | `lintlang scan <file> --format json` |
| 6 | **profiles.db** | 792 psychographic profiles of AI industry decision-makers | `sqlite3 ~/Desktop/hermes-labs-gtm-research/profiles.db "SELECT * FROM profiles WHERE name LIKE '%query%'"` |
| 7 | **corpus.db** | 1,338 company entities from GTM research corpus | `sqlite3 ~/Desktop/hermes-labs-gtm-research/corpus.db "SELECT * FROM companies"` |
| 8 | **research-corpus** | 33,480 structured experiment data points across 7 domains | `sqlite3 ~/Documents/projects/research-corpus/results.db "SELECT * FROM results WHERE source LIKE '%query%'"` |
| 9 | **ollama** | Local LLM inference (qwen3.5:0.8b/2b/4b/9b, nomic-embed-text, bge-reranker) | `curl -s http://localhost:11434/api/chat -d '{"model":"qwen3.5:2b","messages":[...],"stream":false}'` |
| 10 | **find_tool.py** | Semantic search over 160+ specialized tools. Returns exact execution syntax. | `python3 ~/ai-infra/find_tool.py "compliance scoring"` |

**Coverage:** research, memory, communication, profiling, analysis, data, inference, self-extension. An agent with these 10 can do anything. The other 160 are accelerators.

---

## Tool Manifest Schema (YAML)

Every tool in the vault gets a manifest file at `~/ai-infra/manifests/{tool-name}.yaml`. This is what `find_tool.py` reads.

```yaml
# Required fields
name: hermes-score                          # unique identifier
path: ~/Documents/projects/hermes-labs-hackathon-2/hermes-score/
entry: python3 -m hermes_score              # exact command, copy-paste ready
description: "EU AI Act compliance scorer. Input company profile, output 0-100 score per Article."
version: "0.1.0"

# Input specification (prevents hallucinated arguments)
input:
  format: json                              # json | csv | text | stdin | file
  schema: '{"company": "str", "vertical": "str", "certifications": ["str"], "eu_exposure": "bool"}'
  accepts_stdin: true                       # can pipe input
  accepts_file: true                        # can pass file path
  accepts_args: "--company <name> --vertical <vertical>"  # exact CLI flags
  example: 'python3 -m hermes_score --company "Corti" --vertical healthcare'

# Output specification (prevents piping mismatches)
output:
  format: json                              # json | csv | text | markdown | file
  schema: '{"overall_score": "int", "article_9": "int", "article_14": "int", "article_15": "int"}'
  writes_stdout: true                       # output goes to stdout
  writes_file: "--output <path>"            # optional file output flag
  example_output: '{"overall_score": 84, "article_9": 18, "article_14": 16, "article_15": 6}'

# Runtime safety
dependencies:
  python: ["pyyaml"]                        # pip packages needed
  system: []                                # brew/system packages needed
  services: []                              # running services needed (e.g., "ollama", "cogito-server")
  installed: true                           # are all deps currently installed?
interactive: false                          # does it prompt for user input? (y/n, readline, click.confirm)
tested: true                                # do tests pass?
test_count: 23                              # number of passing tests
test_command: "cd {path} && pytest -q"      # exact test command

# Discovery metadata
tags: ["compliance", "eu-ai-act", "scoring", "gtm", "article-9", "article-15"]
category: "gtm"                             # gtm | research | security | profiling | infrastructure | data
source: "ship-or-die-r1"                    # which hackathon/session created it
pipes_well_with: ["lintlang", "extract.py", "profiles.db"]  # known good chains

# Human context
one_liner: "Scores any company 0-100 on EU AI Act readiness by Article"
when_to_use: "When you need to quantify a company's compliance gap before outreach"
when_not_to_use: "When you need actual behavioral testing (use hermes-audit instead)"
```

### Schema Rules
- **entry** must be copy-paste executable. No "cd first" unless unavoidable.
- **input.example** and **output.example_output** are MANDATORY. The agent tests understanding by comparing expected output shape.
- **interactive: true** tools are NEVER returned to autonomous agents. `find_tool.py` returns the alternative instead.
- **dependencies.installed** is checked at discovery time, not at registry build time.
- **pipes_well_with** is explicit — the agent doesn't guess compatibility.

---

## find_tool.py Specification

### Core behavior
```
python3 ~/ai-infra/find_tool.py "score a company on EU AI Act compliance"
```

Returns:
```json
{
  "matches": [
    {
      "name": "hermes-score",
      "relevance": 0.95,
      "entry": "python3 -m hermes_score --company '<name>' --vertical '<vertical>'",
      "input_format": "json",
      "output_format": "json",
      "installed": true,
      "interactive": false,
      "one_liner": "Scores any company 0-100 on EU AI Act readiness by Article"
    }
  ],
  "chain_suggestion": null
}
```

### Chain discovery
```
python3 ~/ai-infra/find_tool.py --chain "company name → compliance score → personalized email"
```

Returns a pre-defined chain or constructs one from compatible tools:
```json
{
  "chain": [
    {"step": 1, "tool": "supersearch", "output_format": "text"},
    {"step": 2, "tool": "extract.py", "output_format": "json"},
    {"step": 3, "tool": "hermes-score", "output_format": "json"},
    {"step": 4, "tool": "email-template", "output_format": "text"}
  ],
  "compatible": true,
  "format_warnings": []
}
```

### Search methods (in priority order)
1. **Exact tag match** — fastest, most reliable
2. **Keyword match in description + one_liner + tags** — good for natural language queries
3. **Semantic similarity via nomic-embed-text** — fallback for vague queries (requires Ollama running)

### Flags
- `--accepts <format>` — filter by input format
- `--outputs <format>` — filter by output format
- `--tag <tag>` — filter by tag
- `--category <cat>` — filter by category
- `--chain "<A> → <B> → <C>"` — find or construct a tool chain
- `--installed-only` — only return tools with all deps installed
- `--autonomous` — exclude interactive tools (DEFAULT for agent use)

---

## Pre-Defined Macro Chains

Common workflows that agents should look up, not invent:

```yaml
chains:

  company_to_compliance_score:
    description: "Score any company on EU AI Act readiness"
    steps:
      - tool: supersearch
        args: "'{company}' AI compliance certifications EU"
        output: raw text files
      - tool: hermes-score
        args: "--company '{company}' --vertical '{vertical}'"
        output: json score per Article
    
  person_to_psychographic_profile:
    description: "Profile any person from their public writing"
    steps:
      - tool: supersearch
        args: "'{name}' blog post talk conference"
        output: raw text files
      - tool: extract.py
        args: "extract_features(combined_text)"
        output: 13-dim json feature vector
      - tool: profiles.db
        args: "INSERT INTO profiles ..."
        output: stored profile

  company_to_outreach_email:
    description: "Full pipeline from company name to calibrated cold email"
    steps:
      - tool: supersearch
        args: "'{company}' CTO VP Engineering founder"
        output: person name + title
      - tool: supersearch
        args: "'{person}' '{company}' email contact"
        output: email address
      - tool: supersearch
        args: "'{person}' blog post talk"
        output: raw text for profiling
      - tool: extract.py
        args: "extract_features(text)"
        output: linguistic features
      - tool: email_template
        args: "calibrate(features, vertical)"
        output: personalized email text

  target_to_full_audit:
    description: "Run full diagnostic pipeline on a target company's AI system"
    steps:
      - tool: lintlang
        args: "scan <config>"
        output: structural findings
      - tool: hermes-audit
        args: "--target '{company}'"
        output: 8-step diagnostic
      - tool: hermes-report
        args: "--input <audit_output>"
        output: client-facing report
      - tool: hermes-score
        args: "--company '{company}'"
        output: compliance score

  research_to_findings:
    description: "Run scaffold experiments and synthesize findings"
    steps:
      - tool: experiment-runner
        args: "--config <yaml>"
        output: results json
      - tool: finding-synth
        args: "--input <results>"
        output: cross-cutting synthesis
      - tool: scaffold-gaps
        args: "--results <synthesis>"
        output: next experiments to run
```

---

## Gap Analysis Solutions

### 1. Dependency Hell

**Problem:** Agent discovers a tool, tries to run it, fails because a pip package is missing.

**Solution:** `find_tool.py` checks `dependencies.installed` BEFORE returning the tool.

If installed = false, returns:
```json
{
  "tool": "hermes-score",
  "available": false,
  "reason": "missing dependency: pyyaml",
  "fix": "pip install pyyaml",
  "alternative": "Use corpus.db directly: sqlite3 ~/Desktop/hermes-labs-gtm-research/corpus.db 'SELECT * FROM compliance_scores'",
  "auto_fix_safe": true
}
```

- `auto_fix_safe: true` means the agent can run the fix command without human approval (pip install is safe)
- `auto_fix_safe: false` for system-level installs (brew, apt) — requires human approval
- The `alternative` field gives a primitive-based fallback that always works

**Registry build step:** Run `pip install -e .` on all 15 Ship or Die packages. Run `pip check` on each. Mark installed = true/false accurately.

### 2. Interactive Prompts

**Problem:** A legacy script has `input("Continue? y/n")` and hangs the autonomous agent.

**Solution:** `find_tool.py` in `--autonomous` mode (default) NEVER returns interactive tools.

Detection during registry build:
```python
# Scan every .py file in the tool's directory
INTERACTIVE_PATTERNS = [
    r'input\s*\(',
    r'readline\s*\(',
    r'click\.confirm',
    r'inquirer\.',
    r'questionary\.',
    r'getpass\.',
]
```

For important tools that are interactive:
```yaml
interactive: true
non_interactive_mode: "--batch --no-prompt"  # if available
alternative: "Use hermes-score --company X instead (non-interactive equivalent)"
```

If a tool is interactive AND has no batch mode AND has no alternative: it's human-only. Marked as `agent_usable: false`.

### 3. Piping Format Mismatches

**Problem:** Agent chains Tool A (outputs CSV) → Tool B (expects JSON). Silent data corruption.

**Solution:** Format compatibility is enforced by `find_tool.py --chain`.

Rules:
1. `output.format` of step N must match `input.format` of step N+1
2. If formats differ, `find_tool.py` inserts a converter: `json2csv`, `csv2json`, `text2json`
3. If no converter exists, the chain is rejected with an explicit error

```json
{
  "chain": [...],
  "compatible": false,
  "format_warnings": [
    "Step 2 outputs 'csv' but Step 3 expects 'json'. Insert: python3 -c 'import csv,json,sys; ...' between steps."
  ]
}
```

Pre-built converters at `~/ai-infra/converters/`:
- `json2csv.py` — json array → csv
- `csv2json.py` — csv → json array
- `text2json.py` — raw text → {"text": "..."} wrapper
- `json2text.py` — extract text field from json

---

## Tool Categories and Counts

| Category | Count | Examples |
|----------|-------|---------|
| **Primitives** | 10 | supersearch, cogito, himalaya, extract.py, lintlang, ollama, find_tool.py |
| **GTM / Sales** | ~25 | hermes-score, compliance-gap-scanner, outreach-personalizer, pipeline-crm, deal-velocity-scorer |
| **Audit / Compliance** | ~20 | hermes-audit, hermes-report, article-mapper, behavioral-test-gen, evidence-linker |
| **Research** | ~20 | experiment-runner, finding-synth, scaffold-gaps, scaffold-ab, te-calculator, significance-calc |
| **Security / Red Team** | ~25 | scaffold-redteam, attack-taxonomy, layered-detector, immune-defense, little-canary |
| **Profiling** | ~20 | voice-fingerprint, belief-velocity-engine, pitch-predictor, message-calibrator, candidate-profiler |
| **Infrastructure** | ~15 | langstate, claude-router, cogito-dashboard, memquery, drift-monitor, scaffold-registry |
| **Experimental** | ~30 | model-fingerprinter, wittgenstein-probe, scaffold-telepathy, reconstructive-memory |

**Total: ~170 tools**

---

## Registry Build Process

### Step 1: Inventory (30 min)
```bash
# List all prototype directories
find ~/Documents/projects/hermes-labs-hackathon/ -maxdepth 3 -name "main.py" -o -name "*.py" | head -200
find ~/Documents/projects/hermes-labs-hackathon-2/ -maxdepth 2 -name "pyproject.toml"
```

### Step 2: Generate manifests (2 hours, automated)
For each tool:
1. Read `main.py` or entry point — extract argparse flags
2. Read `README.md` or `PITCH.md` — extract description and tags
3. Read `pyproject.toml` — extract dependencies and version
4. Scan for interactive patterns
5. Run `pip install -e . && pytest -q` — check if tests pass
6. Write manifest YAML to `~/ai-infra/manifests/{name}.yaml`

### Step 3: Build find_tool.py (1 hour)
- Load all manifests at startup
- Keyword search + tag matching
- Optional: embed descriptions with nomic-embed-text for semantic search
- Chain validation logic

### Step 4: Update CLAUDE.md
Replace "Tools You MUST Use" section with:
```
## Tools
10 primitives are listed below. For 160+ specialized tools, run:
python3 ~/ai-infra/find_tool.py "what you need"
```

### Step 5: Test
- Agent spawned in clean session
- Given a novel task it hasn't seen
- Must discover and use tools without being told which ones
- Success = correct tool chain, no hallucinated flags, working output

---

## File Structure

```
~/ai-infra/
├── DISCOVERY_ENGINE_BLUEPRINT.md    ← this file
├── TOOL_REGISTRY.md                 ← human-readable index (primitives only)
├── find_tool.py                     ← discovery engine (~100 LOC)
├── manifests/                       ← one YAML per tool
│   ├── hermes-score.yaml
│   ├── hermes-audit.yaml
│   ├── lintlang.yaml
│   ├── ... (170+ files)
│   └── _template.yaml              ← blank manifest for new tools
├── converters/                      ← format bridge scripts
│   ├── json2csv.py
│   ├── csv2json.py
│   ├── text2json.py
│   └── json2text.py
└── chains/                          ← pre-defined macro chains
    ├── company_to_score.yaml
    ├── person_to_profile.yaml
    ├── company_to_email.yaml
    └── target_to_audit.yaml
```

---

## What This Enables

An agent receives: "Score Abridge on EU AI Act compliance and draft a cold email to their CTO."

Without discovery engine: writes 200 lines of Python from scratch, misses existing tools, takes 30 minutes, outputs generic email.

With discovery engine:
1. `find_tool.py --chain "company → score → email"` → returns company_to_outreach_email chain
2. Follows the chain: supersearch → extract → hermes-score → email template
3. Each step uses exact CLI flags from the manifest
4. Output is calibrated to the CTO's psychographic profile
5. Total time: 3 minutes. Uses 5 existing tools. Zero new code.

**The 170 tools become a compound intelligence layer. The discovery engine is the nervous system.**
