# Agent Warden Audit Checklist

Use this checklist before switching from audit-only to stronger enforcement.

## A) Input Data Quality
- [ ] `~/.local/share/sysmond/logs/actions_*.jsonl` exists and is fresh
- [ ] `~/.local/share/sysmond/logs/incidents/*.json` exists (if any kills)
- [ ] Canary logs present (`security/canary-audit.jsonl`, `security/canary-alerts.jsonl`)

## B) Signal Quality Review
- [ ] Top 20 `FLAG` reasons reviewed
- [ ] LLM parser failures categorized separately from true risky actions
- [ ] Noise ratio documented (flags per 100 actions)

## C) Helpful-but-Dangerous Scenarios
- [ ] bulk file modification scenario tested
- [ ] mistaken path scenario tested
- [ ] runaway process creation/retry scenario tested
- [ ] exfil-like domain scenario tested

## D) Threshold Calibration
- [ ] `flag_threshold` tuned from observed noise
- [ ] `flag_window` tuned to avoid accidental accumulation spikes
- [ ] hard invariants validated as immediate stop conditions

## E) Promotion Gate
- [ ] No false kills in last 48h
- [ ] All critical scenario tests trigger expected response
- [ ] Operator override path tested and audited

## F) Report Output
- [ ] `agent-warden-forensic --last-hours 24` exported and archived
- [ ] Summary shared with: action counts, flags, incidents, kill reasons, overrides
