# Agent Warden Audit Checklist

Use this checklist before deploying against important workloads or enabling
`WARDEN_KILL_ON_FLAGS=1`. The public `agent-gorgon==0.1.6` release has no audit-only switch and
applies deterministic HALT/KILL rules while running. Current `main` includes an unreleased
`--audit-only` candidate for non-signaling calibration.

## A) Input Data Quality
- [ ] `~/.local/share/agent-gorgon/logs/actions_*.jsonl` exists and is fresh
- [ ] `~/.local/share/agent-gorgon/logs/incidents/*.json` exists (if any controls fired)
- [ ] Any optional integration evidence is identified separately from Warden observations

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
- [ ] Disposable-target control attempts match the reviewed policy
- [ ] All critical scenario tests trigger expected response
- [ ] Failed or partial SIGSTOP/SIGKILL attempts are surfaced and understood

## F) Report Output
- [ ] `agent-gorgon-forensic --last-hours 24 --out <private-report-path>` exported and archived
- [ ] Summary includes action counts, flags, incidents, control reasons, and observed outcomes
