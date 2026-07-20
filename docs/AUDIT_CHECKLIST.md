# Agent Warden Audit Checklist

Use this checklist before deploying against important workloads or enabling
`WARDEN_KILL_ON_FLAGS=1`. Agent Warden 0.1.5 has no audit-only switch and always applies its
deterministic HALT/KILL rules while running.

## A) Input Data Quality
- [ ] `~/.local/share/sysmond/logs/actions_*.jsonl` exists and is fresh
- [ ] `~/.local/share/sysmond/logs/incidents/*.json` exists (if any kills)
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
- [ ] `agent-warden-forensic --last-hours 24` exported and archived
- [ ] Summary includes action counts, flags, incidents, control reasons, and observed outcomes
