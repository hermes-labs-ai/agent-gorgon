# Agent Warden — Layered Implementation Plan (Repo Update)

Goal: strengthen runtime safety without breaking normal user workflows.

Core principle: early rollout is **signal-first**; flags provide calibration data, and kill actions should follow configurable risk accumulation except for hard invariants.

---

## Success Criteria

- [ ] False-kill rate stays near zero in normal workflows
- [ ] High-risk/mass-destructive behaviors are blocked reliably
- [ ] Every flag/hold/kill/override is auditable
- [ ] Rollout can progress from audit-only → enforce with explicit gates

---

## Layer 0 — Baseline & Freeze

- [ ] Tag current baseline (`v0.1.0-baseline`)
- [ ] Snapshot current policy (`examples/scope.openclaw.yaml`)
- [x] Save baseline forensic summary for comparison

Audit checks:
- [ ] Baseline tag exists
- [ ] Baseline forensic report path recorded

---

## Layer 1 — Threat Model (Helpful-but-Dangerous Included)

- [ ] Define categories: benign / suspicious / dangerous / critical
- [ ] Add helpful-but-dangerous scenarios:
  - [ ] mistaken bulk deletion
  - [ ] wrong-path mass write
  - [ ] runaway retries/loops
  - [ ] accidental external exfil path
- [ ] Map each scenario to expected response (FLAG / HOLD / KILL)

Audit checks:
- [ ] Scenario matrix committed
- [ ] Policy-to-response mapping reviewed

---

## Layer 2 — Deterministic Guardrails

- [ ] Add explicit mass-action thresholds (file/process/network)
- [ ] Add destructive command patterns + sensitive path hard blocks
- [ ] Keep deterministic checks authoritative for critical invariants

Audit checks:
- [ ] Unit tests for threshold triggers
- [ ] Unit tests for hard-invariant kills

---

## Layer 3 — Enforcement Modes

- [ ] Mode A: `audit_only`
- [ ] Mode B: `flag_and_hold`
- [ ] Mode C: `enforce_kill`
- [ ] Document defaults per environment

Audit checks:
- [ ] Mode toggle test matrix passes
- [ ] No unintended kill in `audit_only`

---

## Layer 4 — Flag Accumulation Policy ("x flags before fire")

- [ ] Expose configurable thresholds in policy:
  - `flag_threshold`
  - `flag_window`
  - `max_actions_per_minute`
- [ ] Define defaults tuned for stable operations
- [ ] Keep immediate kill for hard invariants regardless of count

Audit checks:
- [ ] Replay tests confirm kill only after threshold (except hard invariants)
- [ ] Threshold values documented with rationale

---

## Layer 5 — Operator Override + Auditability

- [ ] Support explicit operator override for ambiguous blocks
- [ ] Require TTL + one-time-use semantics for override
- [ ] Log override reason and actor/session metadata

Audit checks:
- [ ] Override event appears in forensic report
- [ ] Expired override is rejected

---

## Layer 6 — Forensics & Reporting

- [ ] Standardized incident schema (flag/hold/kill/override)
- [ ] Daily summary output (counts + top reasons)
- [ ] Correlate with Canary events when available

Audit checks:
- [ ] 24h forensic report generation succeeds
- [ ] Evidence manifest includes action + incident logs

---

## Layer 7 — Rollout Plan

- [ ] Week 1: audit-only
- [ ] Week 2: flag-and-hold for dangerous class
- [ ] Week 3: enforce_kill for critical class
- [ ] Weekly postmortem + threshold tuning

Promotion gates:
- [ ] No critical false kill during prior phase
- [ ] >=95% detection on seeded dangerous replay set
- [ ] Operator override misuse rate acceptable

---

## Immediate Next Tasks (This Week)

- [x] Add README note on expected early flag noise
- [ ] Add policy guidance for `flag_threshold` tuning
- [ ] Create replay test pack for helpful-but-dangerous scenarios
- [x] Produce first weekly audit report from real logs

Owner note:
- Start strict on hard invariants, conservative on kill thresholds, and iterate with data.
