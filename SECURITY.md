# Security Policy

## Supported versions

Current support target: latest `main` branch and newest tagged release.

## Reporting a vulnerability

Please **do not** open public issues for suspected vulnerabilities.

Preferred process:
1. Email **lpcisystems@gmail.com** (or use a private GitHub Security Advisory, if enabled).
2. Include reproduction steps, expected impact, and any known mitigation.
3. You should receive acknowledgment as soon as possible.

## Operator hardening checklist

Before production use:
- Agent Warden 0.1.5 has no audit-only mode; it evaluates deterministic HALT/KILL rules and
  attempts their configured controls while running;
  validate first against a disposable target and reviewed low-disruption scope.
- Treat it as a best-effort polling guard, not a sandbox or syscall interceptor. Short-lived
  children and actions between polls can be missed.
- HALT/KILL are signal attempts, not guaranteed outcomes. Inspect the recorded control result;
  process-tree changes and OS permissions can produce partial or failed controls. Retry state is
  reconciled against the visible process tree; one KILL episode reuses its rollback/report receipt.
- Credential-read correlation treats the complete IP loopback ranges as IPC rather than egress.
  An active non-local socket at read time or a later newly observed non-local connection inside the
  correlation window activates the deterministic exfil KILL rule.
- Relative recursive-delete operands are evaluated against the observed child cwd. If cwd capture
  is unavailable, Agent Warden HALTs rather than classifying the delete SAFE.
  Supported `env` wrappers and root/home glob or ancestor forms are reduced before classification;
  unresolved wrapper or shell-expansion semantics also HALT rather than acquiring irreversible
  KILL authority. Forbidden-glob intersections are decided symbolically without a recursive
  filesystem glob walk in process-event evaluation.
- Use `--no-llm` if action/scope data must not be sent to a localhost Ollama service.
- Prefer `--agent-pid` over process-name matching.
- Keep scope allowlists narrow and explicit.
- Store logs on protected storage and define rotation/retention.
- Add separate inbound and kernel-isolation controls when those threat boundaries matter.
