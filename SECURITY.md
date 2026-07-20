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
  process-tree changes and OS permissions can produce partial or failed controls.
- Relative recursive-delete operands are evaluated against the observed child cwd. If cwd capture
  is unavailable, Agent Warden HALTs rather than classifying the delete SAFE.
- Use `--no-llm` if action/scope data must not be sent to a localhost Ollama service.
- Prefer `--agent-pid` over process-name matching.
- Keep scope allowlists narrow and explicit.
- Store logs on protected storage and define rotation/retention.
- Add separate inbound and kernel-isolation controls when those threat boundaries matter.
