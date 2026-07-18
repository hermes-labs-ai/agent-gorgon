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
- Agent Warden 0.1.5 has no audit-only mode and enforces deterministic HALT/KILL rules while running;
  validate first against a disposable target and reviewed low-disruption scope.
- Use `--no-llm` if action/scope data must not be sent to a localhost Ollama service.
- Prefer `--agent-pid` over process-name matching.
- Keep scope allowlists narrow and explicit.
- Store logs on protected storage and define rotation/retention.
- Pair with inbound protections (for example, Little Canary) for layered defense.
