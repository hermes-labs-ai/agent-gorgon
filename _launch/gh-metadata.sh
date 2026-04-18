#!/bin/bash
# Run this from the repo root AFTER reviewing.
# This sets the GitHub repo description, topics, and homepage.
# REVIEW BEFORE RUNNING.

gh repo edit roli-lpci/agent-gorgon \
  --description "3-layer Claude Code hook defense that stops AI agents from fabricating tool output" \
  --add-topic "claude-code" \
  --add-topic "ai-agents" \
  --add-topic "hooks" \
  --add-topic "tool-discovery" \
  --add-topic "fabrication-defense" \
  --add-topic "agent-framework" \
  --add-topic "llm-safety" \
  --add-topic "eu-ai-act" \
  --add-topic "hermes-labs" \
  --homepage "https://github.com/roli-lpci/agent-gorgon"
