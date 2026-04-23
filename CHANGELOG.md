# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Pending
- Publish to PyPI (configure Trusted Publishing at pypi.org first, then push a v* tag)
- Set GitHub repo description and topics (`bash _launch/gh-metadata.sh`)
- Upload `_launch/images/social-1200x630.jpg` as GitHub social preview (Settings > Social Preview)

## [0.1.0] - 2026-04-16

### Added
- Initial release.
- 3-layer hook defense: `UserPromptSubmit` (pre-prompt tool injection), `Stop` (post-generation
  confabulation detection), and `PreToolUse/Bash` (reimplementation blocking).
- Discovery engine `find_tool.py`: reads YAML manifests, returns ranked copy-paste-ready entry commands.
- YAML manifest system with `_template.yaml` schema and `hermes-score.yaml` reference implementation.
- `install.sh`: one-command hook registration into Claude Code `settings.json`.
- Converters: `csv2json.py`, `json2csv.py`, `json2text.py`, `text2json.py`.
- 116 passing tests covering all hooks and the discovery engine.

[Unreleased]: https://github.com/roli-lpci/agent-gorgon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/roli-lpci/agent-gorgon/releases/tag/v0.1.0
