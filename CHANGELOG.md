# Changelog

All notable changes to trapscan are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-06

Initial public release.

### Added
- 38 rules across five categories: editor/IDE auto-execution, Git metadata traps, install/build hooks, AI coding-agent configuration and prompt injection, and file-content checks (hidden Unicode, download-and-run, decode-and-eval, exfiltration URLs, disguised binaries). Full list in `docs/rules.md`.
- Text, `--json` and `--sarif` (2.1.0) output; `--fail-on` exit-code threshold; `--ignore`, `--only`, `--exclude`; inline `trapscan:ignore` marker.
- `trapscan clone <url>`: clone with hooks disabled and submodules skipped, then scan.
- Direct scanning of `.zip` and `.tar*` archives with path-traversal and symlink guards.
- Tolerant JSONC parser (comments, trailing commas) for editor and agent config files.
- Severity calibration against flask, express, ripgrep, fastapi, vite, anthropic-sdk-python and microsoft/vscode.
- Composite GitHub Action (`action.yml`), demo-repository generator, unit test suite (29 tests, stdlib `unittest`).

[0.1.0]: https://github.com/kosys0224-spec/trapscan/releases/tag/v0.1.0
