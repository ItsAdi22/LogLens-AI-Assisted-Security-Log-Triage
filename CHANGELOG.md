# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Phase 0: Project bootstrap, repository layout, build configuration via `pyproject.toml` (PEP 621).
- CLI skeleton with `loglens --version` and `--help` using Typer and Rich.
- Strict type checking (`mypy --strict`), formatting, and linting (`ruff`).
- GitHub Actions CI matrix (Python 3.11, 3.12, 3.13 on Linux and macOS), CodeQL analysis, and Release workflow.
- Community guidelines: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, and issue/PR templates.
- Architectural Decision Record ADR-0001 for baseline design choices.
- Unit test suite for CLI and version flags.
