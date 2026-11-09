# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Phase 2: Clustering & Rules Engine:
  - Drain3 template mining integration (`DrainClusterer`) with top extracted field tracking and sample collection.
  - Statistical anomaly detectors in `src/loglens/cluster/stats.py`: sliding-window entity bursts, rare template detection, and rate spikes via z-score.
  - IP and User-Agent threat intelligence enrichment (`src/loglens/enrich/`).
  - Declarative YAML rule schema (`Rule`, `RuleMatch`, `RuleCondition`) with validation.
  - Deterministic `RuleEngine` evaluating template patterns, field regexes, entity grouping, and time windows.
  - 18 built-in detection rules mapped to MITRE ATT&CK techniques across SSH, Web, and System/Sudo domains.
  - `loglens rules list`, `loglens rules validate`, and `loglens rules test` CLI commands.
  - Integration of clustering and rules into `loglens analyze` displaying ranked findings and mined template clusters.
  - Documentation guide: `docs/writing-rules.md`.
- Phase 1: Ingestion & Parsing layer:
  - Streaming file reader with transparent gzip decompression (`FileReader`) and rotation-aware tailing (`TailReader`).
  - Stdin streaming reader (`StdinReader`).
  - Core data models: `Event`, `Cluster`, `Finding`, `LLMAssessment`, `Report`, and `ReportMetadata`.
  - Parsers with autodetect:
    - `AuthLogParser`: sshd, sudo, PAM, su with legacy and ISO 8601 timestamp support and year rollover handling.
    - `WebAccessParser`: Nginx, Apache, OpenLiteSpeed Common and Combined Log Formats with vhost support.
    - `SyslogParser`: RFC 3164 (BSD) and RFC 5424 (IETF) syslog streams.
    - `JsonLinesParser`: structured JSON logs with automatic timestamp and severity resolution.
    - `GenericParser`: resilient fallback line parser.
  - Comprehensive Hypothesis property-based fuzz tests verifying parsers never crash on arbitrary input.
  - CLI command `loglens analyze <path> --no-llm` with rich summary metrics and top IP/action tables.
  - Synthetic log generator script `scripts/gen_synthetic_logs.py` producing sanitized sample data.
- Phase 0: Project bootstrap, repository layout, build configuration via `pyproject.toml` (PEP 621).
- CLI skeleton with `loglens --version` and `--help` using Typer and Rich.
- Strict type checking (`mypy --strict`), formatting, and linting (`ruff`).
- GitHub Actions CI matrix (Python 3.11, 3.12, 3.13 on Linux and macOS), CodeQL analysis, and Release workflow.
- Community guidelines: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, and issue/PR templates.
- Architectural Decision Record ADR-0001 for baseline design choices.
- Unit test suite for CLI and version flags.
