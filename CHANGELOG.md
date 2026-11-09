# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Phase 4: Reports, Notifications, Store & Watch Mode:
  - Reporting subsystem (`src/loglens/report/`) supporting Markdown, JSON (`report_schema_version = "1.0.0"`), and self-contained HTML.
  - Strict HTML output safety: all log-derived templates, messages, field values, and finding summaries are escaped (`html.escape()`) against XSS injection.
  - HTML report styling with toggleable dark/light themes, metric cards, and responsive CSS layout.
  - SQLite storage manager (`src/loglens/store/db.py`) persisting runs, clusters, findings, and schema migrations with parameter-bound SQL queries.
  - `loglens report [--since 24h] [--format md|json|html] [--out FILE]` CLI command querying historical triage runs.
  - Multi-channel notification subsystem (`src/loglens/notify/`) supporting Telegram bot alerts/digests, Discord webhook embeds, and HMAC-SHA256 authenticated JSON webhooks.
  - `CooldownTracker` eliminating alert spam by deduplicating repeated findings within configurable windows.
  - Real-time continuous monitoring `loglens watch <path>` with debounce batching, rotation detection, and signal handling.
  - Pipeline exit code semantics: exit code 2 when security findings meet or exceed `--fail-on` threshold (ideal for CI/CD and cron jobs).
- Phase 3: Redaction & LLM Triage:
  - Reversible token-based anonymization engine (`Redactor`) with levels `standard`, `strict`, and `off`.
  - Comprehensive regex extractors for IPv4, IPv6, email addresses, JWT tokens, AWS access keys, Bearer tokens, URL credentials, query string secrets, and private keys.
  - Multi-provider LLM abstraction (`LLMProvider` protocol) supporting Ollama, OpenAI-compatible APIs (OpenAI, OpenRouter, vLLM, LM Studio), Google Gemini, and Anthropic Claude.
  - Deterministic `MockLLMProvider` for isolated, offline CI testing without network overhead.
  - Guard module with ANSI code stripping, control character removal, tag breakout neutralization (`&lt;/log_data&gt;`), payload truncation, and suspicious prompt injection detection.
  - Output extraction and validation against Pydantic `LLMAssessment` with single-repair retry prompts.
  - Versioned prompt templates (`triage_v1.md`, `repair_v1.md`) enforcing SOC analyst persona and strict data containment boundaries.
  - Persistent SQLite and in-memory triage caching (`LLMCache`) keyed by SHA-256 preventing redundant token charges.
  - Token budget guardrails (`TokenBudget`) enforcing safety caps per run with automatic graceful fallback to rule findings.
  - Cloud LLM privacy consent gate (`verify_cloud_consent`) requiring explicit acknowledgment before external data transfer.
  - `loglens providers test` CLI command verifying provider connectivity.
  - `loglens analyze` CLI enhancements: `--llm/--no-llm`, `--provider`, `--model`, `--base-url`, `--redaction`, `--dry-run-llm`, and `--agree-cloud-llm`.
  - Full adversarial evaluation suite in `tests/eval/test_prompt_injection.py` testing injection resilience.
  - Documentation: `docs/privacy-and-redaction.md` and `docs/llm-providers.md`.
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
