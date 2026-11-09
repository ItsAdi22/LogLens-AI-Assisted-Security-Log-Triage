# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-09

### Added
- **Phase 8: Hardening, Performance Profiling, Stability Guarantees & v1.0.0 Production Release**:
  - Streaming memory boundedness guarantees (< 25 MB peak RAM across 5,000 events and Drain3 clustering).
  - Automated performance & memory profiling utility (`scripts/benchmark_large_file.py`) demonstrating > 88,000 lines/sec throughput.
  - Performance regression test suite (`tests/unit/test_perf_bounds.py`).
  - Comprehensive third-party security audit checklist (`docs/security-audit.md`) covering prompt injection defense, stored XSS elimination, SQL injection parameter binding, and container non-root security.
  - Formal Stability Guarantees and Deprecation Policy (`docs/stability-and-deprecation.md`) locking SemVer 2.0.0, CLI exit codes, and `report_schema_version = "1.0.0"`.
  - Production migration guide (`docs/migration-guide.md`) covering upgrades from v0.1.0 to v1.0.0 and database migration procedures.
  - Thread-safe SQLite connection pooling in `StorageManager` (`check_same_thread=False`) supporting FastAPI concurrent worker threads.
- **Phase 7: Ecosystem, Sigma Importer & Extensibility**:
  - Specialized built-in ecosystem parsers:
    - `Fail2banParser` (`src/loglens/parsers/fail2ban.py`): Ingests `/var/log/fail2ban.log` tracking jail actions, ban enforcement, and unban lifecycle.
    - `UfwParser` (`src/loglens/parsers/ufw.py`): Ingests UFW and Linux iptables kernel packet drop logs (`/var/log/ufw.log`).
    - `DatabaseAuthParser` (`src/loglens/parsers/database_auth.py`): Ingests PostgreSQL and MySQL/MariaDB failed logins and unauthorized connection attempts.
    - `MinecraftParser` (`src/loglens/parsers/minecraft.py`): Ingests Minecraft server console logs (`logs/latest.log`) with automatic detection of connection spam, RCON failures, and Log4Shell (`${jndi:...}`) exploit attempts.
    - `PterodactylParser` (`src/loglens/parsers/pterodactyl.py`): Ingests Pterodactyl Wings and Pelican daemon logs (`wings.log`) capturing token authentication failures.
    - `DockerJsonParser` (`src/loglens/parsers/docker_json.py`): Ingests container JSON log lines (`*-json.log`).
  - Sigma rule importer (`src/loglens/rules/sigma.py`): Converts open-source Sigma YAML detection rules into LogLens native rules.
  - CLI command `loglens rules import-sigma <path> [--out <dir>]`.
  - Python entry point plugin architecture (`src/loglens/plugins/`): Discovers and loads custom third-party extensions for `loglens.parsers`, `loglens.rules`, and `loglens.notifiers`.
  - CLI command `loglens plugins list`.
  - Suggested-action perimeter mitigation export (`src/loglens/actions/`): Extracts verified offending source IPs and generates advisory configuration scripts for `nftables`, `iptables`, `fail2ban`, and `cloudflare` (strictly generate-only, never automatically applied).
  - CLI command `loglens export-actions <report> --target nftables|iptables|fail2ban|cloudflare [--out file]`.
  - Optional GeoIP enrichment (`lookup_geoip`) with graceful fallback.
  - Comprehensive documentation: `docs/ecosystem.md`.
- **Phase 6: Web UI & Timeline Inspection**:
  - Web dashboard package (`src/loglens/web/`) built using FastAPI, Jinja2, and vendored HTMX (zero Node/npm build steps).
  - 100% offline, self-hosted frontend with vendored HTMX (`/static/js/htmx.min.js`).
  - Security hardening: bound to `127.0.0.1` by default, optional Bearer/query token authentication, strict CSP header, frame-ancestors blocking, and Jinja2 autoescaping.
  - Interactive dashboard (`/`) displaying metric cards, severity distribution bar, 7-day incident activity timeline, and filterable ingestion runs.
  - Run detail inspection (`/runs/{run_id}`) displaying parsed events, cluster breakdown with `<*>` wildcard highlighting, and security findings.
  - On-demand AI incident explanation (`POST /runs/{run_id}/findings/{finding_id}/explain`) via HTMX with persistent SQLite updates.
  - REST API endpoints for telemetry integration (`/api/stats`, `/api/runs`, `/api/runs/{run_id}`, `/health`).
  - `loglens serve` CLI command with `--host`, `--port`, `--db`, `--token`, and `--provider` options.
  - Comprehensive documentation: `docs/web-ui.md`.

## [0.1.0] - 2026-11-09

### Added
- **Phase 5: Quality, Documentation, Packaging & Release**:
  - Ground-truth evaluation benchmark suite (`tests/eval/scenarios.py`) spanning 12 attack, injection, and benign scenarios.
  - Evaluation runner (`tests/eval/run.py`) measuring severity agreement (100%), attack classification (100%), and prompt injection resistance (100%).
  - Multi-stage minimal production `Dockerfile` with non-root security boundaries (`loglens:1000`) and volume mounts for `/logs` and `/config`.
  - Multi-container `docker-compose.yml` stack pairing LogLens with local Ollama service for 100% offline private triage.
  - MkDocs Material documentation suite (`mkdocs.yml`, `docs/index.md`, `docs/quickstart.md`, `docs/threat-model.md`, `docs/architecture.md`, `docs/benchmarks.md`, `docs/eval-results.md`).
  - Community contribution backlog (`docs/good-first-issues.md`) with 12 well-scoped tasks across parsers, rules, alerts, and tooling.
  - GitHub issue templates for new parser requests and new MITRE ATT&CK detection rule requests.
- **Phase 4: Reports, Notifications, Store & Watch Mode**:
  - Reporting subsystem (`src/loglens/report/`) supporting Markdown, JSON (`report_schema_version = "1.0.0"`), and self-contained HTML.
  - Strict HTML output safety: all log-derived templates, messages, field values, and finding summaries are escaped (`html.escape()`) against XSS injection.
  - HTML report styling with toggleable dark/light themes, metric cards, and responsive CSS layout.
  - SQLite storage manager (`src/loglens/store/db.py`) persisting runs, clusters, findings, and schema migrations with parameter-bound SQL queries.
  - `loglens report [--since 24h] [--format md|json|html] [--out FILE]` CLI command querying historical triage runs.
  - Multi-channel notification subsystem (`src/loglens/notify/`) supporting Telegram bot alerts/digests, Discord webhook embeds, and HMAC-SHA256 authenticated JSON webhooks.
  - `CooldownTracker` eliminating alert spam by deduplicating repeated findings within configurable windows.
  - Real-time continuous monitoring `loglens watch <path>` with debounce batching, rotation detection, and signal handling.
  - Pipeline exit code semantics: exit code 2 when security findings meet or exceed `--fail-on` threshold (ideal for CI/CD and cron jobs).
- **Phase 3: Redaction & LLM Triage**:
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
- **Phase 2: Clustering & Rules Engine**:
  - Drain3 template mining integration (`DrainClusterer`) with top extracted field tracking and sample collection.
  - Statistical anomaly detectors in `src/loglens/cluster/stats.py`: sliding-window entity bursts, rare template detection, and rate spikes via z-score.
  - IP and User-Agent threat intelligence enrichment (`src/loglens/enrich/`).
  - Declarative YAML rule schema (`Rule`, `RuleMatch`, `RuleCondition`) with validation.
  - Deterministic `RuleEngine` evaluating template patterns, field regexes, entity grouping, and time windows.
  - 18 built-in detection rules mapped to MITRE ATT&CK techniques across SSH, Web, and System/Sudo domains.
  - `loglens rules list`, `loglens rules validate`, and `loglens rules test` CLI commands.
  - Integration of clustering and rules into `loglens analyze` displaying ranked findings and mined template clusters.
  - Documentation guide: `docs/writing-rules.md`.
- **Phase 1: Ingestion & Parsing layer**:
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
- **Phase 0: Bootstrap & Foundations**:
  - Project bootstrap, repository layout, build configuration via `pyproject.toml` (PEP 621).
  - CLI skeleton with `loglens --version` and `--help` using Typer and Rich.
  - Strict type checking (`mypy --strict`), formatting, and linting (`ruff`).
  - GitHub Actions CI matrix (Python 3.11, 3.12, 3.13 on Linux and macOS), CodeQL analysis, and Release workflow.
  - Community guidelines: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, and issue/PR templates.
  - Architectural Decision Record ADR-0001 for baseline design choices.
