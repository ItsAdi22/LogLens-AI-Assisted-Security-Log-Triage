# LogLens — AI-Assisted Security Log Triage

**LogLens** is an open-source, blue-team-first security log triage utility designed for site reliability engineers, system administrators, and security operations center (SOC) analysts.

It bridges the gap between simple rule matchers (like `fail2ban`) and heavyweight, enterprise SIEM platforms (like Wazuh or Splunk). By combining **streaming parsing**, **Drain3 log clustering**, and **deterministic rule heuristics** with **privacy-preserving local or cloud LLM evaluation**, LogLens condenses millions of noisy raw log events into prioritized, actionable security findings in seconds.

---

## ⚡ Core Capabilities

- **Streaming & Multi-Format Ingestion**: Streaming ingestion with gzip decompression and rotation-aware tailing. Autodetects SSH/auth logs, Nginx/Apache/OpenLiteSpeed combined access logs, RFC 3164/5424 syslog, and JSON lines.
- **Drain3 Template Clustering**: Groups raw events into template patterns with wildcard parameter extraction (`Failed password for <*> from <*> port <*>`).
- **Deterministic Rules & Anomaly Detection**: 18+ built-in MITRE ATT&CK detection rules plus statistical detectors for entity bursts, template rarity, and rate spikes.
- **Bidirectional Reversible Redaction**: Anonymizes IPs, credentials, JWTs, API keys, and email addresses into surrogate tokens (`[IP_1]`, `[TOKEN_1]`) before prompt delivery, then restores original indicators upon receipt.
- **Multi-Provider LLM Triage**: Zero-configuration local triage via Ollama, or cloud triage via OpenAI-compatible endpoints, Google Gemini, and Anthropic Claude.
- **Strict Injection Defense**: Prompt isolation (`<log_data>...</log_data>`), ANSI stripping, control character removal, tag breakout escaping, and strict Pydantic output schema validation with single-repair retry.
- **Multi-Channel Alerting & Deduplication**: Real-time alerts and digests via Telegram, Discord, and HMAC-SHA256 authenticated webhooks, with automatic cooldown deduplication to prevent alert fatigue.
- **Self-Contained Reporting**: Generate Markdown, versioned JSON (`report_schema_version = 1.0.0`), and single-file, XSS-safe HTML reports with dark/light themes.
- **Persistent SQLite History**: Full run tracking, cluster indexing, and finding recall via `loglens report --since 24h`.
- **Continuous Watch Mode**: Live log tailing with debounced cycle evaluation and graceful signal shutdown.

---

## 🔒 Privacy & Security First

1. **Zero Telemetry**: LogLens collects zero analytics, telemetry, or user metrics. None.
2. **Local by Default**: Designed to run 100% offline with local Ollama or pure deterministic rule mode (`--no-llm`).
3. **Cloud LLM Consent Gate**: Explicit consent (`--agree-cloud-llm`) is required before any anonymized cluster summaries are transmitted to external cloud providers.
4. **XSS-Safe Reporting**: All HTML report strings derived from log lines are escaped against script injection attacks.
