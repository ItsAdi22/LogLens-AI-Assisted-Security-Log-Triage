# LogLens — AI-Assisted Security Log Triage

[![CI](https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage/actions/workflows/ci.yml/badge.svg)](https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)
[![CodeQL](https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage/actions/workflows/codeql.yml/badge.svg)](https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage/actions/workflows/codeql.yml)

> **Lightweight, local-first, privacy-respecting log triage for self-hosters, sysadmins, and DevOps.**

LogLens ingests logs, deduplicates and clusters them using Drain3, applies fast deterministic security rules, and optionally sends **compact, redacted cluster summaries** to an LLM (such as local Ollama) to explain what happened, evaluate severity, and suggest defensive actions.

---

## 🔒 Privacy & Security First

- **Zero Telemetry**: No tracking, analytics, phone-home, or third-party telemetry. Ever.
- **Local-First & Offline**: Designed for local LLMs via Ollama. Cloud LLMs are optional and require explicit consent.
- **Privacy by Default**: High-entropy redaction of IPs, emails, credentials, and tokens occurs *before* any text reaches an LLM.
- **Token-Efficient**: LLMs see clustered templates and statistical summaries—never raw lines of your logs.
- **Hardened Against Prompt Injection**: Logs contain untrusted data. LogLens sanitizes, truncates, and bounds untrusted data in delimited XML blocks with rigid system instructions and strict Pydantic JSON schemas. The LLM has zero execution privileges.

---

## 🚀 Quickstart (3 Commands)

```bash
# 1. Install loglens
pip install loglens

# 2. Analyze an authentication log without an LLM (rules-only)
loglens analyze /var/log/auth.log --no-llm

# 3. Analyze with local Ollama
loglens analyze /var/log/auth.log --provider ollama
```

---

## 📊 Comparison

| Feature | `grep` / `fail2ban` | Wazuh / Elastic SIEM | **LogLens** |
|---|---|---|---|
| **Setup time** | Minutes | Hours/Days | **< 2 minutes** |
| **Resource usage** | Low | Heavy (GBs of RAM) | **Lightweight (< 100MB RAM)** |
| **Clustering** | ❌ No | ❌ Complex setup | **✅ Drain3 automatic template mining** |
| **AI Explanation** | ❌ None | ❌ None or expensive cloud add-on | **✅ Local LLM (Ollama) or Cloud** |
| **Privacy Redaction** | N/A | Manual pipeline | **✅ Automatic reversible redaction** |
| **Rule Engine** | Regex / Python | XML / Decoders | **✅ Simple, readable YAML rules** |
| **Hostile Log Safety** | Vulnerable to bypass | Complex parsing | **✅ Delimited untrusted data boundaries** |

---

## 🛠️ Feature Overview

- **Multiple Ingestors**: Files, streaming stdin, syslog, journald.
- **Smart Parsers**: Automatically autodetects `sshd` / `auth.log`, Nginx / Apache / OpenLiteSpeed web access logs, JSON logs, and generic syslog.
- **Drain3 Template Clustering**: Groups thousands of log lines into recurring event templates.
- **Rule Engine**: MITRE ATT&CK-mapped detection rules for brute force, web scanning, exploit probes, and statistical anomaly detection.
- **Structured LLM Assessment**: Outputs validated Pydantic models with `attack_type`, severity, confidence score, evidence citations, and actionable suggestions.
- **Comprehensive Reporting**: Export reports to Markdown, JSON, HTML, or receive alerts on Telegram, Discord, or webhooks.

---

## 🗺️ Roadmap

- [x] **Phase 0**: Bootstrap & CI/CD infrastructure
- [ ] **Phase 1**: Ingestion & robust parsers (sshd, web, syslog)
- [ ] **Phase 2**: Drain3 clustering & YAML rule engine
- [ ] **Phase 3**: Reversible redactor & multi-provider LLM triage
- [ ] **Phase 4**: Reports (MD/JSON/HTML), SQLite store, notifiers, `watch` mode
- [ ] **Phase 5**: Eval suite, Docker, documentation, v0.1.0 release
- [ ] **Phase 6**: Lightweight Web UI (FastAPI + HTMX)
- [ ] **Phase 7**: Additional parsers (Minecraft, Pterodactyl, fail2ban) & Sigma import
- [ ] **Phase 8**: Production hardening & v1.0 release

---

## 🤝 Contributing

Contributions are welcome! Please check out [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## 📄 License

LogLens is licensed under the [Apache License, Version 2.0](LICENSE).
