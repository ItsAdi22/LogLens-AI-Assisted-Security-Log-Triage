# Quickstart Guide

Get up and running with **LogLens** in less than 5 minutes.

---

## 1. Installation

LogLens requires **Python 3.11+**. We recommend installing via `pipx` for isolated CLI usage or using our official Docker image.

### Using pipx (Recommended for CLI)
```bash
pipx install loglens
```

### Using standard pip
```bash
pip install loglens
```

### Using Docker
```bash
docker pull ghcr.io/itsadi22/loglens:v0.1.0
# Or run with local directory mounted
docker run --rm -v $(pwd)/logs:/logs ghcr.io/itsadi22/loglens:v0.1.0 analyze /logs/auth.log
```

---

## 2. 3-Command Quickstart

Triage security logs immediately without setting up databases or cloud accounts:

```bash
# 1. Verify installation
loglens --version

# 2. Analyze a sample log file in offline, rule-only mode (no LLM required)
loglens analyze /var/log/auth.log --no-llm

# 3. Analyze with local LLM triage using Ollama (100% private, zero telemetry)
loglens analyze /var/log/nginx/access.log --llm --provider ollama --out report.html
```

---

## 3. CLI Command Reference

LogLens provides an intuitive suite of subcommands:

### `loglens analyze`
Analyzes security logs from a local file or standard input.

```bash
loglens analyze <PATH|-> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `<PATH>` or `-` | Required | Path to the target log file (`.log`, `.gz`), or `-` to stream from stdin. |
| `--format` | `auto` | Log parser format: `auto`, `auth`, `nginx`, `apache`, `ols`, `syslog`, `json`, `generic`. |
| `--llm / --no-llm` | `--no-llm` | Enable AI triage assessment using LLM. |
| `--provider` | `ollama` | Provider backend: `ollama`, `openai_compat`, `gemini`, `anthropic`, `mock`. |
| `--model` | Provider default | Explicit model name (e.g. `llama3.2`, `gpt-4o`, `gemini-1.5-flash`). |
| `--redaction` | `standard` | Privacy redaction level: `strict`, `standard`, `off`. |
| `--out` | None (stdout) | Output report path. Format is inferred from extension (`.md`, `.json`, `.html`). |
| `--fail-on` | None | Exit code `2` if findings meet or exceed severity: `critical`, `high`, `medium`, `low`, `info`. |
| `--verbose` | `False` | Display detailed processing logs and debug information. |

### `loglens watch`
Continuously monitors a live log file in real-time, buffering events, clustering patterns, and dispatching notifications.

```bash
# Monitor live auth.log with telegram alerts
loglens watch /var/log/auth.log --interval 5s --notify telegram
```

| Flag | Default | Description |
|---|---|---|
| `<PATH>` | Required | Log file path to watch. |
| `--interval` | `5s` | Flush and triage polling window. |
| `--notify` | None | Real-time notification channel: `telegram`, `discord`, `webhook`. |
| `--llm / --no-llm` | `--no-llm` | Enable AI assessment during live watch. |

### `loglens report`
Query historical triage runs stored in the local SQLite database.

```bash
# Generate a summary of all findings from the last 24 hours
loglens report --since 24h --format html --out daily_digest.html
```

### `loglens rules`
Manage, inspect, and validate detection rules.

```bash
# List all 18+ built-in MITRE ATT&CK detection rules
loglens rules list

# Validate custom YAML rule syntax
loglens rules validate my_rules.yml

# Test rule execution against a real log file
loglens rules test my_rules.yml --against /var/log/auth.log
```

### `loglens providers test`
Test network connectivity, authentication credentials, and model health for configured LLM backends.

```bash
loglens providers test --provider ollama
loglens providers test --provider openai_compat
```

---

## 4. Typical Workflows

### Scenario A: Streaming Stdin from Remote SSH Host
Triage logs from a remote production server without installing LogLens remotely:

```bash
ssh user@server "tail -n 5000 /var/log/auth.log" | loglens analyze - --out report.md
```

### Scenario B: CI/CD Quality Gate & Security Audits
Run LogLens inside GitHub Actions or GitLab CI to ensure test environments aren't experiencing brute-force attacks or secret leaks:

```bash
# Fails the pipeline (exit code 2) if HIGH or CRITICAL attacks are detected
loglens analyze /var/log/nginx/access.log --fail-on high
```

### Scenario C: Daily Automated Cron Digest
Set up a nightly cron job to summarize daily incidents and send an alert to your Discord or Telegram triage channel:

```bash
0 0 * * * /usr/local/bin/loglens analyze /var/log/auth.log --since 24h --llm --provider ollama --out /var/reports/daily.html
```
