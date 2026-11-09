# Migration Guide: Upgrading to LogLens v1.0.0

This guide assists system administrators, SecOps engineers, and developers in upgrading existing LogLens deployments from **v0.1.0** to **v1.0.0**.

---

## 1. Overview of Changes in v1.0.0

LogLens v1.0.0 marks the production-ready milestone of the project. Key enhancements include:
- **Interactive Web UI**: `loglens serve` provides a local-first FastAPI + HTMX dashboard with real-time cluster exploration and on-demand AI explanation.
- **Expanded Ecosystem Parsers**: First-class support for Fail2ban, UFW/iptables, Postgres/MySQL authentication, Minecraft (with Log4Shell detection), Pterodactyl/Pelican game panels, and Docker JSON logs.
- **Sigma Rule Importer**: Native import of Sigma detection YAML rules with MITRE ATT&CK technique mapping.
- **Firewall Action Exporters**: Generate drop/ban rules for `nftables`, `iptables`, `fail2ban`, and `Cloudflare IP Access Rules` (with strict advisory-only generation).
- **Hardened Security & Performance**: Strict CSP, parameter-bound SQLite queries, streaming memory boundedness (< 25 MB on 5k lines, > 90k lines/s throughput), and prompt injection isolation.

---

## 2. Upgrading via Package Managers

### Python / pip / pipx
```bash
# Using pipx (recommended)
pipx upgrade loglens

# Using standard pip in a virtualenv
pip install --upgrade "loglens>=1.0.0"
```

### Docker
Pull the latest official production image:
```bash
docker pull itsadi22/loglens:1.0.0
# Or update docker-compose.yml:
# image: itsadi22/loglens:1.0.0
docker compose up -d
```

---

## 3. Database Schema Migration

LogLens uses an embedded SQLite database (`~/.local/share/loglens/loglens.db` by default) to persist run history, cluster statistics, and security findings.

- **Automatic Migration**: When upgrading from `v0.1.0` to `v1.0.0`, LogLens automatically executes non-destructive schema migrations on first startup.
- **Manual Verification**: You can verify database integrity prior to production rollout:
  ```bash
  # Check database schema version and connectivity
  loglens report --since 24h --format md
  ```
- **Thread Safety**: The storage layer in v1.0.0 includes multi-threading connection management (`check_same_thread=False`) to support concurrent web dashboard workers and asynchronous background watchers.

---

## 4. Configuration Updates (`config.yml`)

The configuration format remains fully backward-compatible with v0.1.0. Existing configuration files at `~/.config/loglens/config.yml` will load without modification.

To enable the new Web UI dashboard features, you may optionally append the `web` section:

```yaml
# Optional: Web UI Configuration (New in v1.0.0)
web:
  host: "127.0.0.1"      # Bind to localhost by default for security
  port: 8080             # Web dashboard listening port
  auth_token: ""         # Optional token for Bearer/query authentication
```

---

## 5. Sigma Rules Migration

If you maintain custom Sigma rules, you can now convert them to native LogLens detection rules:

```python
from loglens.rules.sigma import load_sigma_rule

rule = load_sigma_rule("my_sigma_rule.yml")
print(f"Loaded: {rule.title} (Severity: {rule.severity})")
```

---

## 6. Pre-Upgrade Checklist

Before deploying v1.0.0 to production SIEM pipelines:
- [x] Review [Stability Guarantees](stability-and-deprecation.md) for SemVer 2.0.0 commitments.
- [x] Run `loglens providers test` to verify configured LLM connectivity.
- [x] Run `loglens rules list` to ensure all built-in and custom rules are detected.
- [x] Verify your backup of `~/.local/share/loglens/loglens.db`.
