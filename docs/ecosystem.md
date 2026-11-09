# Ecosystem, Parsers & Extensibility

LogLens is engineered as a highly extensible platform capable of parsing specialized game and database infrastructure, importing community Sigma rules, dynamically loading third-party plugins, and generating perimeter mitigation scripts.

---

## 1. Supported Ecosystem Parsers

In addition to standard Linux `auth.log`, Nginx, Apache, and Syslog, LogLens includes built-in parsers for:

| Parser | Format Name | Typical Log Path | Key Detections |
|---|---|---|---|
| **Fail2ban** | `fail2ban` | `/var/log/fail2ban.log` | Jail actions, ban enforcement, and unban lifecycle |
| **UFW / iptables** | `ufw` | `/var/log/ufw.log`, `kern.log` | Blocked inbound packets, ports, interfaces, and protocol scanning |
| **Database Auth** | `database_auth` | `/var/log/postgresql/*.log`, MySQL error logs | Failed PostgreSQL/MySQL passwords, denied connections, database brute force |
| **Minecraft Server** | `minecraft` | `logs/latest.log` | Connection flooding/login spam, failed RCON passwords, **Log4Shell (`${jndi:...}`) exploit payloads** |
| **Pterodactyl / Pelican** | `pterodactyl` | `wings.log` | Token authentication failures, unauthorized daemon API requests |
| **Docker Daemon** | `docker_json` | `/var/lib/docker/containers/*/*-json.log` | Container stderr crash loops, unhandled panic exceptions |

All parsers support **automatic format detection** (`--format auto`) by sampling the first 50 lines of input.

---

## 2. Sigma Rule Import

LogLens supports importing standard YAML detection rules from the open-source [Sigma Project](https://github.com/SigmaHQ/sigma):

```bash
# Convert a single Sigma rule file
loglens rules import-sigma /path/to/sigma_rule.yml --out ./custom_rules/

# Recursively import an entire directory of Sigma rules
loglens rules import-sigma /path/to/sigma/rules/web/ --out ./custom_rules/
```

### Conversion Mechanics
- **Logsource Mapping**: Maps Sigma categories (`webserver`, `sshd`, `firewall`) to LogLens target sources.
- **Modifiers**: Converts `contains`, `startswith`, `endswith`, and `regex` filters into compiled regex patterns.
- **MITRE ATT&CK**: Extracts and normalizes attack technique tags (`attack.t1190` -> `T1190`).
- **Severity Mapping**: Automatically aligns `informational` -> `info`, `low`, `medium`, `high`, `critical`.

---

## 3. Python Entry Points Plugin Architecture

LogLens enables third parties to ship parsers, detection rules, and alert notifiers as standard Python packages using entry points.

### Declaring Entry Points (`pyproject.toml`)

```toml
[project.entry-points."loglens.parsers"]
caddy = "my_loglens_plugin.parsers:CaddyParser"

[project.entry-points."loglens.rules"]
k8s_rules = "my_loglens_plugin.rules:get_k8s_rules"

[project.entry-points."loglens.notifiers"]
slack = "my_loglens_plugin.notifiers:SlackNotifier"
```

### Inspecting Installed Plugins
```bash
loglens plugins list
```

---

## 4. Suggested Action Export (Firewall & Mitigation)

LogLens can extract high-confidence malicious source IPs from `HIGH` and `CRITICAL` findings and generate perimeter mitigation configurations.

> [!CAUTION]
> **MANDATORY SAFETY NOTICE**:
> LogLens **NEVER** automatically applies firewall rules, ban drops, or network modifications.
> All scripts are generated as advisory configurations that must be reviewed by an administrator before deployment.

```bash
# Export an nftables blacklist set configuration
loglens export-actions report.json --target nftables --out blocklist.nft

# Export standard iptables DROP commands
loglens export-actions report.json --target iptables --out blocklist.sh

# Export Cloudflare IP Access Rules JSON
loglens export-actions report.json --target cloudflare --out cloudflare_waf.json

# Export fail2ban-client manual ban commands
loglens export-actions report.json --target fail2ban --out fail2ban_bans.sh
```
