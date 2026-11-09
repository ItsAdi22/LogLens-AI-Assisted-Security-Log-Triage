# Good First Issues for Community Contributors

Welcome to the **LogLens** open-source contributor community!

Whether you are interested in cybersecurity detection engineering, LLM prompt engineering, or high-performance Python, LogLens has plenty of beginner-friendly tasks.

Here is a curated list of well-scoped, bite-sized tasks ready for community contributors.

---

## Parser Tasks

### 1. `parser: ufw-iptables`
- **Scope**: Implement a parser for Linux `ufw.log` and `iptables` kernel firewall log lines (e.g. `[UFW BLOCK] IN=eth0 OUT= MAC=... SRC=... DST=... PROTO=TCP SPT=... DPT=...`).
- **File**: `src/loglens/parsers/ufw.py`
- **Tests**: Add unit test cases in `tests/unit/test_parsers.py` with synthetic firewall drop events.

### 2. `parser: fail2ban`
- **Scope**: Implement a parser for `/var/log/fail2ban.log` recording jail actions (e.g. `fail2ban.actions [1234]: NOTICE [sshd] Ban 198.51.100.22`).
- **File**: `src/loglens/parsers/fail2ban.py`
- **Tests**: Verify IP extraction, jail identifier, and action type (`Ban`, `Unban`).

### 3. `parser: postgresql-log`
- **Scope**: Parse PostgreSQL query and connection logs (`LOG: connection received: host=...`, `FATAL: password authentication failed for user ...`).
- **File**: `src/loglens/parsers/postgres.py`
- **Tests**: Synthetic failed authentication and fatal connection logs.

### 4. `parser: docker-daemon`
- **Scope**: Ingest Docker engine / containerd daemon logs (`dockerd`) to track container crash loops, privilege escalation warnings, and socket bindings.
- **File**: `src/loglens/parsers/docker.py`

---

## Detection Engineering & Rule Tasks

### 5. `rule: redis-unauthenticated-access`
- **Scope**: Write a YAML rule detecting unauthenticated command execution attempts or rogue `CONFIG SET` commands in Redis logs.
- **File**: `src/loglens/rules/builtin/redis_unauth.yml`
- **Tags**: MITRE ATT&CK `T1078` (Valid Accounts) / `T1200`.

### 6. `rule: apache-log4j-jndi-probe`
- **Scope**: Create a rule detecting JNDI lookup strings (`${jndi:ldap://...}`, `${jndi:rmi://...}`) in HTTP requests, headers, and query parameters.
- **File**: `src/loglens/rules/builtin/web_log4j_jndi.yml`
- **Tags**: MITRE ATT&CK `T1190` (Exploit Public-Facing Application).

### 7. `rule: sudo-nopasswd-abuse`
- **Scope**: Create a detection rule flagging unauthorized or suspicious commands executed via `sudo` with elevated privileges.
- **File**: `src/loglens/rules/builtin/auth_sudo_abuse.yml`
- **Tags**: MITRE ATT&CK `T1548.003` (Sudo and Sudo Caching).

### 8. `rule: gitlab-cve-probes`
- **Scope**: Detection rule targeting path traversal and arbitrary file read attempts against common Git/GitLab endpoint signatures.
- **File**: `src/loglens/rules/builtin/web_gitlab_cve.yml`

---

## Alerting & Integration Tasks

### 9. `notify: slack-webhook`
- **Scope**: Add a Slack notification adapter matching the Slack Block Kit messaging format.
- **File**: `src/loglens/notify/slack.py`
- **Tests**: Mocked HTTP unit test verifying Block Kit JSON serialization.

### 10. `notify: pagerduty-events-api`
- **Scope**: Add a PagerDuty Events API v2 notifier triggering incident alerts on `HIGH` and `CRITICAL` findings.
- **File**: `src/loglens/notify/pagerduty.py`

---

## Documentation & Tooling Tasks

### 11. `docs: asciinema-demo-recording`
- **Scope**: Record a 45-second terminal session using `asciinema` showcasing `loglens analyze sample_auth.log` and generate an animated SVG for `README.md`.

### 12. `cli: export-to-sigma`
- **Scope**: Implement an export helper command `loglens rules export-sigma` converting LogLens YAML rules to the Sigma rule format.

---

## How to Get Started
1. Pick any issue above and leave a comment on the GitHub issue tracker to claim it.
2. Read [CONTRIBUTING.md](https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage/blob/main/CONTRIBUTING.md) for environment setup and testing guidelines.
3. Open a Pull Request following conventional commits (`feat:`, `fix:`, `docs:`). All PRs run CI with type checking (`mypy --strict`) and linting (`ruff`).

