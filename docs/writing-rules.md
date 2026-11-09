# Writing Rules for LogLens

LogLens uses a declarative, human-readable YAML rule schema to define deterministic security detection rules. Rules can match on raw event fields, regex patterns, or mined Drain3 cluster templates, and can evaluate statistical conditions over sliding time windows.

---

## Rule Specification Schema

Each rule is a standalone YAML file (e.g. `rules/builtin/ssh-bruteforce-001.yml`).

```yaml
id: ssh-bruteforce-001
title: SSH Brute Force from Single Source
description: Multiple failed SSH login attempts detected from a single source IP in a short time window.
source: sshd
match:
  template_regex: "Failed password for .* from"
  field_matches:
    action: failed_password
condition:
  group_by: ip
  count_gte: 10
  window: 5m
severity: high
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.001
references:
  - https://attack.mitre.org/techniques/T1110/001/
false_positives:
  - Misconfigured automated deployment script with an expired password
```

---

## Schema Fields Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | **Yes** | Unique identifier in kebab-case / slug format (`[a-zA-Z0-9_-]+`). |
| `title` | string | **Yes** | Concise human-readable title. |
| `description` | string | **Yes** | Clear explanation of the malicious behavior or security event. |
| `source` | string or list[string] | No | Target log source daemon (`sshd`, `web`, `syslog`, `sudo`, `kernel`). |
| `severity` | string | **Yes** | One of `critical`, `high`, `medium`, `low`, or `info`. |
| `match` | object | **Yes** | Pattern matching conditions (see below). |
| `condition` | object | No | Temporal threshold and aggregation conditions (see below). |
| `tags` | list[string] | No | MITRE ATT&CK technique IDs (e.g., `attack.t1110`) and category tags. |
| `references` | list[string] | No | External reference URLs (MITRE ATT&CK, OWASP, CVEs). |
| `false_positives` | list[string] | No | Known benign operational scenarios that could trigger the rule. |

---

## Matching Criteria (`match`)

- **`template_regex`**: Regular expression applied against the Drain3 mined template.
- **`message_regex`**: Regular expression applied directly against the log message text.
- **`field_matches`**: Exact key-value matching on normalized fields (e.g. `action: failed_password`, `status: 404`).
- **`field_regex`**: Regular expressions applied against specific field values (e.g. `path: "(\\.\\./|/etc/passwd)"`).

---

## Aggregation & Windowing (`condition`)

- **`group_by`**: The normalized field used to partition events (e.g. `ip` or `user`).
- **`count_gte`**: Minimum occurrences required within the window to trigger a finding.
- **`window`**: Time duration string such as `30s` (30 seconds), `5m` (5 minutes), `1h` (1 hour), `1d` (1 day).

---

## Validating and Testing Rules

Use the `loglens rules` CLI command to validate and test your rules:

```bash
# 1. Validate rule syntax against the Pydantic schema
loglens rules validate my-custom-rule.yml

# 2. Test rule execution against a real or synthetic log file
loglens rules test my-custom-rule.yml --against examples/sample_auth.log

# 3. List all registered built-in and custom rules
loglens rules list
```
