# Security Policy

The LogLens team takes the security of our project, our users, and their systems seriously.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## Reporting a Vulnerability

If you discover a security vulnerability within LogLens:

1. **Please do NOT disclose it publicly in an issue or discussion.**
2. Report vulnerabilities privately via [GitHub Private Vulnerability Reporting](https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage/security/advisories/new) or by emailing the project maintainers directly.
3. Include:
   - Description of the issue and potential impact
   - Minimal reproduction steps or proof-of-concept
   - Any suggested mitigations or patches

We will acknowledge receipt within 48 hours and coordinate a fix and advisory disclosure.

---

## Security Principles in LogLens

- **Log Content is Untrusted**: Log files may contain malicious payloads, escape sequences, or prompt-injection attempts. All untrusted inputs are delimited, sanitized, and bounded.
- **Redaction by Default**: Personally identifiable information, IPs, tokens, and credentials are redacted prior to external processing.
- **Zero Execution Privileges**: The AI triage component is strictly isolated: no code execution, no shell access, and no automated remediation.
- **Local-First Design**: Users can run fully self-hosted without external network transmission using Ollama.
