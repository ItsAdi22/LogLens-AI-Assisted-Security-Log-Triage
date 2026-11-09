# Privacy, Anonymization, and Redaction in LogLens

Security logs frequently contain sensitive telemetry: external and internal IP addresses, user credentials embedded in query strings, JWT authorization headers, API keys, and corporate email addresses. Transmitting unredacted log data to third-party or cloud-hosted LLM endpoints poses compliance and security risks.

LogLens solves this with an in-memory, **bidirectional, reversible tokenization engine** that anonymizes data before prompt delivery and restores original values upon receipt of the structured analysis.

---

## 1. How Redaction Works

1. **Detection**: LogLens scans log lines, template strings, top extracted fields, and sample messages using high-entropy regex patterns.
2. **Tokenization**: Each sensitive indicator is replaced with a scoped surrogate placeholder (e.g. `[IP_1]`, `[EMAIL_1]`, `[TOKEN_1]`).
3. **Consistency**: Redaction is consistent across a triage run. If IP `198.51.100.42` appears in multiple clusters or sample messages, it consistently maps to `[IP_1]`.
4. **LLM Evaluation**: The LLM analyzes the cluster reasoning purely on the anonymized relationships (e.g. *"[IP_1] performed 150 failed authentications targeting admin"*).
5. **Restoration**: Once the LLM response is validated against `LLMAssessment`, all surrogate tokens in `summary`, `evidence`, and `recommended_actions` are restored back to the true indicators (e.g. *"[IP_1]"* -> *"198.51.100.42"*).

---

## 2. Redaction Levels

You can configure the redaction level via the `--redaction` CLI flag:

```bash
loglens analyze /var/log/auth.log --llm --redaction standard
```

| Level | Description | Indicators Redacted |
|---|---|---|
| `standard` (default) | Strong default protection for SOC operations. | IPv4, IPv6, Emails, JWT tokens, AWS keys, Bearer tokens, URL credentials, Query credentials (`password=...`, `token=...`), Private keys. |
| `strict` | Maximum privacy mode for multi-tenant and external audits. | All `standard` indicators + personal filesystem user directories (`/home/<user>`, `C:\Users\<user>`). |
| `off` | Raw pass-through mode. | No redaction performed. Recommended only for completely synthetic logs or offline, air-gapped deployments. |

---

## 3. Auditing Redaction (`--dry-run-llm`)

Before calling any LLM, you can inspect the exact redacted payloads and prompts using `--dry-run-llm`:

```bash
loglens analyze examples/sample_auth.log --dry-run-llm --redaction standard
```

This outputs the exact `<log_data>` block with surrogate tokens and exits with code 0 without making network requests.

---

## 4. Cloud LLM Consent Gate

LogLens guarantees that no data is transmitted to an external cloud provider (OpenAI, Gemini, Anthropic) without explicit user knowledge:

- If an interactive terminal is detected, LogLens displays a privacy disclosure and requests confirmation.
- In automated scripts or CI/CD pipelines, pass `--agree-cloud-llm` or set `LOGLENS_AGREE_CLOUD_LLM=1` to acknowledge and permit cloud transmission.
- Local providers (Ollama, local vLLM, mock) do not require cloud consent.

