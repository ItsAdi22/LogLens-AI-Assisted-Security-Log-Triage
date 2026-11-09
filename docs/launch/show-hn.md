# Show HN: LogLens – AI-Assisted Security Log Triage (100% Offline via Ollama)

**URL**: https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage

**Title**: Show HN: LogLens – AI-assisted security log triage for self-hosters (100% offline via Ollama)

---

### Body

Hey HN,

I built **LogLens** because running a home server, VPS, or homelab usually means one of two extremes:
1. Drowning in gigabytes of raw SSH and Nginx logs, trying to `grep` for anomalies while missing distributed brute-force attacks.
2. Setting up a heavyweight SIEM (Elastic/Wazuh) that eats 8GB+ RAM, runs half a dozen JVM processes, and takes days to configure.

LogLens is a lightweight (under 65MB RAM constant), local-first, privacy-respecting security log triage CLI and web dashboard written in Python 3.11+.

### The Core Problem: Why LLMs Shouldn't See Raw Log Lines
If you pipe 50,000 raw log lines directly into an LLM context window:
1. You burn millions of tokens (and hundreds of dollars on cloud APIs).
2. You hit context-window exhaustion and rate limits.
3. You risk massive prompt injection vulnerabilities from attacker-controlled user agents and usernames.
4. You leak PII, private IPs, and session tokens.

### How LogLens Solves This:
1. **Streaming Ingestion & Auto-detection**: Automatically identifies auth.log, Nginx/Apache access logs, Fail2ban, UFW, PostgreSQL/MySQL, Minecraft server logs, and Docker JSON lines.
2. **Drain3 Template Clustering**: Compresses 50,000 raw lines down to ~15 signature templates (a **99.96% token reduction**).
3. **Deterministic MITRE ATT&CK Rules Engine**: 18+ built-in YAML rules evaluate brute-force thresholds, credential access, rare templates, and volume drops before any AI involvement.
4. **Reversible Token Redaction**: Masks IPv4/6, emails, Bearer tokens, JWTs, and AWS access keys *prior* to triage.
5. **Prompt-Injection Quarantine**: Log content is strictly isolated inside `<untrusted_log_cluster>` boundary tags. The model is given zero tools, zero network access, and zero code execution permissions. Responses are strictly validated against a Pydantic JSON schema.
6. **Local-First AI Triage**: Runs 100% offline with local Ollama models (`llama3.2:3b`, `mistral:7b`), or optionally connects to cloud models (Claude, OpenAI, Gemini).
7. **Actionable Outputs**:
   - Executive Markdown & XSS-safe single-file HTML reports.
   - Real-time Telegram and Discord notifications with cooldown deduplication.
   - FastAPI + HTMX interactive web dashboard (`loglens serve`).
   - Advisory perimeter firewall script exporter for `nftables`, `iptables`, `fail2ban`, and Cloudflare.

### Quickstart (3 Commands)
```bash
pipx install loglens

# Run 100% offline without LLM setup (rule-only mode)
loglens analyze /var/log/auth.log --no-llm

# Or triage with local Ollama and render an interactive HTML dashboard
loglens analyze /var/log/nginx/access.log --llm --provider ollama --out report.html
```

Docker Compose with Ollama included:
```bash
docker compose up -d
docker compose exec loglens loglens analyze /logs/auth.log --llm --provider ollama
```

### Benchmarks & Audits:
- Throughput: **> 88,000 lines/second** on multi-pattern workloads.
- Memory: Strictly bounded at **< 25 MB RAM** across 5,000 parsed events and Drain3 clusters.
- Security: Audited using Cloudflare's open-source adversarial `security-audit-skill` with 0 confirmed vulnerabilities.

Code, docs, and Docker setup are all on GitHub under Apache-2.0:
https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage

Would love to hear your thoughts, feedback, and what log formats or rules you'd like to see next!
