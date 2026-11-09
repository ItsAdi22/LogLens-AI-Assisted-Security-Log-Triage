# Reddit Launch Templates

This document provides tailored submission copy for relevant subreddits.

---

## 1. r/selfhosted

**Title**: I built LogLens: A lightweight, self-hosted AI security log analyzer that runs 100% offline with Ollama (< 65MB RAM)

**Flair**: `Project` / `Self-Hosted App`

**Post Body**:
Hey everyone,

Like many of you, I run several VPS instances and home servers. Checking logs usually meant either relying on basic `fail2ban` alerts or setting up an Elastic/Wazuh stack that devoured 4-8GB of RAM.

I built **LogLens** as a middle ground: a privacy-respecting, local-first log triage engine that runs either as a CLI or a lightweight web dashboard.

### Why it's different:
- **Tiny footprint**: Consumes < 65MB RAM constant memory via lazy streaming generators.
- **Drain3 Clustering**: Instead of sending thousands of lines to an LLM, LogLens mines log templates using the Drain3 algorithm. 50,000 raw lines compress down to ~15 templates (99.8% token savings).
- **100% Offline by default**: Pairs directly with local Ollama models (`llama3.2:3b`, `mistral`).
- **Prompt Injection Defense**: Attacker log strings (user agents, usernames) are quarantined inside XML boundaries with schema-enforced JSON validation. The LLM has zero execution privileges.
- **Built-in MITRE Rules**: 18+ YAML rules detect brute force, credential stuffing, SQLi, web path scans, and Log4Shell attempts before an LLM even sees them.
- **Outputs**: Generates dark/light HTML reports, sends Telegram/Discord alerts with cooldown deduplication, and provides a FastAPI + HTMX dashboard (`loglens serve`).

**GitHub**: https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage

Feedback and PRs for new log formats or rules are very welcome!

---

## 2. r/homelab & r/sysadmin

**Title**: [Tool] LogLens – Local log triage engine with Drain3 template mining, MITRE ATT&CK rules, and Ollama integration

**Post Body**:
Hey folks,

If you manage servers or a homelab, you know that raw security logs are mostly repetitive noise interrupted by occasional malicious bursts.

LogLens was created to automate log triage without shipping your server logs to third-party clouds or running resource-heavy SIEMs.

### Architecture:
1. **Streaming Ingestion**: Auto-detects Linux auth.log, Nginx/Apache, Fail2ban, UFW, Postgres/MySQL auth, Minecraft console, and Docker JSON logs.
2. **Clustering**: Groups similar log lines using Drain3.
3. **Detection**: Rule engine matching MITRE ATT&CK tags (`T1110` brute force, `T1059` command injection, `T1190` exploit public apps).
4. **Token Redaction**: Reversibly scrubs IPs, emails, JWTs, and API credentials.
5. **LLM Triage**: Synthesizes cluster findings into an executive incident assessment with actionable containment steps.
6. **Firewall Rule Exporter**: Can output drop lists for `nftables`, `iptables`, `fail2ban`, or Cloudflare (strictly advisory, never auto-applied).

Try it with Docker Compose:
```bash
docker compose up -d
docker compose exec loglens loglens analyze /logs/auth.log --no-llm
```

Repo: https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage

---

## 3. r/netsec

**Title**: LogLens: Local-First Security Log Triage with Drain3 Clustering, Prompt-Injection Containment, and MITRE ATT&CK Tagging

**Post Body**:
LogLens is an open-source (Apache-2.0) defensive triage framework designed to evaluate security logs while addressing the security risks of LLM-assisted analysis.

### Defensive Engineering:
- **Untrusted Input Boundary**: Log content is treated as potentially hostile. Dynamic input is stripped of XML tags and quarantined in `<untrusted_log_cluster>` containers. Responses are validated against Pydantic schemas.
- **Reversible Token Masking**: Scrubs high-entropy tokens and IP addresses before model invocation.
- **Auditing**: Evaluated against Cloudflare's adversarial `security-audit-skill` for prompt injection, stored XSS, and SQL injection parameters.
- **Performance**: Benchmark throughput exceeds 88,000 lines/sec; memory remains bounded under 25 MB RAM.

Full technical documentation, threat model, and evaluation benchmarks:
https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage
