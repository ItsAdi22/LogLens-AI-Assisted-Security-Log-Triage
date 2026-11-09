# ADR 0001: Initial Architecture and Design Constraints

## Status
Accepted

## Context
Security logs on self-hosted servers, homelabs, and small environments are voluminous and noisy. Traditional SIEM solutions (Wazuh, Elastic SIEM) demand heavy compute resources and complex setup. Simple regex tools like `fail2ban` lack broader incident context and explanation.

We need a lightweight, privacy-first, local-first architecture that clusters log streams, executes fast deterministic rule evaluation, and uses AI/LLMs solely on compact, redacted summaries to provide understandable triage assessments.

## Decisions

1. **Language & Packaging**:
   - Python 3.11+ using PEP 621 packaging with `hatchling` backend.
   - Strict static typing (`mypy --strict`) and Ruff formatting/linting.

2. **Core Pipeline Architecture**:
   - Streaming pipeline: Ingestion -> Parsing & Normalization -> Enrichment -> Drain3 Clustering -> Rule Matching -> Reversible Redaction -> LLM Triage -> Reporting.
   - Decoupled stages: The rule engine and clustering must function completely without an LLM (supporting `--no-llm`).

3. **Untrusted Input & Hostile Log Defense**:
   - Log lines are strictly treated as untrusted data.
   - Log summaries delivered to LLMs are bounded in XML-like data tags (`<log_data>`).
   - The LLM has zero execution privileges (no tool calling, no bash execution, no network access).
   - Structured JSON schema enforcement via Pydantic with single repair retry and fallback to deterministic rule findings.

4. **Privacy & Redaction**:
   - Automated redaction of IPv4/IPv6 addresses, credentials, email addresses, and security tokens prior to any external network dispatch.
   - Reversible token mapping stored in-memory to ensure final reports presented to the user retain actionable identifiers.

5. **Local-First Default**:
   - Default provider is local Ollama.
   - Zero telemetry and no external phone-home data collection.

## Consequences
- Requires high unit test coverage (>= 85%) across all parsers, redactors, and guard components.
- Fuzz testing via `hypothesis` will ensure parsers never crash on malformed or adversarial input.
