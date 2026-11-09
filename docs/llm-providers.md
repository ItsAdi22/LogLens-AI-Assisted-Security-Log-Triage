# LLM Triage Providers & Configuration

LogLens supports both local and cloud-hosted Large Language Models for automated log triage. The triage engine produces structured security assessments validated against the `LLMAssessment` schema.

---

## 1. Supported Providers

| Provider | Type | Default Model | Config Requirements |
|---|---|---|---|
| `ollama` (default) | Local | `llama3.2:3b` | Running Ollama server (`http://localhost:11434`) |
| `openai` / `openai_compat` | Cloud / Local | `gpt-4o-mini` | `OPENAI_API_KEY` (or custom `--base-url`) |
| `gemini` | Cloud | `gemini-2.5-flash` | `GEMINI_API_KEY` |
| `anthropic` | Cloud | `claude-3-5-haiku-20241022` | `ANTHROPIC_API_KEY` |
| `mock` | Testing | `mock-triage-v1` | None (deterministic offline mock) |

---

## 2. Quickstart Examples

### Local Triage with Ollama (Zero Cloud Exposure)

Ensure Ollama is running and has the triage model pulled:
```bash
ollama serve
ollama pull llama3.2:3b
```

Run analysis with `--llm`:
```bash
loglens analyze /var/log/auth.log --llm --provider ollama
```

### Testing Provider Connectivity

Verify that your configured model and endpoint are reachable:
```bash
loglens providers test --provider ollama
loglens providers test --provider openai
loglens providers test --provider gemini
```

### OpenAI-Compatible Backends (LM Studio, vLLM, OpenRouter, Mistral)

Specify custom endpoints using `--base-url`:
```bash
loglens analyze /var/log/nginx/access.log --llm \
    --provider openai_compat \
    --base-url http://localhost:1234/v1 \
    --model mistral-7b-instruct
```

### Google Gemini

```bash
export GEMINI_API_KEY="your-api-key"
loglens analyze /var/log/auth.log --llm --provider gemini --agree-cloud-llm
```

### Anthropic Claude

```bash
export ANTHROPIC_API_KEY="your-api-key"
loglens analyze /var/log/auth.log --llm --provider anthropic --agree-cloud-llm
```

---

## 3. Cost & Latency Optimization

### In-Memory and SQLite Caching
LogLens computes a deterministic SHA-256 fingerprint of the prompt template, model name, and redacted cluster data. When repeated identical attacks or cron jobs are observed across analysis runs, LogLens returns cached assessments instantly with zero token consumption.

### Token Budget Guardrails
Each triage run enforces a token budget (default: 100,000 tokens). If an unexpectedly large surge of events exhausts the budget, LogLens halts further API calls and gracefully falls back to deterministic rule findings without failing the pipeline.

### Graceful Fallback
If an LLM endpoint is offline or experiences network timeouts, LogLens issues a warning and presents complete deterministic rule findings with exit code 0.
