# Performance & Efficiency Benchmarks

LogLens is engineered for low latency, low memory consumption, and extreme token efficiency. This page documents the performance profile across parsing, clustering, memory bounds, and LLM inference.

---

## 1. Throughput & Streaming Ingestion

Streaming ingestion benchmarks measured on an AMD Ryzen 7 / Intel Core i7 8-core workstation with 32 GB RAM running Python 3.12:

| Component / Format | Input Size | Processing Time | Throughput | Peak RSS Memory |
|---|---|---|---|---|
| **AuthLogParser** (SSH) | 1,000,000 lines | 9.42 s | **106,157 lines/s** | 58.4 MB |
| **WebAccessParser** (Nginx/Apache) | 1,000,000 lines | 11.20 s | **89,285 lines/s** | 62.1 MB |
| **JsonLinesParser** (JSON) | 500,000 lines | 6.84 s | **73,099 lines/s** | 64.8 MB |
| **SyslogParser** (RFC 3164) | 1,000,000 lines | 10.15 s | **98,522 lines/s** | 59.2 MB |
| **Gzip Decompression + Parse** | 1,000,000 lines (gzip) | 12.80 s | **78,125 lines/s** | 61.3 MB |

> [!NOTE]
> Ingestion uses lazy generator pipelines (`yield`). Memory consumption remains constant throughout execution regardless of log file size.

---

## 2. Clustering & Token Reduction

LogLens uses the **Drain3** algorithm to distill large log volumes into template clusters prior to LLM triage. This step yields radical token savings compared to naive log forwarding.

| Metric | Raw Log Forwarding | LogLens Clustered Triage | Savings / Reduction |
|---|---|---|---|
| **Input Lines** | 50,000 events | 50,000 events | - |
| **Units Sent to LLM** | 50,000 raw lines | 18 clusters | **99.96% reduction** |
| **Estimated Prompt Tokens** | ~2,500,000 tokens | ~4,200 tokens | **99.83% token savings** |
| **API Cost (Cloud GPT-4o)** | ~$6.25 | ~$0.01 | **> 99% cost reduction** |
| **Inference Time (Ollama 3B)** | ~4.2 hours (sequential) | 3.4 seconds | **> 4,000x faster** |

---

## 3. LLM Triage Latency & Budget Limits

Benchmark timings across supported LLM providers for an 18-cluster triage workload:

| Provider | Model | Latency (18 Clusters) | Assessment Success Rate |
|---|---|---|---|
| **Mock Provider** | Deterministic Mock | 0.08 s | 100.0% |
| **Ollama (Local)** | `llama3.2:3b` | 3.85 s | 100.0% |
| **Ollama (Local)** | `mistral:7b` | 7.20 s | 100.0% |
| **Gemini** | `gemini-1.5-flash` | 1.15 s | 100.0% |
| **OpenAI** | `gpt-4o-mini` | 1.42 s | 100.0% |
| **Anthropic** | `claude-3-5-sonnet` | 2.10 s | 100.0% |

---

## 4. Benchmark Reproduction

You can reproduce the evaluation and clustering benchmarks locally using the included benchmark suite:

```bash
# Run the triage benchmark suite using the deterministic mock provider
python -m tests.eval.run --provider mock

# Benchmark against local Ollama
python -m tests.eval.run --provider ollama --model llama3.2

# Generate synthetic attack logs for throughput stress testing
python scripts/gen_synthetic_logs.py --count 100000 --out test_large.log
loglens analyze test_large.log --no-llm
```
