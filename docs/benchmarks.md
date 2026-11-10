# Performance & Efficiency Benchmarks

LogLens is engineered for low latency, low memory consumption, and extreme token efficiency. This page documents the performance profile across parsing, clustering, memory bounds, and LLM inference.

---

## 1. Throughput & Streaming Ingestion

Streaming ingestion, parsing, and Drain3 template clustering measured on a synthetic 50,000-line authentication log using `scripts/benchmark_large_file.py`:

| Metric | Measured Value |
|---|---|
| **Input Log Events** | 50,000 lines |
| **Drain3 Clusters Mined** | 14 |
| **Security Findings** | 12 |
| **Ingestion & Clustering Time** | 0.521 s |
| **Rule Evaluation Time** | 0.042 s |
| **Total Elapsed Time** | 0.563 s |
| **Throughput** | **88,810 lines/s** |
| **Peak Traced Memory (`tracemalloc`)** | **12.45 MB** |
| **Final Memory Allocation** | 4.82 MB |

> [!NOTE]
> Ingestion uses lazy generator pipelines (`yield`). Memory consumption remains strictly bounded under load; unit tests continuously enforce that streaming 5,000 events consumes strictly less than 25 MB peak RAM (`tests/unit/test_perf_bounds.py`).

---

## 2. Clustering & Token Reduction (Analytical Model)

LogLens uses the **Drain3** algorithm to distill raw log streams into template clusters prior to LLM triage. The figures below represent an analytical calculation comparing raw log forwarding against clustered triage on a synthetic 50,000-line authentication log (producing 14 clusters, as profiled in Section 1):

| Metric | Raw Log Forwarding | LogLens Clustered Triage | Savings / Reduction | Basis |
|---|---|---|---|---|
| **Input Lines** | 50,000 events | 50,000 events | - | Input dataset |
| **Units Sent to LLM** | 50,000 raw lines | 14 clusters | **99.97% reduction** | Measured (`scripts/benchmark_large_file.py`) |
| **Prompt Tokens** | ~2,500,000 tokens | ~3,500 tokens | **99.86% token savings** | Estimated (~50 tokens/line vs ~250 tokens/cluster) |
| **API Cost (Cloud GPT-4o)** | ~$6.25 | ~$0.01 | **> 99% cost reduction** | Estimated (at $2.50 / 1M input tokens) |
| **Inference Time (Sequential)** | ~4.2 hours | ~4.2 s | **~3,500x faster** | Estimated (14 clusters × 300ms vs 50k lines sequential) |

---

## 3. LLM Triage Latency & Evaluation

Evaluation execution timings for triage assessment using the test suite runner (`python -m tests.eval.run`):

| Provider | Model | Workload | Latency | Assessment Success Rate | Basis |
|---|---|---|---|---|---|
| **Mock Provider** | Deterministic Test Mock | 12 evaluation scenarios | 0.08 s | 100.0% | Measured (`tests/eval/run.py`) |

> [!NOTE]
> LogLens supports local inference via Ollama (`llama3.2`, `mistral`, etc.) and cloud providers (Gemini, OpenAI, Anthropic). Cloud latencies and rate limits depend on remote API availability and network transit, and are therefore omitted from deterministic local benchmarks.

---

## 4. Large-File & Memory Profiling Suite

LogLens provides an automated profiling tool in `scripts/benchmark_large_file.py` to evaluate throughput and peak memory allocations under heavy load:

```bash
# Benchmark against 50,000 synthetic log lines
python scripts/benchmark_large_file.py test_large.log --max-lines 50000
```

Memory boundedness is continuously enforced via unit tests (`tests/unit/test_perf_bounds.py`), ensuring that parsing and clustering 5,000 log events consumes strictly less than 25 MB of peak RAM.

---

## 5. Benchmark Reproduction

You can reproduce the evaluation, clustering, and throughput benchmarks locally:

```bash
# Run deterministic unit performance tests
pytest tests/unit/test_perf_bounds.py -v

# Run the triage benchmark suite using the deterministic mock provider
python -m tests.eval.run --provider mock

# Benchmark against local Ollama
python -m tests.eval.run --provider ollama --model llama3.2

# Generate synthetic attack logs for throughput stress testing
python scripts/gen_synthetic_logs.py --count 100000 --out test_large.log
python scripts/benchmark_large_file.py test_large.log
```
