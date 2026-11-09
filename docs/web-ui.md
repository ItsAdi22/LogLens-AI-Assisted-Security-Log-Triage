# Web UI Dashboard (FastAPI + HTMX)

LogLens provides an optional lightweight, local-first web interface designed for sysadmins and SOC analysts to inspect historical triage runs, explore clustered log signatures, and request on-demand LLM explanations.

```bash
# Launch dashboard on http://127.0.0.1:8080
loglens serve
```

---

## 1. Key Capabilities

- **Zero JavaScript Build Step**: Built using **FastAPI**, **Jinja2**, and **HTMX** with zero node/npm build dependencies.
- **100% Offline & Self-Hosted**: Vendored HTMX assets bundled directly inside the package. Works in completely air-gapped homelabs and enterprise environments.
- **Metric Cards & Severity Breakdown**: Instant visibility into total parsed events, mined cluster patterns, and active security incidents.
- **7-Day Incident Activity Timeline**: Built-in activity trend showing event frequency and finding volume across recent ingestion runs.
- **Drain3 Cluster Explorer**: Deep inspection of mined template signatures with variable parameters (`<*>`) highlighted.
- **On-Demand AI Explanations**: Findings detected via deterministic rules include an **"Explain with AI"** HTMX trigger that calls the configured LLM provider on demand and dynamically renders root-cause forensic explanations and mitigation steps without a full page reload.

---

## 2. CLI Usage & Options

```bash
loglens serve [OPTIONS]
```

| Option | Environment Variable | Default | Description |
|---|---|---|---|
| `--host` | `LOGLENS_HOST` | `127.0.0.1` | Network interface to bind. (Defaults to localhost for security). |
| `--port` | `LOGLENS_PORT` | `8080` | Port number to listen on. |
| `--db` | `LOGLENS_DB_PATH` | `~/.config/loglens/loglens.db` | Custom SQLite database path. |
| `--token` | `LOGLENS_WEB_TOKEN` | None | Secret token required for authentication. |
| `--provider` | `LOGLENS_PROVIDER` | `ollama` | LLM backend for on-demand explanations (`ollama`, `openai_compat`, `gemini`, `anthropic`, `mock`). |
| `--model` | `LOGLENS_MODEL` | Provider default | Explicit LLM model identifier. |

---

## 3. Security Architecture

1. **Localhost-Only Default**: By default, `loglens serve` binds exclusively to `127.0.0.1` to prevent accidental network exposure.
2. **Optional Bearer Token Authentication**: When `--token <secret>` or `LOGLENS_WEB_TOKEN` is set, all dashboard pages and API endpoints require either:
   - Header: `Authorization: Bearer <secret>`
   - Query Parameter: `?token=<secret>`
3. **Strict Content Security Policy (CSP)**:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';
   ```
4. **Clickjacking & MIME Protection**:
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: strict-origin-when-cross-origin`
5. **XSS Protection**: All log templates, messages, field values, and user agents are strictly escaped using Jinja2 automatic autoescaping and `html.escape()`.

---

## 4. REST API Endpoints

The web service also exposes clean JSON endpoints for programmatic integration:

| Endpoint | Method | Description |
|---|---|---|
| `/health` | `GET` | Health check endpoint returning `{ "status": "ok", "version": "0.1.0" }`. |
| `/api/stats` | `GET` | Global summary telemetry and severity count breakdown. |
| `/api/runs` | `GET` | Historical list of all ingestion runs sorted descending. |
| `/api/runs/{run_id}` | `GET` | Full JSON export of the specified triage report. |

