# Contributing to LogLens

Thank you for your interest in contributing to **LogLens**! We are committed to building a clean, modern, privacy-first security log triage tool.

---

## Code of Conduct

All contributors and participants are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Branch Protection & Development Flow

1. The `main` branch is always kept green and deployable. Direct pushes to `main` in production are restricted.
2. Develop features and fixes in feature branches (`feat/auth-parser`, `fix/redaction-ipv6`, etc.).
3. Submit a Pull Request targeting `main`. All CI checks (linting, static type checking, unit tests) must pass before merging.
4. Keep commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat:` New features
   - `fix:` Bug fixes
   - `docs:` Documentation only changes
   - `test:` Adding or updating tests
   - `refactor:` Code change that neither fixes a bug nor adds a feature
   - `chore:` Maintenance tasks, dependency updates

---

## Security Guidelines

- **Never commit real logs or sensitive data**. Always use synthetic or sanitized fixtures in `tests/fixtures/` and `examples/`.
- Log content is treated as **untrusted input**. Ensure log data is never treated as instructions by LLM prompts.
- Do not introduce telemetry or tracking.
- Dependencies should remain minimal and audited.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ItsAdi22/LogLens-AI-Assisted-Security-Log-Triage.git
   cd LogLens-AI-Assisted-Security-Log-Triage
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies in editable mode:**
   ```bash
   pip install -e ".[all]"
   ```

4. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

---

## Quality Checks

Run the following before submitting a pull request:

```bash
# Lint & format check
ruff check .
ruff format --check .

# Type checking
mypy --strict src tests

# Run unit tests
pytest --cov=src/loglens --cov-report=term-missing
```

---

## Architecture Decisions (ADRs)

If a change introduces significant architectural choices or assumptions, please record an Architecture Decision Record in `docs/decisions/NNNN-title.md`.
