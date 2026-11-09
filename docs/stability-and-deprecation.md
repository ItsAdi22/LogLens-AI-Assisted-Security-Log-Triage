# Stability Guarantees & Deprecation Policy

LogLens adheres to strict semantic stability and backward compatibility guarantees starting from **v1.0.0**. This document outlines the compatibility contract for the CLI, public Python APIs, configuration schema, report output formats, and database migrations.

---

## 1. Semantic Versioning (SemVer 2.0.0)

LogLens strictly follows [Semantic Versioning 2.0.0](https://semver.org/):

$$\text{MAJOR} . \text{MINOR} . \text{PATCH}$$

- **MAJOR (e.g., 1.x.x $\to$ 2.0.0)**:
  - Incompatible API modifications, breaking configuration changes, removal of deprecated flags, or major schema redesigns.
  - Breaking changes will never occur within the `1.x.y` lifecycle.
- **MINOR (e.g., 1.0.0 $\to$ 1.1.0)**:
  - Backwards-compatible feature additions:
    - New log parsers and detection rule packs.
    - Additional LLM provider integrations.
    - New notification exporters or reporting formats.
    - Additional CLI subcommands or non-breaking flags.
- **PATCH (e.g., 1.0.0 $\to$ 1.0.1)**:
  - Backwards-compatible bug fixes, security patches, parser regex refinements, and internal performance optimizations.

---

## 2. Interface Stability Contracts

### 2.1 CLI Flags & Subcommands
- **Core Commands**: Subcommands (`analyze`, `watch`, `report`, `explain`, `rules`, `providers`, `serve`) have frozen argument interfaces.
- **Exit Code Guarantees**:
  - `0`: Execution completed successfully; no findings at or above the configured alert threshold.
  - `1`: System error (file not found, parser crash, unhandled runtime exception, invalid configuration).
  - `2`: Security findings detected at or above the alert threshold (enabling CI/CD pipeline blocking).
- **Configuration Precedence**:
  1. CLI command-line options (`--provider`, `--since`, etc.)
  2. Environment variables (`LOGLENS_PROVIDER`, `LOGLENS_DB_PATH`, etc.)
  3. User configuration file (`~/.config/loglens/config.yml`)
  4. Built-in defaults

### 2.2 Report Schema Stability (`1.0.0`)
- The JSON triage report schema is locked to version `1.0.0`:
  ```json
  {
    "metadata": {
      "schema_version": "1.0.0",
      "generated_at": "...",
      "log_source": "...",
      "total_lines": 100,
      "parsed_events": 98,
      "unparsed_lines": 2,
      "total_clusters": 5,
      "findings_count": 2
    },
    "findings": [...],
    "clusters": [...],
    "stats": {...}
  }
  ```
- **Forward Compatibility**: In the `1.x` release series, fields will **never** be removed or renamed in the JSON report output. Any new fields will be optional.

### 2.3 SQLite Storage Schema
- SQLite database migrations are tracked via `schema_migrations` table and `PRAGMA user_version`.
- Database schemas are designed for forward compatibility. Older `1.x` clients can safely read data produced by newer `1.x` clients.

---

## 3. Deprecation Window & Lifecycle

When a feature, CLI flag, or Python API function is scheduled for retirement:

1. **Announcement**: The deprecation is marked in the documentation and listed in `CHANGELOG.md` under the `Deprecated` section.
2. **Runtime Warning**: The affected component emits a `DeprecationWarning` or CLI warning indicating the recommended replacement.
3. **Deprecation Window**: Deprecated functionality will remain operational for a **minimum of two minor releases** (e.g., a feature deprecated in `1.1.0` remains functional throughout `1.2.x` and `1.3.x` before any potential removal in `2.0.0`).
4. **Removal**: Deprecated functionality is only removed in a **major release** (`v2.0.0`).
