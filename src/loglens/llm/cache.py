"""Persistent SQLite and in-memory caching and token budget management for LLM triage."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


class LLMCache:
    """Cache LLM triage responses to eliminate redundant API calls and costs."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            # Default to in-memory if no explicit path
            self.db_path = ":memory:"
        elif isinstance(db_path, Path):
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(db_path)
        else:
            self.db_path = db_path

        self._conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS triage_cache (
                    cache_key TEXT PRIMARY KEY,
                    response_json TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def compute_key(redacted_cluster_text: str, prompt_version: str, model: str) -> str:
        """Compute deterministic SHA-256 cache key."""
        payload = f"{prompt_version}:{model}:{redacted_cluster_text}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> str | None:
        """Retrieve cached JSON string if present."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT response_json FROM triage_cache WHERE cache_key = ?", (cache_key,))
        row = cursor.fetchone()
        return str(row[0]) if row else None

    def set(
        self,
        cache_key: str,
        response_json: str,
        model: str,
        prompt_version: str,
    ) -> None:
        """Store response in cache."""
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO triage_cache
                (cache_key, response_json, model, prompt_version, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    response_json,
                    model,
                    prompt_version,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def close(self) -> None:
        """Close database connection."""
        self._conn.close()


class TokenBudget:
    """Enforces safety limits on tokens consumed per run."""

    def __init__(self, max_tokens_per_run: int = 100_000) -> None:
        self.max_tokens = max_tokens_per_run
        self.used_tokens = 0

    @property
    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def is_exhausted(self) -> bool:
        return self.used_tokens >= self.max_tokens

    def consume(self, estimated_tokens: int) -> bool:
        """Record token consumption. Returns True if within budget, False if exhausted."""
        if self.is_exhausted:
            return False
        self.used_tokens += estimated_tokens
        return True
