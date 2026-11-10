"""Fallback generic log parser that gracefully handles arbitrary log lines."""

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from loglens.models import Event, compute_raw_hash
from loglens.parsers.base import extract_common_system_fields

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
ISO_TS_REGEX = re.compile(
    r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?\b"
)


class GenericParser:
    """Fallback parser for unstructured or unclassified log streams."""

    name = "generic"
    description = "Fallback generic line-based parser"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Fallback parser has low non-zero score so specialized parsers take precedence."""
        return 0.1 if sample_lines else 0.0

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse arbitrary line into an Event."""
        line = raw_line.strip()
        if not line:
            return None

        # Look for an embedded ISO timestamp
        ts: datetime | None = None
        ts_match = ISO_TS_REGEX.search(line)
        if ts_match:
            try:
                ts_str = ts_match.group(0).replace(" ", "T")
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
            except ValueError:
                pass

        if not ts:
            ts = reference_dt or datetime.now(UTC)

        fields: dict[str, Any] = {}
        ip_match = IP_REGEX.search(line)
        if ip_match:
            fields["ip"] = ip_match.group(0)

        extract_common_system_fields(line, fields)

        # Detect severity hint from common keywords
        lower = line.lower()
        severity_hint = "info"
        if "crit" in lower or "fatal" in lower:
            severity_hint = "critical"
        elif "err" in lower or "fail" in lower:
            severity_hint = "error"
        elif "warn" in lower:
            severity_hint = "warning"

        return Event(
            ts=ts,
            source="generic",
            host=None,
            severity_hint=severity_hint,
            message=line,
            fields=fields,
            raw_hash=compute_raw_hash(raw_line),
        )
