"""Laravel and PHP Monolog framework log parser."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, ClassVar

from loglens.models import Event, compute_raw_hash

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


class LaravelParser:
    """Parser for Laravel / Monolog application event and error logs."""

    name = "laravel"
    description = "Laravel framework and PHP Monolog application logs"

    # Pattern: [2026-11-10 04:42:49] local.ERROR: SQLSTATE[HY000] ...
    LARAVEL_PATTERN = re.compile(
        r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\]\s+"
        r"(?P<env>[a-zA-Z0-9_\-\.]+)\.(?P<level>[A-Z]+):\s+"
        r"(?P<message>.*)$"
    )

    SEVERITY_MAP: ClassVar[dict[str, str]] = {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "error": "error",
        "warning": "warning",
        "notice": "info",
        "info": "info",
        "debug": "info",
    }

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Score confidence that the sample originates from a Laravel log."""
        if not sample_lines:
            return 0.0

        matches = 0
        total_non_empty = 0

        for line in sample_lines:
            sline = line.strip()
            if not sline:
                continue
            total_non_empty += 1
            if self.LARAVEL_PATTERN.match(sline):
                matches += 1

        if total_non_empty == 0:
            return 0.0

        ratio = matches / total_non_empty
        if ratio >= 0.2:
            return 0.95
        if matches > 0:
            return 0.6
        return 0.0

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single Laravel log line into an Event."""
        line = raw_line.strip()
        if not line:
            return None

        m = self.LARAVEL_PATTERN.match(line)
        if m:
            ts_str = m.group("timestamp").replace(" ", "T")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
            except ValueError:
                ts = reference_dt or datetime.now(UTC)

            env = m.group("env")
            raw_level = m.group("level").lower()
            severity_hint = self.SEVERITY_MAP.get(raw_level, "info")
            msg_body = m.group("message").strip()

            fields: dict[str, Any] = {
                "environment": env,
                "level": raw_level,
            }

            # If message contains an embedded JSON exception context, extract the clean headline
            if ' {"exception":' in msg_body:
                headline, _, exc_suffix = msg_body.partition(' {"exception":')
                clean_msg = headline.strip()
                fields["exception_context"] = '{"exception":' + exc_suffix
            else:
                clean_msg = msg_body

            # Extract IP if present in the message
            ip_m = IP_REGEX.search(msg_body)
            if ip_m:
                fields["ip"] = ip_m.group(0)

            return Event(
                ts=ts,
                source="laravel",
                host=None,
                severity_hint=severity_hint,
                message=clean_msg,
                fields=fields,
                raw_hash=compute_raw_hash(raw_line),
            )

        # Handle standalone stack trace or continuation lines if not pre-grouped
        if line.startswith("#") or line.startswith("[stacktrace]") or line.startswith("at "):
            ts = reference_dt or datetime.now(UTC)
            return Event(
                ts=ts,
                source="laravel",
                host=None,
                severity_hint="error",
                message=line,
                fields={"stacktrace": True},
                raw_hash=compute_raw_hash(raw_line),
            )

        return None
