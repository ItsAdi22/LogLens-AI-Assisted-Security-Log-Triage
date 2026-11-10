"""Adaptive multiplexing parser that routes lines to the best matching specialized parser."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from loglens.models import Event
from loglens.parsers.base import Parser, registry


class AdaptiveMultiParser(Parser):
    """Multiplexes incoming log streams across specialized parsers dynamically per line."""

    name: str = "adaptive"
    description: str = "Multiplexes lines dynamically across specialized parsers"

    def __init__(self, parsers: list[Parser] | None = None) -> None:
        self._custom_parsers = parsers

    def _get_parsers(self) -> list[Parser]:
        if self._custom_parsers is not None:
            return self._custom_parsers

        # Specific formats first, then syslog, then generic fallback
        ordered_names = [
            "auth",
            "laravel",
            "web",
            "fail2ban",
            "ufw",
            "database_auth",
            "minecraft",
            "docker_json",
            "syslog",
            "generic",
        ]
        resolved: list[Parser] = []
        for name in ordered_names:
            p = registry.get(name)
            if p is not None:
                resolved.append(p)
        return resolved

    def matches_sample(self, lines: Sequence[str]) -> float:
        """Adaptive parser always supports any mixed sample."""
        return 0.95

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Route the raw line to the first specialized parser that successfully yields an Event."""
        clean = raw_line.strip()
        if not clean:
            return None

        # Clean off docker prefix if present (e.g. "panel | [2026-11-10 ...]")
        stripped_line = clean
        if " | " in clean:
            parts = clean.split(" | ", 1)
            # If the right side looks like a timestamped log line, try both
            if parts[1].startswith(
                (
                    "[",
                    "20",
                    "19",
                    "{",
                    "Jan",
                    "Feb",
                    "Mar",
                    "Apr",
                    "May",
                    "Jun",
                    "Jul",
                    "Aug",
                    "Sep",
                    "Oct",
                    "Nov",
                    "Dec",
                )
            ):
                stripped_line = parts[1]

        parsers = self._get_parsers()
        for p in parsers:
            if p.name == "generic":
                continue
            try:
                ev = p.parse_line(clean, line_number, reference_dt=reference_dt)
                if ev is not None:
                    return ev
                if stripped_line != clean:
                    ev_stripped = p.parse_line(
                        stripped_line, line_number, reference_dt=reference_dt
                    )
                    if ev_stripped is not None:
                        return ev_stripped
            except Exception:
                continue

        # Fallback to generic parser
        gen = registry.get("generic")
        if gen is not None:
            return gen.parse_line(clean, line_number, reference_dt=reference_dt)
        return None
