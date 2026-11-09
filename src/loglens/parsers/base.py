"""Base abstractions, protocol, and registry for log parsers."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol

from loglens.models import Event


def resolve_syslog_timestamp(
    month_str: str,
    day_str: str,
    time_str: str,
    *,
    reference_dt: datetime | None = None,
) -> datetime:
    """Parse a legacy syslog timestamp without a year (e.g. 'Oct 11 14:32:10').

    Handles year rollover (e.g. log in December analyzed in January).
    """
    ref = reference_dt or datetime.now(UTC)
    current_year = ref.year

    # Standard 3-letter month lookup
    months = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }
    month = months.get(month_str.capitalize(), 1)
    day = int(day_str)
    hour, minute, second = (int(x) for x in time_str.split(":"))

    try:
        candidate = datetime(current_year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        # Handle leap year edge cases
        candidate = datetime(current_year, month, min(day, 28), hour, minute, second, tzinfo=UTC)

    # If candidate is more than ~30 days in the future, assume it occurred late last year
    delta_days = (candidate - ref).days
    if delta_days > 30:
        candidate = candidate.replace(year=current_year - 1)

    return candidate


class Parser(Protocol):
    """Protocol for log parser implementations."""

    name: str
    description: str

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Return a confidence score between 0.0 and 1.0 for given sample lines."""
        ...

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single line into a normalized Event, or None if malformed/unparseable."""
        ...


class ParserRegistry:
    """Registry for available log parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def register(self, parser: Parser) -> None:
        """Register a parser instance."""
        self._parsers[parser.name] = parser

    def get(self, name: str) -> Parser | None:
        """Get parser by name."""
        return self._parsers.get(name)

    def list_all(self) -> list[Parser]:
        """List all registered parsers."""
        return list(self._parsers.values())

    def autodetect(self, sample_lines: Sequence[str], threshold: float = 0.3) -> Parser:
        """Autodetect the best parser for the sample lines.

        Returns the best matching parser or falls back to 'generic'.
        """
        cleaned_samples = [line.strip() for line in sample_lines if line.strip()][:50]
        if not cleaned_samples:
            generic = self.get("generic")
            if generic is not None:
                return generic
            raise RuntimeError("No parsers registered")

        best_parser: Parser | None = None
        best_score = -1.0

        for parser in self._parsers.values():
            if parser.name == "generic":
                continue
            try:
                score = parser.matches_sample(cleaned_samples)
                if score > best_score:
                    best_score = score
                    best_parser = parser
            except Exception:
                continue

        if best_parser is not None and best_score >= threshold:
            return best_parser

        generic_fallback = self.get("generic")
        if generic_fallback is not None:
            return generic_fallback

        return next(iter(self._parsers.values()))


# Global parser registry instance
registry = ParserRegistry()
