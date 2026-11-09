"""Base abstractions for log ingestion."""

from collections.abc import Iterator
from typing import Protocol


class LogSource(Protocol):
    """Protocol for log sources producing raw lines with line numbers."""

    def stream(self) -> Iterator[tuple[int, str]]:
        """Yield (line_number, raw_line) tuples."""
        ...
