"""Base protocol and utilities for triage report generation."""

from typing import Protocol

from loglens.models import Report


class ReportFormatter(Protocol):
    """Protocol for transforming a Report into an output representation."""

    def format(self, report: Report) -> str:
        """Render report into a string format."""
        ...
