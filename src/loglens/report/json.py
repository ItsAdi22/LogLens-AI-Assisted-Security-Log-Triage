"""JSON report formatter for LogLens triage reports."""

from __future__ import annotations

from loglens.models import Report


def generate_json_report(report: Report, indent: int = 2) -> str:
    """Serialize Report into stable JSON representation."""
    return report.model_dump_json(indent=indent)


class JSONReportFormatter:
    """Renders Report into JSON string."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def format(self, report: Report) -> str:
        return generate_json_report(report, indent=self.indent)
