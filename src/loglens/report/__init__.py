"""Reporting package for LogLens (Markdown, JSON, HTML)."""

from loglens.report.base import ReportFormatter
from loglens.report.html import HTMLReportFormatter, generate_html_report
from loglens.report.json import JSONReportFormatter, generate_json_report
from loglens.report.markdown import MarkdownReportFormatter, generate_markdown_report

__all__ = [
    "HTMLReportFormatter",
    "JSONReportFormatter",
    "MarkdownReportFormatter",
    "ReportFormatter",
    "generate_html_report",
    "generate_json_report",
    "generate_markdown_report",
]
