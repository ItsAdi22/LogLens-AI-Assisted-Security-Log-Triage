"""Log ingestion package."""

from loglens.ingest.base import LogSource
from loglens.ingest.file import FileReader, TailReader
from loglens.ingest.multiline import group_multiline_logs
from loglens.ingest.stdin import StdinReader

__all__ = ["FileReader", "LogSource", "StdinReader", "TailReader", "group_multiline_logs"]
