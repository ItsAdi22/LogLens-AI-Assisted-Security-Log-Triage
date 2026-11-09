"""Log ingestion package."""

from loglens.ingest.base import LogSource
from loglens.ingest.file import FileReader, TailReader
from loglens.ingest.stdin import StdinReader

__all__ = ["FileReader", "LogSource", "StdinReader", "TailReader"]
