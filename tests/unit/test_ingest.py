"""Unit tests for file and stdin log ingestion."""

import gzip
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from loglens.ingest.file import FileReader, TailReader
from loglens.ingest.stdin import StdinReader


def test_file_reader_plain(tmp_path: Path) -> None:
    """Verify FileReader reads plain text line-by-line."""
    log_file = tmp_path / "test.log"
    log_file.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")

    reader = FileReader(log_file)
    assert not reader.is_gzip()
    lines = list(reader.stream())
    assert lines == [(1, "line 1"), (2, "line 2"), (3, "line 3")]


def test_file_reader_gzip_without_extension(tmp_path: Path) -> None:
    """Verify FileReader detects gzip file via magic bytes even without .gz extension."""
    gz_file = tmp_path / "compressed_log"
    with gzip.open(gz_file, "wt", encoding="utf-8") as f:
        f.write("magic byte line\n")

    reader = FileReader(gz_file)
    assert reader.is_gzip()
    lines = list(reader.stream())
    assert lines == [(1, "magic byte line")]


def test_file_reader_is_dir(tmp_path: Path) -> None:
    """Verify is_gzip returns False on directories."""
    reader = FileReader(tmp_path)
    assert not reader.is_gzip()


def test_file_reader_nonexistent(tmp_path: Path) -> None:
    """Verify FileReader raises FileNotFoundError on missing files."""
    reader = FileReader(tmp_path / "missing.log")
    with pytest.raises(FileNotFoundError):
        list(reader.stream())


def test_stdin_reader() -> None:
    """Verify StdinReader streams lines from sys.stdin."""
    fake_stdin = StringIO("stdin 1\nstdin 2\n")
    with patch("sys.stdin", fake_stdin):
        reader = StdinReader()
        lines = list(reader.stream())
    assert lines == [(1, "stdin 1"), (2, "stdin 2")]


def test_tail_reader_from_start(tmp_path: Path) -> None:
    """Verify TailReader can read initial content and stops cleanly."""
    log_file = tmp_path / "tail.log"
    log_file.write_text("initial 1\ninitial 2\n", encoding="utf-8")

    reader = TailReader(log_file, interval=0.01, from_start=True)
    stream = reader.stream()

    first = next(stream)
    second = next(stream)
    assert first == (1, "initial 1")
    assert second == (2, "initial 2")

    reader.stop()
    # next invocation should terminate
    remaining = list(stream)
    assert remaining == []
