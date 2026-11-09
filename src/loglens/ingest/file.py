"""File-based log reader supporting plain text, gzip, and rotation-aware tailing."""

import gzip
import os
import time
from collections.abc import Iterator
from pathlib import Path


class FileReader:
    """Streams lines from a plain-text or gzipped log file."""

    def __init__(self, path: str | Path, *, encoding: str = "utf-8") -> None:
        """Initialize FileReader with target file path and encoding."""
        self.path = Path(path)
        self.encoding = encoding

    def is_gzip(self) -> bool:
        """Check if file is gzip-compressed either by extension or magic bytes."""
        if self.path.suffix.lower() == ".gz":
            return True
        if not self.path.exists() or self.path.is_dir():
            return False
        try:
            with open(self.path, "rb") as f:
                return f.read(2) == b"\x1f\x8b"
        except OSError:
            return False

    def stream(self) -> Iterator[tuple[int, str]]:
        """Yield (line_number, line_str) tuples from the file."""
        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        if self.is_gzip():
            with gzip.open(self.path, "rt", encoding=self.encoding, errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    yield line_num, line.rstrip("\r\n")
        else:
            with open(self.path, encoding=self.encoding, errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    yield line_num, line.rstrip("\r\n")


class TailReader:
    """Streams new lines from an actively written log file with logrotate awareness."""

    def __init__(
        self,
        path: str | Path,
        *,
        interval: float = 1.0,
        from_start: bool = False,
        encoding: str = "utf-8",
    ) -> None:
        """Initialize TailReader with file path, polling interval, and position."""
        self.path = Path(path)
        self.interval = interval
        self.from_start = from_start
        self.encoding = encoding
        self._stop = False

    def stop(self) -> None:
        """Signal reader to stop tailing loop."""
        self._stop = True

    def stream(self) -> Iterator[tuple[int, str]]:
        """Continuously yield (line_number, line) as new lines are appended."""
        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        stat = self.path.stat()
        current_ino = getattr(stat, "st_ino", None)
        line_num = 0

        with open(self.path, encoding=self.encoding, errors="replace") as f:
            if not self.from_start:
                f.seek(0, os.SEEK_END)

            while not self._stop:
                line = f.readline()
                if line:
                    line_num += 1
                    yield line_num, line.rstrip("\r\n")
                    continue

                time.sleep(self.interval)

                # Check for file rotation or truncation
                if not self.path.exists():
                    continue

                try:
                    new_stat = self.path.stat()
                    new_ino = getattr(new_stat, "st_ino", None)

                    # Inode changed or file truncated
                    if (current_ino is not None and new_ino != current_ino) or (
                        new_stat.st_size < f.tell()
                    ):
                        f.close()
                        f = open(self.path, encoding=self.encoding, errors="replace")  # noqa: SIM115
                        current_ino = new_ino
                except OSError:
                    continue
