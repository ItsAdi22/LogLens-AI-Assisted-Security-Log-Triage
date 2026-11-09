"""Standard input log reader."""

import sys
from collections.abc import Iterator


class StdinReader:
    """Streams lines from sys.stdin."""

    def stream(self) -> Iterator[tuple[int, str]]:
        """Yield (line_number, line) tuples from stdin."""
        for line_num, line in enumerate(sys.stdin, start=1):
            yield line_num, line.rstrip("\r\n")
