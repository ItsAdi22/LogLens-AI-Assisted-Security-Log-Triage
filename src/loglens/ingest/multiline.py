"""Multiline log aggregator combining stack traces and indented continuations."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

# Headers that typically indicate the start of a new log entry
START_PATTERNS = re.compile(
    r"^(?:"
    r"\[\d{4}-\d{2}-\d{2}"  # [2026-11-10 ... (Laravel, Monolog, Minecraft)
    r"|\d{4}-\d{2}-\d{2}"  # 2026-11-10 ... (ISO, MySQL, Docker)
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+"  # Nov 10 ... (Syslog, Linux auth)
    r"|\{\s*\""  # {"log":... (JSON lines)
    r"|\d{1,3}(?:\.\d{1,3}){3}\s+"  # 192.168.1.1 ... (Web access)
    r")"
)

# Patterns that indicate a line is a stack trace continuation of the previous entry
CONTINUATION_PATTERNS = re.compile(
    r"^(?:"
    r"#\d+\s+"  # #0 /var/www/... (PHP/Laravel/Ruby stack frame)
    r"|\[stacktrace\]"  # [stacktrace]
    r"|at\s+"  # at org.foo... (Java/Node/PHP trace)
    r"|File\s+\""  # File "/app/... (Python traceback)
    r"|Traceback\s+\(most"  # Traceback (most recent call last):
    r"|Caused\s+by:"  # Caused by: ...
    r"|\.\.\.\s+\d+\s+more"  # ... 24 more
    r"|[\t ]+"  # Indented continuation
    r"|\"\s*\}?\s*$"  # Closing JSON context e.g. "}
    r")"
)


def group_multiline_logs(lines: Iterable[str]) -> Iterator[tuple[int, str, list[str]]]:
    """Group lines into (line_number, primary_line, list_of_continuation_lines).

    Aggregates multi-line exceptions, stack traces, and indented continuations into a single
    logical log event, preventing fragmented stack frames from distorting template clustering.
    """
    current_line_num: int = 0
    current_primary: str | None = None
    current_continuations: list[str] = []

    for idx, raw_line in enumerate(lines, 1):
        sline = raw_line.strip()
        if not sline:
            continue

        is_continuation = bool(CONTINUATION_PATTERNS.match(sline))
        is_new_header = bool(START_PATTERNS.match(sline))

        if current_primary is None:
            current_line_num = idx
            current_primary = raw_line
            current_continuations = []
        elif is_continuation or (not is_new_header and not is_continuation):
            current_continuations.append(raw_line)
        else:
            # Yield accumulated event
            yield current_line_num, current_primary, current_continuations
            current_line_num = idx
            current_primary = raw_line
            current_continuations = []

    if current_primary is not None:
        yield current_line_num, current_primary, current_continuations
