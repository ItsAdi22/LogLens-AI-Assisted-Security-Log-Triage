"""Unit tests for multiline log aggregation."""

from __future__ import annotations

from loglens.ingest.multiline import group_multiline_logs


def test_group_multiline_laravel_stacktrace() -> None:
    lines = [
        '[2026-11-10 04:42:49] local.ERROR: Command \'p:egg:update-index\' failed with exit code 1. {"exception":"[object] (Exception(code: 0): ...)"}',
        "#0 /var/www/pterodactyl/app/Console/Kernel.php(100): Illuminate\\Console\\Command->run()",
        "#1 /var/www/pterodactyl/vendor/laravel/framework/src/Illuminate/Console/Scheduling/ScheduleRunCommand.php(42): ...",
        "#2 [internal function]: ...",
        '"}',
        "[2026-11-10 04:42:50] local.INFO: Next task scheduled successfully.",
    ]

    events = list(group_multiline_logs(lines))
    assert len(events) == 2

    # First event grouped lines 1..5
    idx1, primary1, continuations1 = events[0]
    assert idx1 == 1
    assert "p:egg:update-index" in primary1
    assert len(continuations1) == 4
    assert "#0" in continuations1[0]
    assert "#1" in continuations1[1]

    # Second event is line 6
    idx2, primary2, continuations2 = events[1]
    assert idx2 == 6
    assert "Next task scheduled" in primary2
    assert continuations2 == []


def test_group_multiline_python_traceback() -> None:
    lines = [
        "2026-11-10 10:00:00 [ERROR] Unhandled exception occurred in worker process",
        "Traceback (most recent call last):",
        '  File "/app/main.py", line 45, in handle_request',
        "    res = db.query()",
        '  File "/app/db.py", line 12, in query',
        '    raise ConnectionError("Failed to connect to primary node")',
        "ConnectionError: Failed to connect to primary node",
        "2026-11-10 10:00:01 [INFO] Worker restart initiated",
    ]

    events = list(group_multiline_logs(lines))
    assert len(events) == 2

    idx1, primary1, continuations1 = events[0]
    assert idx1 == 1
    assert "Unhandled exception" in primary1
    assert len(continuations1) == 6
    assert any("Traceback" in c for c in continuations1)
    assert any("ConnectionError" in c for c in continuations1)

    idx2, primary2, continuations2 = events[1]
    assert idx2 == 8
    assert "Worker restart" in primary2
    assert continuations2 == []


def test_group_multiline_standard_single_lines() -> None:
    lines = [
        "Nov 10 10:00:01 web01 sshd[1234]: Failed password for root from 192.168.1.50 port 4422 ssh2",
        "Nov 10 10:00:02 web01 sshd[1235]: Failed password for admin from 192.168.1.50 port 4423 ssh2",
        "Nov 10 10:00:03 web01 sshd[1236]: Accepted password for deploy from 192.168.1.100 port 4424 ssh2",
    ]

    events = list(group_multiline_logs(lines))
    assert len(events) == 3
    for _, _, cont in events:
        assert cont == []


def test_group_multiline_empty_and_whitespace() -> None:
    assert list(group_multiline_logs([])) == []
    assert list(group_multiline_logs(["", "   ", "\n"])) == []
