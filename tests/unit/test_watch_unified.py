"""Unit tests for remote source discovery and unified streaming command builder."""

from __future__ import annotations

from unittest.mock import MagicMock

from loglens.watch import (
    build_unified_stream_command,
    discover_remote_sources,
    summarize_discovered_sources,
)


def test_discover_remote_sources_parsing() -> None:
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = (
        b"===FILES===\n"
        b"/var/log/auth.log\n"
        b"/usr/local/lsws/logs/access.log\n"
        b"/usr/local/lsws/logs/error.log\n"
        b"===DOCKER===\n"
        b"pelican-panel\n"
        b"pelican-wings\n"
        b"===COMPOSE===\n"
        b"/root/pelican-panel\n"
    )
    mock_client.exec_command.return_value = (None, mock_stdout, None)

    discovered = discover_remote_sources(mock_client)
    assert "/var/log/auth.log" in discovered["files"]
    assert "/usr/local/lsws/logs/access.log" in discovered["files"]
    assert "pelican-panel" in discovered["docker_containers"]
    assert "/root/pelican-panel" in discovered["compose_dirs"]

    summary = summarize_discovered_sources(discovered)
    assert "auth.log" in summary
    assert "OpenLiteSpeed" in summary
    assert "Docker (pelican-panel" in summary


def test_build_unified_stream_command() -> None:
    discovered = {
        "files": ["/var/log/auth.log", "/usr/local/lsws/logs/access.log"],
        "docker_containers": ["pelican-panel"],
        "compose_dirs": [],
    }
    cmd = build_unified_stream_command(discovered)
    assert "tail -q -n 30 -F /var/log/auth.log /usr/local/lsws/logs/access.log" in cmd
    assert "docker logs -f --tail=20 pelican-panel" in cmd
    assert 'trap "kill 0" EXIT TERM INT' in cmd


def test_build_unified_stream_command_fallback() -> None:
    empty_discovered: dict[str, list[str]] = {
        "files": [],
        "docker_containers": [],
        "compose_dirs": [],
    }
    fallback_cmd = build_unified_stream_command(empty_discovered)
    assert "tail -q -n 30 -F" in fallback_cmd
    assert "/var/log/auth.log" in fallback_cmd
