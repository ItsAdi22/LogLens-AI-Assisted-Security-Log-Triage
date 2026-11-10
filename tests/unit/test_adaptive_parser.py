"""Unit tests for AdaptiveMultiParser multiplexing across heterogeneous log lines."""

from __future__ import annotations

from loglens.parsers.adaptive import AdaptiveMultiParser


def test_adaptive_parser_heterogeneous_stream() -> None:
    parser = AdaptiveMultiParser()

    # 1. SSH Auth line
    ssh_line = "2026-11-10T15:20:18.560675+05:30 mpanel sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 55432 ssh2"
    ev1 = parser.parse_line(ssh_line, 1)
    assert ev1 is not None
    assert ev1.source == "sshd"
    assert ev1.fields.get("user") == "admin"
    assert ev1.fields.get("ip") == "192.168.1.100"

    # 2. Web Access line (Apache / LiteSpeed / Nginx)
    web_line = '198.51.100.42 - - [10/Nov/2026:14:32:10 +0000] "GET /phpmyadmin/index.php HTTP/1.1" 404 153'
    ev2 = parser.parse_line(web_line, 2)
    assert ev2 is not None
    assert ev2.source == "web"
    assert ev2.fields.get("ip") == "198.51.100.42"
    assert ev2.fields.get("status") == 404
    assert ev2.fields.get("path") == "/phpmyadmin/index.php"

    # 3. Laravel / Pelican line with docker prefix
    docker_laravel = "panel | [2026-11-10 14:35:00] production.ERROR: Database connection timeout"
    ev3 = parser.parse_line(docker_laravel, 3)
    assert ev3 is not None
    assert "Database connection timeout" in ev3.message

    # 4. Cron job
    cron_line = "Nov 10 14:40:01 mpanel CRON[5678]: (root) CMD (/usr/local/bin/backup.sh)"
    ev4 = parser.parse_line(cron_line, 4)
    assert ev4 is not None
    assert ev4.fields.get("service") == "cron"
    assert ev4.fields.get("user") == "root"


def test_adaptive_parser_matches_sample() -> None:
    parser = AdaptiveMultiParser()
    assert parser.matches_sample(["any sample line"]) >= 0.9
