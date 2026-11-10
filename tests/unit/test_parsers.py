"""Unit tests for all LogLens parsers and autodetect logic."""

from datetime import UTC, datetime

from loglens.parsers import (
    AuthLogParser,
    GenericParser,
    JsonLinesParser,
    SyslogParser,
    WebAccessParser,
    registry,
)
from loglens.parsers.base import resolve_syslog_timestamp


def test_resolve_syslog_timestamp_standard() -> None:
    """Verify syslog timestamp parsing with standard dates."""
    ref = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
    dt = resolve_syslog_timestamp("Nov", "09", "10:30:00", reference_dt=ref)
    assert dt.year == 2026
    assert dt.month == 11
    assert dt.day == 9
    assert dt.hour == 10
    assert dt.minute == 30


def test_resolve_syslog_timestamp_year_rollover() -> None:
    """Verify that a December log analyzed in January rolls back to previous year."""
    ref = datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC)
    dt = resolve_syslog_timestamp("Dec", "31", "23:59:59", reference_dt=ref)
    assert dt.year == 2025
    assert dt.month == 12
    assert dt.day == 31


def test_auth_log_parser_failed_password() -> None:
    """Verify auth parser extracts failed password events."""
    parser = AuthLogParser()
    line = (
        "Nov 09 14:02:11 web01 sshd[1234]: Failed password for root from 192.0.2.15 port 44212 ssh2"
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == "sshd"
    assert event.host == "web01"
    assert event.severity_hint == "warning"
    assert event.fields["action"] == "failed_password"
    assert event.fields["user"] == "root"
    assert event.fields["ip"] == "192.0.2.15"
    assert event.fields["port"] == 44212
    assert event.fields["invalid_user"] is False


def test_auth_log_parser_invalid_user() -> None:
    """Verify auth parser extracts invalid user failed logins."""
    parser = AuthLogParser()
    line = "Nov 09 14:02:15 web01 sshd[1235]: Failed password for invalid user admin from 192.0.2.16 port 44214 ssh2"
    event = parser.parse_line(line, 2)
    assert event is not None
    assert event.fields["action"] == "failed_password"
    assert event.fields["user"] == "admin"
    assert event.fields["invalid_user"] is True


def test_auth_log_parser_invalid_user_announcement() -> None:
    """Verify auth parser extracts standalone invalid user announcements."""
    parser = AuthLogParser()
    line = "Nov 09 14:02:15 web01 sshd[1235]: Invalid user testuser from 192.0.2.16 port 44214"
    event = parser.parse_line(line, 2)
    assert event is not None
    assert event.fields["action"] == "invalid_user"
    assert event.fields["user"] == "testuser"
    assert event.fields["ip"] == "192.0.2.16"


def test_auth_log_parser_connection_closed() -> None:
    """Verify auth parser extracts connection closed events."""
    parser = AuthLogParser()
    line = "Nov 09 14:02:16 web01 sshd[1236]: Connection closed by authenticating user root 192.0.2.17 port 54321 [preauth]"
    event = parser.parse_line(line, 3)
    assert event is not None
    assert event.fields["action"] == "connection_closed"
    assert event.fields["user"] == "root"
    assert event.fields["ip"] == "192.0.2.17"
    assert event.fields["port"] == 54321


def test_auth_log_parser_pam_failure() -> None:
    """Verify auth parser extracts PAM failure events."""
    parser = AuthLogParser()
    line = "Nov 09 14:02:17 web01 pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser=adm rhost=192.0.2.18"
    event = parser.parse_line(line, 4)
    assert event is not None
    assert event.fields["action"] == "pam_failure"
    assert event.fields["pam_service"] == "sshd:auth"
    assert event.fields["ip"] == "192.0.2.18"
    assert event.fields["user"] == "adm"


def test_auth_log_parser_iso_timestamp() -> None:
    """Verify auth parser handles ISO 8601 timestamps."""
    parser = AuthLogParser()
    line = "2026-11-09T14:02:11.000000+00:00 web01 sshd[1234]: Accepted password for deploy from 192.0.2.19 port 33221 ssh2"
    event = parser.parse_line(line, 5)
    assert event is not None
    assert event.fields["action"] == "accepted"
    assert event.fields["auth_method"] == "password"
    assert event.fields["ip"] == "192.0.2.19"
    assert event.ts.year == 2026


def test_auth_log_parser_accepted_key() -> None:
    """Verify auth parser extracts accepted publickey events."""
    parser = AuthLogParser()
    line = "Nov 09 14:10:00 web01 sshd[1240]: Accepted publickey for ubuntu from 192.0.2.50 port 51234 ssh2: RSA SHA256:abc"
    event = parser.parse_line(line, 3)
    assert event is not None
    assert event.fields["action"] == "accepted"
    assert event.fields["auth_method"] == "publickey"
    assert event.fields["user"] == "ubuntu"
    assert event.fields["ip"] == "192.0.2.50"
    assert event.severity_hint == "info"


def test_auth_log_parser_sudo() -> None:
    """Verify auth parser extracts sudo execution."""
    parser = AuthLogParser()
    line = "Nov 09 14:15:00 web01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls"
    event = parser.parse_line(line, 4)
    assert event is not None
    assert event.fields["action"] == "sudo_command"
    assert event.fields["user"] == "ubuntu"
    assert event.fields["sudo_target_user"] == "root"
    assert event.fields["command"] == "/bin/ls"


def test_web_access_parser_combined() -> None:
    """Verify web access parser on combined log lines."""
    parser = WebAccessParser()
    line = '192.0.2.10 - frank [09/Nov/2026:14:30:00 +0000] "GET /admin.php HTTP/1.1" 404 162 "https://example.com" "Nikto/2.1.6"'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == "web"
    assert event.fields["ip"] == "192.0.2.10"
    assert event.fields["user"] == "frank"
    assert event.fields["method"] == "GET"
    assert event.fields["path"] == "/admin.php"
    assert event.fields["status"] == 404
    assert event.fields["bytes"] == 162
    assert event.fields["user_agent"] == "Nikto/2.1.6"
    assert event.severity_hint == "warning"


def test_web_access_parser_vhost() -> None:
    """Verify web access parser with vhost prefix."""
    parser = WebAccessParser()
    line = 'api.example.com:443 192.0.2.20 - - [09/Nov/2026:14:35:00 +0000] "POST /v1/auth HTTP/2.0" 500 45 "-" "curl/7.88.1"'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.fields["vhost"] == "api.example.com:443"
    assert event.fields["status"] == 500
    assert event.severity_hint == "error"


def test_syslog_parser_rfc3164() -> None:
    """Verify BSD RFC 3164 syslog parsing."""
    parser = SyslogParser()
    line = "Nov 09 15:00:00 bastion kernel: [12345.67] Out of memory: Kill process 999"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == "kernel"
    assert event.host == "bastion"
    assert "Out of memory" in event.message


def test_syslog_parser_rfc5424() -> None:
    """Verify IETF RFC 5424 syslog parsing."""
    parser = SyslogParser()
    line = "<165>1 2026-11-09T15:00:00.123Z bastion myapp 4567 ID47 [example@32473] Connection from 192.0.2.80 failed"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == "myapp"
    assert event.host == "bastion"
    assert event.fields["pid"] == "4567"
    assert event.fields["ip"] == "192.0.2.80"


def test_json_lines_parser() -> None:
    """Verify JSON lines parsing and field extraction."""
    parser = JsonLinesParser()
    line = '{"timestamp": "2026-11-09T15:30:00Z", "level": "error", "service": "auth-service", "message": "Database timeout", "client_ip": "192.0.2.99"}'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == "auth-service"
    assert event.severity_hint == "error"
    assert event.message == "Database timeout"
    assert event.fields["client_ip"] == "192.0.2.99"


def test_json_lines_parser_epoch_timestamps() -> None:
    """Verify JSON parser handles numeric epoch timestamps."""
    parser = JsonLinesParser()
    # Seconds
    ev1 = parser.parse_line('{"ts": 1700000000, "message": "ok"}', 1)
    assert ev1 is not None
    assert ev1.ts.year == 2023

    # Milliseconds
    ev2 = parser.parse_line('{"ts": 1700000000000, "message": "ok"}', 2)
    assert ev2 is not None
    assert ev2.ts.year == 2023


def test_json_lines_parser_severity_variants() -> None:
    """Verify JSON parser maps different severity strings."""
    parser = JsonLinesParser()
    ev_crit = parser.parse_line('{"level": "CRITICAL", "msg": "down"}', 1)
    assert ev_crit is not None
    assert ev_crit.severity_hint == "critical"

    ev_warn = parser.parse_line('{"level": "warning", "msg": "slow"}', 2)
    assert ev_warn is not None
    assert ev_warn.severity_hint == "warning"


def test_json_lines_parser_non_dict() -> None:
    """Verify JSON parser gracefully ignores non-dict JSON lines."""
    parser = JsonLinesParser()
    assert parser.parse_line('"just a string"', 1) is None
    assert parser.parse_line("[1, 2, 3]", 2) is None


def test_generic_parser_fallback() -> None:
    """Verify generic fallback parser handles arbitrary string."""
    parser = GenericParser()
    line = "2026-11-09 16:00:00 Warning: host unreachable from 192.0.2.100"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == "generic"
    assert event.severity_hint == "warning"
    assert event.fields["ip"] == "192.0.2.100"


def test_autodetect_registry() -> None:
    """Verify registry autodetect identifies format correctly."""
    auth_samples = [
        "Nov 09 14:02:11 web01 sshd[1234]: Failed password for root from 192.0.2.15 port 44212 ssh2",
        "Nov 09 14:02:15 web01 sshd[1235]: Failed password for invalid user admin from 192.0.2.16 port 44214 ssh2",
    ]
    detected = registry.autodetect(auth_samples)
    assert detected.name == "auth"

    web_samples = [
        '192.0.2.10 - - [09/Nov/2026:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "curl/7.88.1"',
        '192.0.2.11 - - [09/Nov/2026:14:30:05 +0000] "GET /about.html HTTP/1.1" 200 2048 "-" "curl/7.88.1"',
    ]
    detected_web = registry.autodetect(web_samples)
    assert detected_web.name == "web"

    json_samples = [
        '{"time": "2026-11-09T14:30:00Z", "msg": "test 1"}',
        '{"time": "2026-11-09T14:30:01Z", "msg": "test 2"}',
    ]
    detected_json = registry.autodetect(json_samples)
    assert detected_json.name == "json"


def test_auth_log_parser_connection_reset_preauth() -> None:
    """Verify sshd preauth reset lines are autodetected and parsed with extracted fields."""
    sample = ["Connection reset by invalid user root 222.167.207.101 port 52342 [preauth]"]
    detected = registry.autodetect(sample)
    assert detected.name == "auth"

    parser = AuthLogParser()
    event = parser.parse_line(sample[0], 1)
    assert event is not None
    assert event.fields["user"] == "root"
    assert event.fields["ip"] == "222.167.207.101"
    assert event.fields["port"] == 52342
    assert event.fields["invalid_user"] is True
    assert event.fields["action"] == "preauth_reset"
    assert event.fields["service"] == "sshd"
    assert event.severity_hint == "low"


def test_auth_log_parser_extracts_pam_cron_systemd() -> None:
    """Verify field extraction for pam_unix, cron, and systemd-logind."""
    parser = AuthLogParser()

    # 1. PAM unix session
    pam_line = "pam_unix(systemd-user:session): session opened for user root(uid=0) by root(uid=0)"
    ev_pam = parser.parse_line(pam_line, 1)
    assert ev_pam is not None
    assert ev_pam.fields["user"] == "root"
    assert ev_pam.fields["service"] == "systemd-user"
    assert ev_pam.fields["action"] == "session_opened"

    # 2. Cron job
    cron_line = "CRON[12345]: (root) CMD (/usr/local/bin/backup.sh)"
    ev_cron = parser.parse_line(cron_line, 2)
    assert ev_cron is not None
    assert ev_cron.fields["user"] == "root"
    assert ev_cron.fields["service"] == "cron"
    assert ev_cron.fields["action"] == "cron_cmd"
    assert ev_cron.fields["command"] == "/usr/local/bin/backup.sh"

    # 3. systemd-logind
    logind_line = "systemd-logind[888]: New session 55 of user mango."
    ev_logind = parser.parse_line(logind_line, 3)
    assert ev_logind is not None
    assert ev_logind.fields["user"] == "mango"
    assert ev_logind.fields["service"] == "systemd-logind"
    assert ev_logind.fields["action"] == "new_session"
    assert ev_logind.fields["session_id"] == "55"
