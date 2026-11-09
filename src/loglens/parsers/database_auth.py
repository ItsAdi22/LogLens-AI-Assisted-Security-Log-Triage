"""PostgreSQL and MySQL/MariaDB database authentication and connection log parser."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.models import Event, compute_raw_hash


class DatabaseAuthParser:
    """Parser for database daemon authentication failure and connection logs."""

    name = "database_auth"
    description = "PostgreSQL and MySQL/MariaDB connection and authentication logs"

    # PostgreSQL pattern: YYYY-MM-DD HH:MM:SS [UTC] [pid] user@db LEVEL: message
    PG_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*"
        r"(?:(?P<tz>[A-Z]{3,4}))?\s*"
        r"\[(?P<pid>\d+)\]\s*"
        r"(?:(?P<user>[^@\s]+)@(?P<db>[^\s:]+)\s+)?"
        r"(?P<level>[A-Z]+):\s+"
        r"(?P<message>.*)$",
        re.IGNORECASE,
    )

    # MySQL pattern: ISO timestamp, ID, [Level], message
    MYSQL_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z)?)\s+"
        r"(?P<conn_id>\d+)\s+"
        r"\[(?P<level>\w+)\]\s+"
        r"(?P<message>.*)$",
        re.IGNORECASE,
    )

    MYSQL_ACCESS_DENIED = re.compile(
        r"Access denied for user '(?P<user>[^']+)'@'(?P<host>[^']+)'",
        re.IGNORECASE,
    )

    PG_AUTH_FAILED = re.compile(
        r'password authentication failed for user "(?P<user>[^"]+)"',
        re.IGNORECASE,
    )

    PG_CONN_HOST = re.compile(
        r"host=(?P<host>[0-9a-fA-F:\.]+)(?:\s+port=(?P<port>\d+))?",
        re.IGNORECASE,
    )

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Calculate confidence score that sample lines match database logs."""
        if not sample_lines:
            return 0.0

        matched = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if (
                "authentication failed for user" in stripped
                or "Access denied for user" in stripped
                or "connection authorized:" in stripped
                or ("FATAL:" in stripped and "password" in stripped)
            ):
                matched += 1

        return matched / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single PostgreSQL or MySQL log line into a normalized Event."""
        stripped = raw_line.strip()
        if not stripped:
            return None

        # Try PostgreSQL first
        m_pg = self.PG_PATTERN.match(stripped)
        if m_pg:
            return self._parse_postgres(m_pg, stripped, line_number, reference_dt)

        # Try MySQL second
        m_my = self.MYSQL_PATTERN.match(stripped)
        if m_my:
            return self._parse_mysql(m_my, stripped, line_number, reference_dt)

        return None

    def _parse_postgres(
        self,
        m: re.Match[str],
        raw: str,
        line_number: int,
        reference_dt: datetime | None,
    ) -> Event:
        ts_str = m.group("timestamp")
        try:
            dt = datetime.strptime(ts_str.split(".")[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            dt = reference_dt or datetime.now(UTC)

        pid = int(m.group("pid"))
        user = m.group("user")
        db = m.group("db")
        level = m.group("level").upper()
        msg = m.group("message")

        severity = "info"
        if level in ("FATAL", "PANIC"):
            severity = "critical" if "authentication failed" in msg else "error"
        elif level in ("ERROR", "WARNING"):
            severity = "warning"

        src_ip = None
        m_host = self.PG_CONN_HOST.search(msg)
        if m_host:
            src_ip = m_host.group("host")

        m_user = self.PG_AUTH_FAILED.search(msg)
        if m_user:
            user = m_user.group("user")

        fields: dict[str, str | bool | int | float | None] = {
            "database_system": "postgresql",
            "pid": pid,
            "log_level": level,
        }
        if user and user != "[unknown]":
            fields["user"] = user
        if db and db != "[unknown]":
            fields["database"] = db
        if src_ip:
            fields["client_ip"] = src_ip
            fields["source_ip"] = src_ip
            fields["ip"] = src_ip

        return Event(
            ts=dt,
            source="postgres",
            host="localhost",
            severity_hint=severity,
            message=f"[{level}] {msg}",
            fields=fields,
            raw_hash=compute_raw_hash(raw),
            raw=raw,
        )

    def _parse_mysql(
        self,
        m: re.Match[str],
        raw: str,
        line_number: int,
        reference_dt: datetime | None,
    ) -> Event:
        ts_str = m.group("timestamp").replace("Z", "")
        # Clean ISO or space format
        clean_ts = ts_str.replace("T", " ").split(".")[0]
        try:
            dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            dt = reference_dt or datetime.now(UTC)

        conn_id = int(m.group("conn_id"))
        level = m.group("level").upper()
        msg = m.group("message")

        severity = "info"
        if "access denied" in msg.lower():
            severity = "warning"
        elif level in ("ERROR", "CRITICAL"):
            severity = "error"

        user = None
        src_ip = None
        m_denied = self.MYSQL_ACCESS_DENIED.search(msg)
        if m_denied:
            user = m_denied.group("user")
            src_ip = m_denied.group("host")

        fields: dict[str, str | bool | int | float | None] = {
            "database_system": "mysql",
            "connection_id": conn_id,
            "log_level": level,
        }
        if user:
            fields["user"] = user
        if src_ip:
            fields["client_ip"] = src_ip
            fields["source_ip"] = src_ip
            fields["ip"] = src_ip

        return Event(
            ts=dt,
            source="mysql",
            host="localhost",
            severity_hint=severity,
            message=f"[{level}] {msg}",
            fields=fields,
            raw_hash=compute_raw_hash(raw),
            raw=raw,
        )
