"""Minecraft server log parser for detecting exploit strings and connection spam."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.models import Event, compute_raw_hash


class MinecraftParser:
    """Parser for Minecraft server logs (logs/latest.log) with Log4Shell detection."""

    name = "minecraft"
    description = "Minecraft server console logs (logs/latest.log)"

    LINE_PATTERN = re.compile(
        r"^\[(?P<time>\d{2}:\d{2}:\d{2})\]\s+"
        r"\[(?P<thread>[^/]+)/(?P<level>[A-Z]+)\]:\s+"
        r"(?P<message>.*)$",
    )

    PLAYER_LOGIN = re.compile(
        r"(?P<player>[A-Za-z0-9_]{2,16})\[/(?P<ip>[0-9a-fA-F:\.]+):(?P<port>\d+)\]\s+logged in",
    )

    RCON_FAIL = re.compile(
        r"\[/(?P<ip>[0-9a-fA-F:\.]+):(?P<port>\d+)\]\s+Failed RCON authentication",
    )

    LOG4SHELL_PATTERN = re.compile(
        r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):",
        re.IGNORECASE,
    )

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Calculate confidence score that sample lines match Minecraft server logs."""
        if not sample_lines:
            return 0.0

        matched = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if self.LINE_PATTERN.match(stripped):
                if any(
                    k in stripped
                    for k in (
                        "Server thread",
                        "logged in with entity id",
                        "UUID of player",
                        "Failed RCON",
                    )
                ):
                    matched += 2
                else:
                    matched += 1

        return min(1.0, matched / len(sample_lines))

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single Minecraft log line into a normalized Event."""
        stripped = raw_line.strip()
        if not stripped:
            return None

        m = self.LINE_PATTERN.match(stripped)
        if not m:
            return None

        time_str = m.group("time")
        ref = reference_dt or datetime.now(UTC)
        h, mn, s = (int(x) for x in time_str.split(":"))
        dt = ref.replace(hour=h, minute=mn, second=s, microsecond=0)

        thread = m.group("thread")
        level = m.group("level").upper()
        msg = m.group("message")

        severity = "info"
        if level in ("WARN", "WARNING"):
            severity = "warning"
        elif level in ("ERROR", "FATAL"):
            severity = "error"

        src_ip = None
        player = None
        fields: dict[str, str | bool | int | float | None] = {
            "thread": thread,
            "log_level": level,
        }

        # Check for Log4Shell JNDI injection
        if self.LOG4SHELL_PATTERN.search(msg):
            severity = "critical"
            fields["exploit_attempt"] = "log4shell"

        # Check for player login
        m_login = self.PLAYER_LOGIN.search(msg)
        if m_login:
            player = m_login.group("player")
            src_ip = m_login.group("ip")
            fields["player"] = player
            fields["client_ip"] = src_ip
            fields["ip"] = src_ip
            fields["port"] = int(m_login.group("port"))

        # Check for RCON authentication failure
        m_rcon = self.RCON_FAIL.search(msg)
        if m_rcon:
            src_ip = m_rcon.group("ip")
            fields["client_ip"] = src_ip
            fields["ip"] = src_ip
            fields["port"] = int(m_rcon.group("port"))
            fields["rcon_failure"] = True
            severity = "warning"

        if "logging in too fast" in msg:
            fields["login_spam"] = True
            severity = "warning"

        if src_ip:
            fields["source_ip"] = src_ip

        return Event(
            ts=dt,
            source="minecraft",
            host="localhost",
            severity_hint=severity,
            message=f"[{thread}/{level}] {msg}",
            fields=fields,
            raw_hash=compute_raw_hash(stripped),
            raw=stripped,
        )
