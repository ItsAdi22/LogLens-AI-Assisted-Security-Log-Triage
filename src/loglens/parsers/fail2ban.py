"""Fail2ban action and jail log parser."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.models import Event, compute_raw_hash


class Fail2banParser:
    """Parser for /var/log/fail2ban.log files recording jail actions and IP bans."""

    name = "fail2ban"
    description = "Fail2ban jail action and filter logs (/var/log/fail2ban.log)"

    LINE_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)\s+"
        r"fail2ban\.(?P<component>[\w\.]+)\s*\[(?P<pid>\d+)\]:\s+"
        r"(?P<level>\w+)\s+\[(?P<jail>[^\]]+)\]\s+"
        r"(?P<action>Ban|Unban|Restore Ban|Found)(?:\s+(?P<ip>[0-9a-fA-F:\.]+))?",
        re.IGNORECASE,
    )

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Calculate confidence score that sample lines match fail2ban format."""
        if not sample_lines:
            return 0.0

        matched = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if "fail2ban." in stripped and any(
                w in stripped for w in ("Ban", "Unban", "Found", "NOTICE", "WARNING")
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
        """Parse a single fail2ban log line into a normalized Event."""
        stripped = raw_line.strip()
        if not stripped:
            return None

        m = self.LINE_PATTERN.match(stripped)
        if not m:
            return None

        ts_str = m.group("timestamp")
        # Strip millisecond comma separator if present: 2026-11-09 12:00:00,123 -> 2026-11-09 12:00:00
        if "," in ts_str:
            base_ts, ms = ts_str.split(",", 1)
            try:
                dt = datetime.strptime(base_ts, "%Y-%m-%d %H:%M:%S").replace(
                    microsecond=int(ms.ljust(6, "0")[:6]), tzinfo=UTC
                )
            except ValueError:
                dt = reference_dt or datetime.now(UTC)
        else:
            try:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                dt = reference_dt or datetime.now(UTC)

        component = m.group("component")
        pid = int(m.group("pid"))
        level = m.group("level").upper()
        jail = m.group("jail")
        action = m.group("action")
        ip = m.group("ip")

        severity = "info"
        if action.lower() in ("ban", "restore ban"):
            severity = "warning"
        elif level in ("ERROR", "CRITICAL"):
            severity = "error"

        msg = f"[{jail}] {action}"
        if ip:
            msg += f" {ip}"

        fields: dict[str, str | bool | int | float | None] = {
            "component": component,
            "pid": pid,
            "log_level": level,
            "jail": jail,
            "action": action.lower(),
        }
        if ip:
            fields["client_ip"] = ip
            fields["source_ip"] = ip
            fields["ip"] = ip

        return Event(
            ts=dt,
            source="fail2ban",
            host="localhost",
            severity_hint=severity,
            message=msg,
            fields=fields,
            raw_hash=compute_raw_hash(stripped),
            raw=stripped,
        )
