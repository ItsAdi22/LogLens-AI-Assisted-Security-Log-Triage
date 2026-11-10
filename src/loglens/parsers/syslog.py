"""Parser for generic syslog formats (RFC 3164 and RFC 5424)."""

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from loglens.models import Event, compute_raw_hash
from loglens.parsers.base import extract_common_system_fields, resolve_syslog_timestamp

# RFC 3164: <PRI>? Mon DD HH:MM:SS host program[pid]: message
RE_RFC3164 = re.compile(
    r"^(?:<(?P<pri>[0-9]{1,3})>)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>[0-9]{1,2})\s+(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})\s+(?P<host>[^\s]+)\s+(?P<prog>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>[0-9]+)\])?:\s*(?P<msg>.*)$"
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RE_RFC5424 = re.compile(
    r"^<(?P<pri>[0-9]{1,3})>(?P<ver>[0-9]+)\s+(?P<time>[^\s]+)\s+(?P<host>[^\s]+)\s+(?P<app>[^\s]+)\s+(?P<procid>[^\s]+)\s+(?P<msgid>[^\s]+)(?:\s+(?P<sd>\[.*?\]|-))?(?:\s+(?P<msg>.*))?$"
)

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def pri_to_severity(pri: int | None) -> str:
    """Map syslog priority to severity hint."""
    if pri is None:
        return "info"
    severity_num = pri & 7  # lower 3 bits are severity
    # 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice, 6=info, 7=debug
    if severity_num <= 2:
        return "critical"
    if severity_num == 3:
        return "error"
    if severity_num == 4:
        return "warning"
    return "info"


class SyslogParser:
    """Parser for RFC 3164 and RFC 5424 syslog streams."""

    name = "syslog"
    description = "Generic syslog format (RFC 3164 / RFC 5424)"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Score confidence that sample is standard syslog."""
        if not sample_lines:
            return 0.0

        matches = 0
        for line in sample_lines:
            sline = line.strip()
            if RE_RFC3164.match(sline) or RE_RFC5424.match(sline):
                matches += 1

        return matches / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single syslog line."""
        line = raw_line.strip()
        if not line:
            return None

        # Try RFC 5424 first
        m5424 = RE_RFC5424.match(line)
        if m5424:
            d = m5424.groupdict()
            pri = int(d["pri"]) if d.get("pri") else None
            try:
                ts = datetime.fromisoformat(d["time"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
            except ValueError:
                ts = reference_dt or datetime.now(UTC)

            host = d["host"] if d["host"] != "-" else None
            app = d["app"] if d["app"] != "-" else "syslog"
            msg = d.get("msg") or ""

            fields: dict[str, Any] = {}
            if d.get("procid") and d["procid"] != "-":
                fields["pid"] = d["procid"]
            if d.get("msgid") and d["msgid"] != "-":
                fields["msgid"] = d["msgid"]

            ip_match = IP_REGEX.search(msg)
            if ip_match:
                fields["ip"] = ip_match.group(0)

            extract_common_system_fields(msg, fields)

            return Event(
                ts=ts,
                source=app,
                host=host,
                severity_hint=pri_to_severity(pri),
                message=msg,
                fields=fields,
                raw_hash=compute_raw_hash(raw_line),
            )

        # Try RFC 3164
        m3164 = RE_RFC3164.match(line)
        if m3164:
            d = m3164.groupdict()
            pri = int(d["pri"]) if d.get("pri") else None
            ts = resolve_syslog_timestamp(d["mon"], d["day"], d["time"], reference_dt=reference_dt)
            host = d["host"]
            prog = d["prog"]
            msg = d.get("msg") or ""

            fields = {}
            if d.get("pid"):
                fields["pid"] = int(d["pid"])

            ip_match = IP_REGEX.search(msg)
            if ip_match:
                fields["ip"] = ip_match.group(0)

            extract_common_system_fields(msg, fields)

            return Event(
                ts=ts,
                source=prog,
                host=host,
                severity_hint=pri_to_severity(pri),
                message=msg,
                fields=fields,
                raw_hash=compute_raw_hash(raw_line),
            )

        return None
