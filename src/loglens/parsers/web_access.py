"""Parser for Nginx, Apache, and OpenLiteSpeed web access logs."""

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from loglens.models import Event, compute_raw_hash

# Regular expression for Combined & Common Log Format (with optional vhost prefix)
RE_COMBINED_LOG = re.compile(
    r"^(?:(?P<vhost>[a-zA-Z0-9\.\-]+(?::[0-9]+)?)\s+)?"
    r"(?P<ip>[0-9a-fA-F\.:]+)\s+"
    r"(?P<ident>[^\s]+)\s+"
    r"(?P<user>[^\s]+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>(?P<method>[A-Z]+)?\s*(?P<path>[^\s]*)\s*(?P<protocol>[^"]*)?)"\s+'
    r"(?P<status>[0-9]{3})\s+"
    r"(?P<bytes>[0-9]+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def parse_clf_timestamp(clf_time: str, reference_dt: datetime | None = None) -> datetime:
    """Parse Common Log Format timestamp (e.g., 10/Oct/2026:13:55:36 -0700)."""
    try:
        # e.g., 10/Oct/2026:13:55:36 -0700
        parts = clf_time.split(":")
        date_parts = parts[0].split("/")
        day = int(date_parts[0])
        month = MONTHS.get(date_parts[1].capitalize(), 1)
        year = int(date_parts[2])

        hour = int(parts[1])
        minute = int(parts[2])
        second_tz = parts[3].split()
        second = int(second_tz[0])

        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except Exception:
        return reference_dt or datetime.now(UTC)


class WebAccessParser:
    """Parser for Nginx, Apache, and OpenLiteSpeed web access logs."""

    name = "web"
    description = "Nginx/Apache/OpenLiteSpeed combined and common access logs"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Score confidence that sample lines match web access log format."""
        if not sample_lines:
            return 0.0

        matches = 0
        for line in sample_lines:
            if RE_COMBINED_LOG.match(line.strip()):
                matches += 1

        return matches / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single web access log line."""
        line = raw_line.strip()
        if not line:
            return None

        m = RE_COMBINED_LOG.match(line)
        if not m:
            return None

        data = m.groupdict()
        ts = parse_clf_timestamp(data["time"], reference_dt=reference_dt)
        status = int(data["status"])
        bytes_sent = int(data["bytes"]) if data["bytes"] != "-" else 0

        fields: dict[str, Any] = {
            "ip": data["ip"],
            "method": data["method"] or "UNKNOWN",
            "path": data["path"] or "/",
            "status": status,
            "bytes": bytes_sent,
        }

        if data["protocol"]:
            fields["protocol"] = data["protocol"].strip()
        if data["user"] and data["user"] != "-":
            fields["user"] = data["user"]
        if data["vhost"]:
            fields["vhost"] = data["vhost"]
        if data.get("referer") and data["referer"] != "-":
            fields["referer"] = data["referer"]
        if data.get("ua") and data["ua"] != "-":
            fields["user_agent"] = data["ua"]

        severity_hint = "info"
        if status >= 500:
            severity_hint = "error"
        elif status >= 400:
            severity_hint = "warning"

        message = f"{fields['method']} {fields['path']} {status}"

        return Event(
            ts=ts,
            source="web",
            host=data.get("vhost"),
            severity_hint=severity_hint,
            message=message,
            fields=fields,
            raw_hash=compute_raw_hash(raw_line),
        )
