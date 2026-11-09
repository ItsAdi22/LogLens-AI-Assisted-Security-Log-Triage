"""Pterodactyl and Pelican panel daemon (Wings) log parser."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.models import Event, compute_raw_hash


class PterodactylParser:
    """Parser for Pterodactyl and Pelican game server manager daemon logs."""

    name = "pterodactyl"
    description = "Pterodactyl Wings and Pelican daemon logs (wings.log)"

    ISO_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z)?)\s+"
        r"(?P<level>[A-Z]+):\s+"
        r"(?:\[(?P<subsystem>[^\]]+)\]\s+)?"
        r"(?P<message>.*)$",
        re.IGNORECASE,
    )

    LEGACY_PATTERN = re.compile(
        r"^\[(?P<level>[A-Z]+)\]\s+\((?P<subsystem>[^\)]+)\)\s+(?P<message>.*)$",
        re.IGNORECASE,
    )

    IP_PATTERN = re.compile(
        r"(?:from|ip|client)\s+[:=]?\s*(?P<ip>[0-9a-fA-F:\.]+)",
        re.IGNORECASE,
    )

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Calculate confidence score that sample lines match Pterodactyl/Wings logs."""
        if not sample_lines:
            return 0.0

        matched = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if (
                "(wings)" in stripped
                or "[wings]" in stripped
                or "Pterodactyl" in stripped
                or ("WARN:" in stripped and "server" in stripped)
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
        """Parse a single Wings log line into a normalized Event."""
        stripped = raw_line.strip()
        if not stripped:
            return None

        m_iso = self.ISO_PATTERN.match(stripped)
        if m_iso:
            ts_str = m_iso.group("timestamp").replace("Z", "").replace("T", " ")
            clean_ts = ts_str.split(".")[0]
            try:
                dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                dt = reference_dt or datetime.now(UTC)

            level = m_iso.group("level").upper()
            subsystem = m_iso.group("subsystem") or "daemon"
            msg = m_iso.group("message")
        else:
            m_leg = self.LEGACY_PATTERN.match(stripped)
            if not m_leg:
                return None
            dt = reference_dt or datetime.now(UTC)
            level = m_leg.group("level").upper()
            subsystem = m_leg.group("subsystem")
            msg = m_leg.group("message")

        severity = "info"
        if level in ("WARN", "WARNING"):
            severity = "warning"
        elif level in ("ERROR", "FATAL"):
            severity = "error"

        src_ip = None
        m_ip = self.IP_PATTERN.search(msg)
        if m_ip:
            src_ip = m_ip.group("ip").rstrip(":")

        fields: dict[str, str | bool | int | float | None] = {
            "daemon": "wings",
            "subsystem": subsystem,
            "log_level": level,
        }
        if src_ip:
            fields["client_ip"] = src_ip
            fields["source_ip"] = src_ip
            fields["ip"] = src_ip

        if any(
            w in msg.lower() for w in ("invalid token", "authentication failed", "unauthorized")
        ):
            fields["auth_failure"] = True
            if severity == "info":
                severity = "warning"

        return Event(
            ts=dt,
            source="pterodactyl",
            host="localhost",
            severity_hint=severity,
            message=f"[{subsystem}] {msg}",
            fields=fields,
            raw_hash=compute_raw_hash(stripped),
            raw=stripped,
        )
