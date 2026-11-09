"""UFW (Uncomplicated Firewall) and iptables kernel log parser."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.models import Event, compute_raw_hash
from loglens.parsers.base import resolve_syslog_timestamp


class UfwParser:
    """Parser for /var/log/ufw.log and kernel firewall drop telemetry."""

    name = "ufw"
    description = "UFW and Linux iptables kernel packet drop logs (/var/log/ufw.log)"

    LINE_PATTERN = re.compile(
        r"^(?:(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+)?"
        r"(?:(?P<host>\S+)\s+)?"
        r"(?:kernel:\s+)?(?:\[\s*\d+\.\d+\]\s+)?"
        r"\[(?P<action>UFW\s+(?:BLOCK|AUDIT|ALLOW|LIMIT))\]\s+"
        r"(?P<params>.*)$",
        re.IGNORECASE,
    )

    PARAM_PATTERN = re.compile(r"([A-Z_]+)=([^\s]*)")

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Calculate confidence score that sample lines match UFW firewall logs."""
        if not sample_lines:
            return 0.0

        matched = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if "[UFW " in stripped or ("[UFW" in stripped and "SRC=" in stripped):
                matched += 1

        return matched / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single UFW/iptables log line into a normalized Event."""
        stripped = raw_line.strip()
        if not stripped:
            return None

        m = self.LINE_PATTERN.match(stripped)
        if not m:
            return None

        month = m.group("month")
        day = m.group("day")
        time_str = m.group("time")

        if month and day and time_str:
            dt = resolve_syslog_timestamp(month, day, time_str, reference_dt=reference_dt)
        else:
            dt = reference_dt or datetime.now(UTC)

        host = m.group("host") or "localhost"
        action_tag = m.group("action").upper()
        params_str = m.group("params")

        # Extract key-value parameters
        params: dict[str, str | int | float | bool] = {}
        for k, v in self.PARAM_PATTERN.findall(params_str):
            if k in ("SPT", "DPT", "LEN", "TTL", "WINDOW"):
                try:
                    params[k.lower()] = int(v)
                except ValueError:
                    params[k.lower()] = v
            else:
                params[k.lower()] = v

        src_ip = str(params.get("src", "")) or None
        dst_ip = str(params.get("dst", "")) or None
        proto = str(params.get("proto", "")).upper() or None
        dpt = params.get("dpt")
        spt = params.get("spt")

        action_name = action_tag.replace("UFW ", "").strip()
        severity = "warning" if action_name == "BLOCK" else "info"

        msg = f"[{action_tag}] packet dropped"
        if proto:
            msg += f" {proto}"
        if src_ip:
            msg += f" from {src_ip}"
            if spt:
                msg += f":{spt}"
        if dst_ip and dpt:
            msg += f" to {dst_ip}:{dpt}"

        fields: dict[str, str | bool | int | float | None] = {
            "action": action_name.lower(),
            "firewall": "ufw",
            **params,
        }
        if src_ip:
            fields["client_ip"] = src_ip
            fields["source_ip"] = src_ip
            fields["ip"] = src_ip
        if dst_ip:
            fields["destination_ip"] = dst_ip
        if proto:
            fields["protocol"] = proto

        return Event(
            ts=dt,
            source="ufw",
            host=host,
            severity_hint=severity,
            message=msg,
            fields=fields,
            raw_hash=compute_raw_hash(stripped),
            raw=stripped,
        )
