"""Parser for JSON-formatted structured log streams."""

import contextlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from loglens.models import Event, compute_raw_hash


class JsonLinesParser:
    """Parser for newline-delimited JSON logs."""

    name = "json"
    description = "JSON-formatted structured logs"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Score confidence that sample lines are JSON objects."""
        if not sample_lines:
            return 0.0

        valid_json_count = 0
        for line in sample_lines:
            sline = line.strip()
            if sline.startswith("{") and sline.endswith("}"):
                try:
                    data = json.loads(sline)
                    if isinstance(data, dict):
                        valid_json_count += 1
                except Exception:
                    pass

        return valid_json_count / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single JSON log line."""
        line = raw_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        # 1. Extract timestamp
        ts: datetime | None = None
        for ts_key in ("timestamp", "ts", "@timestamp", "time", "datetime", "date"):
            if ts_key in data:
                val = data.pop(ts_key)
                if isinstance(val, str):
                    try:
                        ts = datetime.fromisoformat(val)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=UTC)
                    except ValueError:
                        pass
                elif isinstance(val, (int, float)):
                    # Unix timestamp (seconds or milliseconds)
                    if val > 1e11:  # milliseconds
                        val = val / 1000.0
                    with contextlib.suppress(Exception):
                        ts = datetime.fromtimestamp(val, tz=UTC)
                if ts:
                    break

        if not ts:
            ts = reference_dt or datetime.now(UTC)

        # 2. Extract message
        message = ""
        for msg_key in ("message", "msg", "log", "event", "description"):
            if msg_key in data and isinstance(data[msg_key], (str, int, float, bool)):
                message = str(data.pop(msg_key))
                break

        if not message:
            message = json.dumps(data)

        # 3. Extract source
        source = "json"
        for src_key in ("source", "service", "app", "logger", "component", "name"):
            if src_key in data and isinstance(data[src_key], str):
                source = str(data.pop(src_key))
                break

        # 4. Extract severity
        severity_hint: str | None = None
        for sev_key in ("level", "severity", "log_level", "levelname"):
            if sev_key in data and isinstance(data[sev_key], str):
                raw_sev = str(data.pop(sev_key)).lower()
                if "crit" in raw_sev or "fatal" in raw_sev or "emerg" in raw_sev:
                    severity_hint = "critical"
                elif "err" in raw_sev:
                    severity_hint = "error"
                elif "warn" in raw_sev:
                    severity_hint = "warning"
                elif (
                    "info" in raw_sev
                    or "notice" in raw_sev
                    or "debug" in raw_sev
                    or "trace" in raw_sev
                ):
                    severity_hint = "info"
                break

        # 5. Extract host
        host: str | None = None
        for host_key in ("host", "hostname", "server"):
            if host_key in data and isinstance(data[host_key], str):
                host = str(data.pop(host_key))
                break

        # Remaining fields (keep primitives)
        fields: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                fields[k] = v
            else:
                fields[k] = str(v)

        return Event(
            ts=ts,
            source=source,
            host=host,
            severity_hint=severity_hint or "info",
            message=message,
            fields=fields,
            raw_hash=compute_raw_hash(raw_line),
        )
