"""Docker container JSON log file parser."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.models import Event, compute_raw_hash


class DockerJsonParser:
    """Parser for Docker daemon container log files (*-json.log)."""

    name = "docker_json"
    description = "Docker container JSON lines log files (/var/lib/docker/containers/*/*-json.log)"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Calculate confidence score that sample lines match Docker JSON lines format."""
        if not sample_lines:
            return 0.0

        matched = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped or not stripped.startswith("{") or not stripped.endswith("}"):
                continue
            if '"log":' in stripped and '"stream":' in stripped and '"time":' in stripped:
                matched += 1

        return matched / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single Docker container JSON line into a normalized Event."""
        stripped = raw_line.strip()
        if not stripped or not stripped.startswith("{"):
            return None

        try:
            payload = json.loads(stripped)
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        log_content = str(payload.get("log", "")).strip()
        stream = str(payload.get("stream", "stdout")).lower()
        time_str = str(payload.get("time", ""))

        if time_str:
            clean_ts = time_str.replace("Z", "").replace("T", " ")
            clean_ts = clean_ts.split(".")[0]
            try:
                dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                dt = reference_dt or datetime.now(UTC)
        else:
            dt = reference_dt or datetime.now(UTC)

        severity = "info"
        if stream == "stderr":
            severity = "warning"
        if any(w in log_content.lower() for w in ("error", "fatal", "panic", "exception")):
            severity = "error"

        fields: dict[str, str | bool | int | float | None] = {
            "stream": stream,
            "container_log": True,
        }

        return Event(
            ts=dt,
            source="docker",
            host="localhost",
            severity_hint=severity,
            message=log_content or f"[{stream}] empty output",
            fields=fields,
            raw_hash=compute_raw_hash(stripped),
            raw=stripped,
        )
