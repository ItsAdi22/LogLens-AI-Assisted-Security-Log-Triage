"""YAML rule definitions and validation schemas."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def parse_window_to_seconds(window_str: str | None) -> float:
    """Parse time window strings (e.g. '5m', '30s', '1h') into seconds."""
    if not window_str:
        return 300.0  # default 5 minutes

    s = window_str.strip().lower()
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60.0
    if s.endswith("h"):
        return float(s[:-1]) * 3600.0
    if s.endswith("d"):
        return float(s[:-1]) * 86400.0

    return float(s)


class RuleMatch(BaseModel):
    """Matching criteria for clusters or log messages."""

    model_config = ConfigDict(extra="forbid")

    template_regex: str | None = Field(
        default=None, description="Regex pattern matching Drain3 cluster template"
    )
    message_regex: str | None = Field(
        default=None, description="Regex pattern matching log message body"
    )
    field_matches: dict[str, str | int | float | bool] = Field(
        default_factory=dict, description="Exact field key-value matches"
    )
    field_regex: dict[str, str] = Field(
        default_factory=dict, description="Regex patterns for specific event fields"
    )


class RuleCondition(BaseModel):
    """Aggregation and threshold conditions."""

    model_config = ConfigDict(extra="forbid")

    group_by: str | None = Field(
        default=None, description="Entity field to group by (e.g. 'ip', 'user')"
    )
    count_gte: int = Field(default=1, ge=1, description="Minimum occurrence threshold")
    window: str | None = Field(
        default="5m", description="Time window for count_gte (e.g. '5m', '10s', '1h')"
    )


class Rule(BaseModel):
    """Detection rule definition."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique rule identifier (e.g. 'ssh-bruteforce-001')")
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(..., description="Detailed description of attack behavior")
    source: str | list[str] | None = Field(
        default=None, description="Target log source(s) (e.g. 'sshd', 'web', 'syslog')"
    )
    match: RuleMatch = Field(..., description="Pattern matching filters")
    condition: RuleCondition | None = Field(
        default=None, description="Optional threshold and grouping conditions"
    )
    severity: Literal["info", "low", "medium", "high", "critical"] = Field(
        ..., description="Deterministic severity level"
    )
    tags: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK and categorization tags"
    )
    references: list[str] = Field(
        default_factory=list, description="Relevant documentation and MITRE links"
    )
    false_positives: list[str] = Field(
        default_factory=list, description="Common benign scenarios triggering this rule"
    )

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        """Ensure ID follows slug format."""
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError(f"Rule ID '{v}' must contain only alphanumeric, dash, and underscore")
        return v
