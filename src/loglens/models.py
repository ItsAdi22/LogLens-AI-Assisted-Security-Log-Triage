"""Core data models for LogLens."""

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def compute_raw_hash(raw_line: str) -> str:
    """Compute a deterministic SHA-256 hash for raw line deduplication."""
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()[:16]


class Event(BaseModel):
    """Normalized security log event."""

    model_config = ConfigDict(frozen=True)

    ts: datetime = Field(..., description="Timestamp of the event")
    source: str = Field(..., description="Log source daemon/app, e.g., 'sshd', 'nginx', 'syslog'")
    host: str | None = Field(default=None, description="Hostname if available")
    severity_hint: str | None = Field(
        default=None, description="Optional severity indicator from source"
    )
    message: str = Field(..., description="Core log message body")
    fields: dict[str, str | bool | int | float | None] = Field(
        default_factory=dict, description="Normalized key-value fields"
    )
    raw_hash: str = Field(..., description="Deterministic hash for deduplication")
    raw: str | None = Field(default=None, description="Raw log line (only if store_raw enabled)")


class Cluster(BaseModel):
    """Drain3 log cluster containing grouped events matching a common template."""

    id: str = Field(..., description="Unique cluster ID")
    template: str = Field(..., description="Drain3 mined template with wildcards")
    count: int = Field(default=0, description="Total occurrences observed")
    first_seen: datetime = Field(..., description="Earliest event timestamp")
    last_seen: datetime = Field(..., description="Latest event timestamp")
    top_fields: dict[str, list[tuple[str, int]]] = Field(
        default_factory=dict, description="Top extracted values with frequencies"
    )
    sample_messages: list[str] = Field(
        default_factory=list, description="Sample log messages for inspection (max 3)"
    )


class LLMAssessment(BaseModel):
    """Structured assessment produced by LLM triage."""

    summary: str = Field(..., description="Executive summary of the cluster activity")
    attack_type: str | None = Field(
        default=None,
        description="Identified attack category (e.g. ssh_bruteforce, web_scanning, sqli)",
    )
    severity: Literal["info", "low", "medium", "high", "critical"] = Field(
        ..., description="Assessed severity level"
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    evidence: list[str] = Field(
        default_factory=list,
        description="Facts extracted strictly from the provided cluster data",
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Defensive and remediation recommendations"
    )
    false_positive_likelihood: Literal["low", "medium", "high"] = Field(
        ..., description="Likelihood of benign activity"
    )


class Finding(BaseModel):
    """Actionable security finding combining rule matches and optional LLM triage."""

    id: str = Field(..., description="Unique finding ID")
    cluster_ids: list[str] = Field(..., description="Associated cluster IDs")
    rule_ids: list[str] = Field(default_factory=list, description="IDs of matching rules")
    rule_severity: Literal["info", "low", "medium", "high", "critical"] = Field(
        ..., description="Deterministic severity calculated from rules/heuristics"
    )
    llm: LLMAssessment | None = Field(
        default=None, description="Optional structured LLM evaluation"
    )


class ReportMetadata(BaseModel):
    """Metadata describing a triage report generation run."""

    schema_version: str = "1.0.0"
    generated_at: datetime
    log_source: str
    total_lines: int
    parsed_events: int
    unparsed_lines: int
    total_clusters: int
    findings_count: int


class Report(BaseModel):
    """Complete triage report."""

    metadata: ReportMetadata
    findings: list[Finding]
    clusters: list[Cluster]
    stats: dict[str, Any] = Field(default_factory=dict)
