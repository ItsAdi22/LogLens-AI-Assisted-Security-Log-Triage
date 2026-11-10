"""Application and system error classifier for log clusters."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from loglens.models import Cluster

ErrorCategory = Literal[
    "database_error",
    "application_exception",
    "network_failure",
    "auth_failure",
    "runtime_warning",
    "general_error",
]


class ClassifiedError(BaseModel):
    """Categorized application error or exception mined from log clusters."""

    cluster_id: str
    template: str
    count: int
    category: str
    category_label: str
    severity: Literal["critical", "high", "medium", "low"]
    sample_message: str | None = None
    top_fields: dict[str, list[tuple[str, int]]] = Field(default_factory=dict)
    llm_explanation: str | None = None


# Heuristic patterns for identifying application errors, database failures, and exceptions
ERROR_PATTERNS: list[
    tuple[re.Pattern[str], str, str, Literal["critical", "high", "medium", "low"]]
] = [
    (
        re.compile(
            r"\b(sqlstate|mysql|postgresql|postgres|deadlock|database\s+error|query\s+failed|"
            r"connection\s+refused.*(?:3306|5432)|sqlite3|mongo|redis\s+connection)\b",
            re.IGNORECASE,
        ),
        "database_error",
        "Database / SQL Error",
        "high",
    ),
    (
        re.compile(
            r"\b(curl\s+error|resolving\s+timed\s*out|connection\s+(?:refused|timed\s*out|reset)|"
            r"dns\s+(?:error|timeout|failure)|etimedout|econnrefused|econnreset|"
            r"broken\s+pipe|upstream\s+timed\s*out|502\s+bad\s+gateway|504\s+gateway|"
            r"500\s+internal\s+server)\b",
            re.IGNORECASE,
        ),
        "network_failure",
        "Network / Service Outage",
        "high",
    ),
    (
        re.compile(
            r"\b(uncaught\s+exception|fatal\s+error|unhandled|nullpointer|typeerror|referenceerror|"
            r"segmentation\s+fault|panic|traceback|exception|error\s+while\s+evaluating)\b",
            re.IGNORECASE,
        ),
        "application_exception",
        "Application Exception",
        "critical",
    ),
    (
        re.compile(
            r"\b(permission\s+denied|access\s+denied|unauthorized|forbidden|invalid\s+credentials|"
            r"403\s+forbidden|auth\s+failed)\b",
            re.IGNORECASE,
        ),
        "auth_failure",
        "Auth / Access Failure",
        "medium",
    ),
    (
        re.compile(
            r"\b(deprecated|warning|warn|slow\s+query|high\s+memory|threshold\s+exceeded)\b",
            re.IGNORECASE,
        ),
        "runtime_warning",
        "Runtime Warning",
        "low",
    ),
    (
        re.compile(
            r"\b(error|failed|failure|crash|fatal|critical|exit\s+code)\b",
            re.IGNORECASE,
        ),
        "general_error",
        "System Error",
        "medium",
    ),
]


def classify_cluster_error(cluster: Cluster) -> ClassifiedError | None:
    """Classify a cluster as an application or system error if it matches known error heuristics."""
    text_to_check = f"{cluster.template} {' '.join(cluster.sample_messages)}"

    for regex, cat_id, cat_label, default_sev in ERROR_PATTERNS:
        if regex.search(text_to_check):
            sample = cluster.sample_messages[0] if cluster.sample_messages else cluster.template
            return ClassifiedError(
                cluster_id=cluster.id,
                template=cluster.template,
                count=cluster.count,
                category=cat_id,
                category_label=cat_label,
                severity=default_sev,
                sample_message=sample,
                top_fields=cluster.top_fields,
            )

    return None


def extract_classified_errors(clusters: list[Cluster]) -> list[ClassifiedError]:
    """Scan all mined clusters in a report and return detected application and system errors."""
    errors: list[ClassifiedError] = []
    for c in clusters:
        classified = classify_cluster_error(c)
        if classified is not None:
            errors.append(classified)

    # Sort by severity rank (critical > high > medium > low) and event frequency
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    errors.sort(key=lambda e: (sev_rank.get(e.severity, 0), e.count), reverse=True)
    return errors
