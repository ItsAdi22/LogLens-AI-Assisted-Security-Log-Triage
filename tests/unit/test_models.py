"""Unit tests for LogLens core data models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from loglens.models import (
    Cluster,
    Event,
    Finding,
    LLMAssessment,
    Report,
    ReportMetadata,
    compute_raw_hash,
)


def test_compute_raw_hash() -> None:
    """Verify compute_raw_hash is deterministic and 16 hex chars."""
    h1 = compute_raw_hash("sample line 1")
    h2 = compute_raw_hash("sample line 1")
    h3 = compute_raw_hash("sample line 2")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 16


def test_event_instantiation() -> None:
    """Verify Event model creation with standard fields."""
    now = datetime.now(UTC)
    ev = Event(
        ts=now,
        source="sshd",
        host="server1",
        severity_hint="warning",
        message="Failed password for root from 192.0.2.1",
        fields={"ip": "192.0.2.1", "user": "root"},
        raw_hash=compute_raw_hash("Failed password for root"),
    )
    assert ev.source == "sshd"
    assert ev.fields["ip"] == "192.0.2.1"
    assert ev.raw is None


def test_cluster_instantiation() -> None:
    """Verify Cluster model creation and fields."""
    now = datetime.now(UTC)
    cluster = Cluster(
        id="cluster-1",
        template="Failed password for <*> from <*>",
        count=42,
        first_seen=now,
        last_seen=now,
        top_fields={"ip": [("192.0.2.1", 40), ("192.0.2.2", 2)]},
        sample_messages=["Failed password for root from 192.0.2.1"],
    )
    assert cluster.count == 42
    assert len(cluster.sample_messages) == 1


def test_llm_assessment_validation() -> None:
    """Verify LLMAssessment enforces confidence range and literals."""
    assessment = LLMAssessment(
        summary="SSH brute force attempt detected",
        attack_type="ssh_bruteforce",
        severity="high",
        confidence=0.95,
        evidence=["42 failed attempts in 2 minutes", "Single source IP"],
        recommended_actions=["Block IP in firewall", "Enforce SSH key auth"],
        false_positive_likelihood="low",
    )
    assert assessment.severity == "high"
    assert assessment.confidence == 0.95

    with pytest.raises(ValidationError):
        LLMAssessment(
            summary="Invalid confidence",
            severity="high",
            confidence=1.5,  # must be <= 1.0
            false_positive_likelihood="low",
        )


def test_finding_and_report() -> None:
    """Verify Finding and Report models."""
    now = datetime.now(UTC)
    finding = Finding(
        id="f-001",
        cluster_ids=["cluster-1"],
        rule_ids=["ssh-bruteforce-001"],
        rule_severity="high",
        llm=None,
    )
    report = Report(
        metadata=ReportMetadata(
            generated_at=now,
            log_source="auth.log",
            total_lines=100,
            parsed_events=100,
            unparsed_lines=0,
            total_clusters=1,
            findings_count=1,
        ),
        findings=[finding],
        clusters=[],
        stats={"duration_sec": 0.5},
    )
    assert report.metadata.total_lines == 100
    assert report.findings[0].rule_severity == "high"
