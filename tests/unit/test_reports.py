"""Unit tests for Markdown, JSON, and HTML report generators."""

from datetime import UTC, datetime

from loglens.models import Cluster, Finding, LLMAssessment, Report, ReportMetadata
from loglens.report import (
    HTMLReportFormatter,
    JSONReportFormatter,
    MarkdownReportFormatter,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
)


def sample_report() -> Report:
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="test_auth.log",
        total_lines=500,
        parsed_events=480,
        unparsed_lines=20,
        total_clusters=5,
        findings_count=1,
    )
    cluster = Cluster(
        id="c-001",
        template="Failed password for root from 192.0.2.100 port 22",
        count=80,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("192.0.2.100", 80)]},
        sample_messages=["Failed password for root from 192.0.2.100 port 22 ssh2"],
    )
    finding = Finding(
        id="find-001",
        cluster_ids=["c-001"],
        rule_ids=["ssh-bruteforce-001"],
        rule_severity="high",
        llm=LLMAssessment(
            summary="Brute force login assault targeting root account.",
            attack_type="ssh_bruteforce",
            severity="high",
            confidence=0.98,
            evidence=["80 failed authentications from 192.0.2.100 in short duration"],
            recommended_actions=["Ban IP 192.0.2.100 at firewall", "Disable SSH root login"],
            false_positive_likelihood="low",
        ),
    )
    return Report(
        metadata=meta,
        findings=[finding],
        clusters=[cluster],
        stats={"parse_rate": 96.0},
    )


def test_markdown_report_generation() -> None:
    rep = sample_report()
    md = generate_markdown_report(rep)

    assert "# LogLens Security Triage Report" in md
    assert "Executive Summary" in md
    assert "test_auth.log" in md
    assert "find-001" in md
    assert "ssh-bruteforce-001" in md
    assert "Brute force login assault" in md
    assert "Ban IP 192.0.2.100" in md
    assert "c-001" in md

    formatter = MarkdownReportFormatter()
    assert formatter.format(rep) == md


def test_markdown_report_empty_findings() -> None:
    empty_rep = Report(
        metadata=ReportMetadata(
            generated_at=datetime.now(UTC),
            log_source="clean.log",
            total_lines=10,
            parsed_events=10,
            unparsed_lines=0,
            total_clusters=1,
            findings_count=0,
        ),
        findings=[],
        clusters=[],
    )
    md = generate_markdown_report(empty_rep)
    assert "No security threats or anomalous rule violations detected" in md


def test_json_report_generation() -> None:
    rep = sample_report()
    raw_json = generate_json_report(rep)

    roundtrip = Report.model_validate_json(raw_json)
    assert roundtrip.metadata.log_source == "test_auth.log"
    assert len(roundtrip.findings) == 1
    assert roundtrip.findings[0].id == "find-001"

    formatter = JSONReportFormatter()
    assert formatter.format(rep) == raw_json


def test_html_report_xss_safety() -> None:
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="<script>alert('source-xss')</script>",
        total_lines=10,
        parsed_events=10,
        unparsed_lines=0,
        total_clusters=1,
        findings_count=1,
    )
    malicious_finding = Finding(
        id="find-xss",
        cluster_ids=["<img src=x onerror=alert(1)>"],
        rule_ids=["rule-<script>"],
        rule_severity="critical",
        llm=LLMAssessment(
            summary="Attacker injected <script>document.cookie</script> in log.",
            attack_type="xss_attempt",
            severity="critical",
            confidence=1.0,
            evidence=["Payload contained <b>injection</b>"],
            recommended_actions=["Sanitize <input> tags"],
            false_positive_likelihood="low",
        ),
    )
    cluster = Cluster(
        id="c-xss",
        template="GET /<script>evil()</script> HTTP/1.1",
        count=1,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    rep = Report(
        metadata=meta,
        findings=[malicious_finding],
        clusters=[cluster],
    )

    rendered_html = generate_html_report(rep)

    # Verify all malicious tags were escaped
    assert "<script>alert('source-xss')</script>" not in rendered_html
    assert "&lt;script&gt;alert(&#x27;source-xss&#x27;)&lt;/script&gt;" in rendered_html
    assert "<img src=x onerror=alert(1)>" not in rendered_html
    assert "<script>document.cookie</script>" not in rendered_html
    assert "&lt;script&gt;document.cookie&lt;/script&gt;" in rendered_html
    assert "<b>injection</b>" not in rendered_html
    assert "&lt;b&gt;injection&lt;/b&gt;" in rendered_html

    # Ensure document structure
    assert "<!DOCTYPE html>" in rendered_html
    assert "toggleTheme()" in rendered_html

    formatter = HTMLReportFormatter()
    assert formatter.format(rep) == rendered_html
