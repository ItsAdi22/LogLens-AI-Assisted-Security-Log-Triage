"""Integration tests for Phase 2: Clustering and Rule Engine DoD verification."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from loglens.cluster import DrainClusterer
from loglens.models import Event, compute_raw_hash
from loglens.parsers import AuthLogParser, WebAccessParser
from loglens.rules import RuleEngine, get_builtin_rules


def test_clean_baseline_zero_false_positives() -> None:
    """DoD verification: Clean baseline traffic generates zero false positive findings."""
    rules = get_builtin_rules()
    engine = RuleEngine(rules)

    now = datetime.now(UTC)
    clean_events: list[Event] = []

    # 1. Routine accepted SSH logins from multiple internal admins
    for i in range(10):
        clean_events.append(
            Event(
                ts=now + timedelta(minutes=i * 5),
                source="sshd",
                host="srv1",
                severity_hint="info",
                message=f"Accepted publickey for admin from 192.0.2.50 port {40000 + i} ssh2",
                fields={"action": "accepted", "ip": "192.0.2.50", "user": "admin"},
                raw_hash=compute_raw_hash(f"clean_ssh_{i}"),
            )
        )

    # 2. Routine 200 OK web browsing
    for i in range(30):
        clean_events.append(
            Event(
                ts=now + timedelta(seconds=i * 10),
                source="web",
                host="web01",
                severity_hint="info",
                message=f"GET /page{i % 5}.html 200",
                fields={
                    "method": "GET",
                    "path": f"/page{i % 5}.html",
                    "status": 200,
                    "ip": "192.0.2.60",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                },
                raw_hash=compute_raw_hash(f"clean_web_{i}"),
            )
        )

    clusterer = DrainClusterer()
    clusterer.add_events(clean_events)
    clusters = clusterer.get_clusters()

    findings = engine.evaluate(clean_events, clusters)
    # The only rule that could fire on accepted logins is the informational 'ssh-success-after-failure-004' (severity info).
    # Zero high, critical, or medium security alert findings should trigger!
    security_alerts = [f for f in findings if f.rule_severity in ("critical", "high", "medium")]
    assert len(security_alerts) == 0


def test_synthetic_attack_logs_fire_expected_rules() -> None:
    """DoD verification: Attack logs correctly trigger expected high-severity rules."""
    rules = get_builtin_rules()
    engine = RuleEngine(rules)

    examples_dir = Path(__file__).resolve().parent.parent.parent / "examples"
    auth_log = examples_dir / "sample_auth.log"
    web_log = examples_dir / "sample_access.log"

    auth_parser = AuthLogParser()
    auth_events: list[Event] = []
    auth_clusterer = DrainClusterer()
    with open(auth_log, encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            ev = auth_parser.parse_line(line, idx)
            if ev:
                auth_events.append(ev)
                auth_clusterer.add_event(ev)

    auth_findings = engine.evaluate(auth_events, auth_clusterer.get_clusters())
    auth_rule_ids = {r for f in auth_findings for r in f.rule_ids}
    assert "ssh-bruteforce-001" in auth_rule_ids
    assert "ssh-invalid-user-002" in auth_rule_ids

    web_parser = WebAccessParser()
    web_events: list[Event] = []
    web_clusterer = DrainClusterer()
    with open(web_log, encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            ev = web_parser.parse_line(line, idx)
            if ev:
                web_events.append(ev)
                web_clusterer.add_event(ev)

    web_findings = engine.evaluate(web_events, web_clusterer.get_clusters())
    web_rule_ids = {r for f in web_findings for r in f.rule_ids}
    assert "web-sqli-attempt-005" in web_rule_ids
    assert "web-scanner-ua-007" in web_rule_ids
    assert "web-path-traversal-001" in web_rule_ids
    assert "web-env-probe-002" in web_rule_ids
