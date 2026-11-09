"""Unit tests for the YAML rule schema and rule engine."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from loglens.models import Cluster, Event, compute_raw_hash
from loglens.rules import (
    RuleEngine,
    get_builtin_rules,
)
from loglens.rules.schema import Rule, parse_window_to_seconds


def test_parse_window_to_seconds() -> None:
    """Verify window parsing for s, m, h, d."""
    assert parse_window_to_seconds("30s") == 30.0
    assert parse_window_to_seconds("5m") == 300.0
    assert parse_window_to_seconds("2h") == 7200.0
    assert parse_window_to_seconds("1d") == 86400.0
    assert parse_window_to_seconds(None) == 300.0


def test_load_all_builtin_rules() -> None:
    """Verify that all built-in rules validate against the schema."""
    rules = get_builtin_rules()
    assert len(rules) >= 15
    rule_ids = {r.id for r in rules}
    assert "ssh-bruteforce-001" in rule_ids
    assert "web-sqli-attempt-005" in rule_ids
    assert "web-scanner-ua-007" in rule_ids


def test_rule_schema_validation_failure() -> None:
    """Verify Rule model rejects invalid IDs or extra forbidden fields."""
    with pytest.raises(ValidationError):
        Rule.model_validate(
            {
                "id": "invalid id with spaces",
                "title": "Bad Rule",
                "description": "Desc",
                "match": {},
                "severity": "high",
            }
        )


def test_rule_engine_ssh_bruteforce() -> None:
    """Verify RuleEngine fires ssh-bruteforce-001 on simulated attack."""
    rules = get_builtin_rules()
    engine = RuleEngine(rules)

    now = datetime.now(UTC)
    events: list[Event] = []

    # Generate 15 failed password attempts from 192.0.2.100 within 2 minutes
    for i in range(15):
        events.append(
            Event(
                ts=now + timedelta(seconds=i * 5),
                source="sshd",
                host="srv1",
                severity_hint="warning",
                message=f"Failed password for user{i} from 192.0.2.100 port {50000 + i} ssh2",
                fields={
                    "action": "failed_password",
                    "ip": "192.0.2.100",
                    "user": f"user{i}",
                },
                raw_hash=compute_raw_hash(f"ev{i}"),
            )
        )

    cluster = Cluster(
        id="cluster-1",
        template="Failed password for <*> from <*> port <*>",
        count=15,
        first_seen=now,
        last_seen=now + timedelta(seconds=75),
        top_fields={"ip": [("192.0.2.100", 15)]},
        sample_messages=[events[0].message],
    )

    findings = engine.evaluate(events, [cluster])
    assert len(findings) >= 1
    rule_ids = {r for f in findings for r in f.rule_ids}
    assert "ssh-bruteforce-001" in rule_ids
    assert findings[0].rule_severity == "high"


def test_rule_engine_web_sqli_and_scanner() -> None:
    """Verify RuleEngine detects SQL injection and Nikto scanner UA."""
    rules = get_builtin_rules()
    engine = RuleEngine(rules)

    now = datetime.now(UTC)
    ev_sqli = Event(
        ts=now,
        source="web",
        host="web01",
        severity_hint="warning",
        message="GET /products?id=1%20UNION%20SELECT%20null,password 403",
        fields={
            "ip": "192.0.2.55",
            "path": "/products?id=1%20UNION%20SELECT%20null,password",
            "status": 403,
            "user_agent": "sqlmap/1.7",
        },
        raw_hash="sqli_hash",
    )

    cluster = Cluster(
        id="cluster-web-1",
        template="GET <*> 403",
        count=1,
        first_seen=now,
        last_seen=now,
        top_fields={"ip": [("192.0.2.55", 1)]},
        sample_messages=[ev_sqli.message],
    )

    findings = engine.evaluate([ev_sqli], [cluster])
    fired_rules = {r for f in findings for r in f.rule_ids}
    assert "web-sqli-attempt-005" in fired_rules
    assert "web-scanner-ua-007" in fired_rules
