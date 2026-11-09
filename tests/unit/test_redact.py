"""Unit tests for the redaction engine and patterns."""

from datetime import UTC, datetime

from loglens.models import Cluster, LLMAssessment
from loglens.redact import Redactor


def test_redact_ipv4() -> None:
    redactor = Redactor(level="standard")
    text = "Failed password for root from 192.0.2.100 port 22 ssh2"
    redacted = redactor.redact(text)
    assert "[IP_1]" in redacted
    assert "192.0.2.100" not in redacted
    restored = redactor.restore(redacted)
    assert restored == text


def test_redact_ipv6() -> None:
    redactor = Redactor(level="standard")
    text = "Connection from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 port 5432"
    redacted = redactor.redact(text)
    assert "[IP_1]" in redacted
    assert "2001:0db8" not in redacted
    assert redactor.restore(redacted) == text


def test_redact_email() -> None:
    redactor = Redactor(level="standard")
    text = "User admin@company.corp requested password reset"
    redacted = redactor.redact(text)
    assert "[EMAIL_1]" in redacted
    assert "admin@company.corp" not in redacted
    assert redactor.restore(redacted) == text


def test_redact_jwt() -> None:
    redactor = Redactor(level="standard")
    raw_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0."
        "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    )
    text = f"Authorization header invalid: {raw_jwt}"
    redacted = redactor.redact(text)
    assert "[JWT_1]" in redacted
    assert raw_jwt not in redacted
    assert redactor.restore(redacted) == text


def test_redact_aws_key() -> None:
    redactor = Redactor(level="standard")
    key = "AKIAIOSFODNN7EXAMPLE"
    text = f"AWS access denied for principal {key}"
    redacted = redactor.redact(text)
    assert "[AWS_KEY_1]" in redacted
    assert key not in redacted
    assert redactor.restore(redacted) == text


def test_redact_bearer_token() -> None:
    redactor = Redactor(level="standard")
    token = "secret-token-value-xyz123=="
    text = f"GET /api/v1/resource HTTP/1.1 with Bearer {token}"
    redacted = redactor.redact(text)
    assert "Bearer [TOKEN_1]" in redacted
    assert token not in redacted
    assert redactor.restore(redacted) == text


def test_redact_url_credentials() -> None:
    redactor = Redactor(level="standard")
    text = "Connected to postgresql://dbuser:s3cr3tp@ss@internal.db:5432/app"
    redacted = redactor.redact(text)
    assert "[CRED_1]" in redacted
    assert "s3cr3tp@ss" not in redacted
    assert redactor.restore(redacted) == text


def test_redact_query_param_credentials() -> None:
    redactor = Redactor(level="standard")
    text = "GET /login?user=admin&password=SuperSecretPassword123!&token=xyz HTTP/1.1"
    redacted = redactor.redact(text)
    assert "password=[SECRET_1]" in redacted
    assert "token=[SECRET_2]" in redacted
    assert "SuperSecretPassword123!" not in redacted
    assert redactor.restore(redacted) == text


def test_redact_private_key() -> None:
    redactor = Redactor(level="standard")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mY...\n-----END RSA PRIVATE KEY-----"
    text = f"Error reading certificate:\n{pem}\nCheck file permissions."
    redacted = redactor.redact(text)
    assert "[KEY_1]" in redacted
    assert "MIIEowIBAAKCAQEA0mY" not in redacted
    assert redactor.restore(redacted) == text


def test_redact_strict_paths() -> None:
    redactor_std = Redactor(level="standard")
    redactor_strict = Redactor(level="strict")
    text = "File not found: /home/jdoe/.ssh/authorized_keys"

    assert redactor_std.redact(text) == text  # standard leaves paths intact

    redacted_strict = redactor_strict.redact(text)
    assert "[PATH_1]" in redacted_strict
    assert "/home/jdoe" not in redacted_strict
    assert redactor_strict.restore(redacted_strict) == text


def test_redact_level_off() -> None:
    redactor = Redactor(level="off")
    text = "192.0.2.1 user@example.com AKIAIOSFODNN7EXAMPLE"
    assert redactor.redact(text) == text
    assert redactor.restore(text) == text


def test_token_consistency() -> None:
    redactor = Redactor(level="standard")
    ip = "198.51.100.42"
    text1 = f"Attempt from {ip} on port 22"
    text2 = f"Second attempt from {ip} on port 80"

    r1 = redactor.redact(text1)
    r2 = redactor.redact(text2)

    assert "[IP_1]" in r1
    assert "[IP_1]" in r2
    assert "[IP_2]" not in r2


def test_redact_cluster_and_restore_assessment() -> None:
    redactor = Redactor(level="standard")
    cluster = Cluster(
        id="c-001",
        template="Failed password for invalid user admin from 192.0.2.50 port 44122",
        count=15,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("192.0.2.50", 15)]},
        sample_messages=[
            "Failed password for invalid user admin from 192.0.2.50 port 44122 ssh2",
        ],
    )

    redacted_cluster = redactor.redact_cluster(cluster)
    assert "[IP_1]" in redacted_cluster.template
    assert redacted_cluster.top_fields["ip"][0][0] == "[IP_1]"
    assert "[IP_1]" in redacted_cluster.sample_messages[0]

    assessment = LLMAssessment(
        summary="Brute force attempt originating from [IP_1] against admin account.",
        attack_type="ssh_bruteforce",
        severity="high",
        confidence=0.95,
        evidence=["Multiple failed authentications from [IP_1]"],
        recommended_actions=["Block traffic from [IP_1] at firewall"],
        false_positive_likelihood="low",
    )

    restored = redactor.restore_assessment(assessment)
    assert "192.0.2.50" in restored.summary
    assert "192.0.2.50" in restored.evidence[0]
    assert "192.0.2.50" in restored.recommended_actions[0]
    assert "[IP_1]" not in restored.summary
