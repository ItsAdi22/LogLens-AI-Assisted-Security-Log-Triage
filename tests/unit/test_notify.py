"""Unit tests for notification channels, cooldown deduplication, and HMAC signatures."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest

from loglens.models import Finding, LLMAssessment, ReportMetadata
from loglens.notify import (
    CompositeNotifier,
    CooldownTracker,
    DiscordNotifier,
    MockNotifier,
    TelegramNotifier,
    WebhookNotifier,
    get_notifier,
)


def sample_finding(rule_id: str = "rule-01", severity: str = "high") -> Finding:
    return Finding(
        id="find-sample",
        cluster_ids=["c-101"],
        rule_ids=[rule_id],
        rule_severity=severity,  # type: ignore[arg-type]
        llm=LLMAssessment(
            summary="Attack attempt detected.",
            attack_type="scanner",
            severity=severity,  # type: ignore[arg-type]
            confidence=0.9,
            evidence=["High volume requests"],
            recommended_actions=["Rate limit source"],
            false_positive_likelihood="low",
        ),
    )


def sample_meta() -> ReportMetadata:
    return ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="auth.log",
        total_lines=1000,
        parsed_events=980,
        unparsed_lines=20,
        total_clusters=12,
        findings_count=3,
    )


def test_cooldown_tracker_deduplication() -> None:
    tracker = CooldownTracker(default_cooldown_seconds=3600.0)
    finding = sample_finding()

    now = datetime.now(UTC)
    assert tracker.should_alert(finding, now=now) is True
    # Immediate repeat within cooldown must be suppressed
    assert tracker.should_alert(finding, now=now + timedelta(seconds=10)) is False

    # Different finding should trigger
    diff_finding = sample_finding(rule_id="different-rule")
    assert tracker.should_alert(diff_finding, now=now + timedelta(seconds=20)) is True

    # After cooldown expires, original finding should trigger again
    assert tracker.should_alert(finding, now=now + timedelta(seconds=3601)) is True

    tracker.clear()
    assert tracker.should_alert(finding, now=now) is True


def test_mock_notifier_severity_and_digest() -> None:
    notifier = MockNotifier(min_severity="high", cooldown_seconds=60.0)
    f_low = sample_finding(severity="low")
    f_high = sample_finding(severity="high")

    assert notifier.send_alert(f_low) is False
    assert len(notifier.sent_alerts) == 0

    assert notifier.send_alert(f_high) is True
    assert len(notifier.sent_alerts) == 1

    # Cooldown suppresses duplicate
    assert notifier.send_alert(f_high) is False
    assert len(notifier.sent_alerts) == 1

    # Digest delivery
    meta = sample_meta()
    assert notifier.send_digest([f_low, f_high], meta) is True
    assert len(notifier.sent_digests) == 1
    # Only f_high qualifies under min_severity="high"
    assert len(notifier.sent_digests[0][0]) == 1


def test_telegram_notifier_alert_and_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    notifier = TelegramNotifier(
        bot_token="fake-token",
        chat_id="fake-chat-id",
        min_severity="medium",
    )

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    f = sample_finding(severity="high")
    assert notifier.send_alert(f) is True
    assert mock_client.post.called

    # Digest
    assert notifier.send_digest([f], sample_meta()) is True


def test_discord_notifier_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    notifier = DiscordNotifier(
        webhook_url="https://discord.com/api/webhooks/1234/xyz",
        min_severity="low",
    )

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    f = sample_finding(severity="medium")
    assert notifier.send_alert(f) is True
    assert notifier.send_digest([f], sample_meta()) is True


def test_webhook_notifier_hmac_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    notifier = WebhookNotifier(
        webhook_url="https://alerts.internal.corp/hook",
        secret="super-secret-key",
        min_severity="info",
    )

    posted_headers: dict[str, str] = {}

    def fake_post(url: str, content: bytes, headers: dict[str, str]) -> MagicMock:
        nonlocal posted_headers
        posted_headers = dict(headers)
        res = MagicMock()
        res.status_code = 200
        return res

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.side_effect = fake_post

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    f = sample_finding(severity="high")
    assert notifier.send_alert(f) is True
    assert "X-LogLens-Signature" in posted_headers
    assert posted_headers["X-LogLens-Signature"].startswith("sha256=")


def test_notifier_factory() -> None:
    assert get_notifier("telegram").name == "telegram"
    assert get_notifier("discord").name == "discord"
    assert get_notifier("webhook").name == "webhook"
    assert get_notifier("mock").name == "mock"
    assert get_notifier("composite").name == "composite"

    with pytest.raises(ValueError, match="Unknown notifier channel"):
        get_notifier("unsupported")


def test_composite_notifier_dispatch_and_threshold() -> None:
    mock1 = MockNotifier(name="mock1", min_severity="info")
    mock2 = MockNotifier(name="mock2", min_severity="info")

    composite = CompositeNotifier([mock1, mock2], min_severity="high")
    assert composite._is_configured() is True

    f_low = sample_finding(severity="low")
    f_high = sample_finding(severity="high")

    # Below composite min_severity
    assert composite.send_alert(f_low) is False
    assert len(mock1.sent_alerts) == 0
    assert len(mock2.sent_alerts) == 0

    # Meets composite min_severity -> both notifiers receive
    assert composite.send_alert(f_high) is True
    assert len(mock1.sent_alerts) == 1
    assert len(mock2.sent_alerts) == 1

    # Digest
    meta = sample_meta()
    assert composite.send_digest([f_low, f_high], meta) is True
    assert len(mock1.sent_digests) == 1
    assert len(mock2.sent_digests) == 1


def test_composite_notifier_skips_unconfigured() -> None:
    unconf = DiscordNotifier(webhook_url="")
    conf = MockNotifier(name="mock_conf", min_severity="info")

    composite = CompositeNotifier([unconf, conf], min_severity="medium")
    f_high = sample_finding(severity="high")

    assert composite.send_alert(f_high) is True
    assert len(conf.sent_alerts) == 1
