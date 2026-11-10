"""Base protocols, filters, and cooldown trackers for security notifications."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Protocol

from loglens.models import Finding, ReportMetadata

SEVERITY_LEVELS = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


class Notifier(Protocol):
    """Protocol implemented by notification channels (Telegram, Discord, Webhook)."""

    name: str

    def send_alert(self, finding: Finding, report_meta: ReportMetadata | None = None) -> bool:
        """Send an urgent alert for an individual security finding.

        Returns True if delivered, False if throttled, ignored, or failed.
        """
        ...

    def send_digest(self, findings: list[Finding], report_meta: ReportMetadata) -> bool:
        """Send a periodic digest summarizing multiple findings.

        Returns True if delivered, False otherwise.
        """
        ...


class CooldownTracker:
    """Tracks notification timestamps to eliminate repetitive alert spam within a cooldown window."""

    def __init__(self, default_cooldown_seconds: float = 3600.0) -> None:
        self.default_cooldown = default_cooldown_seconds
        self._last_alerted: dict[str, datetime] = {}

    @staticmethod
    def compute_fingerprint(finding: Finding) -> str:
        """Compute stable fingerprint for deduplicating repeated findings."""
        rules_key = ":".join(sorted(finding.rule_ids))
        clusters_key = ":".join(sorted(finding.cluster_ids))
        attack_key = finding.llm.attack_type if finding.llm and finding.llm.attack_type else ""
        raw = f"{finding.rule_severity}:{rules_key}:{clusters_key}:{attack_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def should_alert(
        self,
        finding: Finding,
        cooldown_seconds: float | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Determine if an alert should fire or be suppressed by cooldown.

        Updates the timestamp if alert is permitted.
        """
        cooldown = cooldown_seconds if cooldown_seconds is not None else self.default_cooldown
        fingerprint = self.compute_fingerprint(finding)
        current_time = now or datetime.now(UTC)

        if fingerprint in self._last_alerted:
            elapsed = (current_time - self._last_alerted[fingerprint]).total_seconds()
            if elapsed < cooldown:
                return False

        self._last_alerted[fingerprint] = current_time
        return True

    def clear(self) -> None:
        """Reset all tracked alert history."""
        self._last_alerted.clear()


class MockNotifier:
    """Deterministic mock notifier for offline testing and CI verification."""

    def __init__(
        self,
        name: str = "mock",
        min_severity: str = "info",
        cooldown_seconds: float = 3600.0,
    ) -> None:
        self.name = name
        self.min_severity = min_severity.lower()
        self.cooldown = CooldownTracker(default_cooldown_seconds=cooldown_seconds)
        self.sent_alerts: list[Finding] = []
        self.sent_digests: list[tuple[list[Finding], ReportMetadata]] = []

    def send_alert(self, finding: Finding, report_meta: ReportMetadata | None = None) -> bool:
        # Check severity threshold
        f_lvl = SEVERITY_LEVELS.get(finding.rule_severity.lower(), 1)
        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        if f_lvl < min_lvl:
            return False

        # Check cooldown
        if not self.cooldown.should_alert(finding):
            return False

        self.sent_alerts.append(finding)
        return True

    def send_digest(self, findings: list[Finding], report_meta: ReportMetadata) -> bool:
        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        qualified = [
            f for f in findings if SEVERITY_LEVELS.get(f.rule_severity.lower(), 1) >= min_lvl
        ]
        self.sent_digests.append((qualified, report_meta))
        return True


logger = logging.getLogger(__name__)


class CompositeNotifier:
    """Dispatches alerts and digests to multiple underlying notifiers."""

    name: str = "composite"

    def __init__(
        self,
        notifiers: list[Notifier] | None = None,
        min_severity: str = "medium",
    ) -> None:
        self.notifiers: list[Notifier] = notifiers or []
        self.min_severity = min_severity.lower()

    def _is_configured(self) -> bool:
        """True if at least one underlying notifier is configured."""
        if not self.notifiers:
            return False
        for n in self.notifiers:
            if not hasattr(n, "_is_configured") or bool(n._is_configured()):
                return True
        return False

    def send_alert(self, finding: Finding, report_meta: ReportMetadata | None = None) -> bool:
        """Send alert to all configured underlying notifiers."""
        f_lvl = SEVERITY_LEVELS.get(finding.rule_severity.lower(), 1)
        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        if f_lvl < min_lvl:
            return False

        any_sent = False
        for notifier in self.notifiers:
            try:
                if hasattr(notifier, "_is_configured") and not notifier._is_configured():
                    continue
                if notifier.send_alert(finding, report_meta):
                    any_sent = True
            except Exception as e:
                logger.warning(
                    "Error dispatching alert to %s: %s",
                    getattr(notifier, "name", str(notifier)),
                    e,
                )
        return any_sent

    def send_digest(self, findings: list[Finding], report_meta: ReportMetadata) -> bool:
        """Send digest to all configured underlying notifiers."""
        any_sent = False
        for notifier in self.notifiers:
            try:
                if hasattr(notifier, "_is_configured") and not notifier._is_configured():
                    continue
                if notifier.send_digest(findings, report_meta):
                    any_sent = True
            except Exception as e:
                logger.warning(
                    "Error dispatching digest to %s: %s",
                    getattr(notifier, "name", str(notifier)),
                    e,
                )
        return any_sent
