"""Generic JSON Webhook notifier with HMAC-SHA256 signature verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Any

import httpx

from loglens.models import Finding, ReportMetadata
from loglens.notify.base import SEVERITY_LEVELS, CooldownTracker

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Dispatches JSON security alerts to arbitrary HTTPS webhook endpoints."""

    name: str = "webhook"

    def __init__(
        self,
        webhook_url: str | None = None,
        secret: str | None = None,
        min_severity: str = "medium",
        cooldown_seconds: float = 3600.0,
    ) -> None:
        self.webhook_url = webhook_url or os.environ.get("LOGLENS_WEBHOOK_URL", "")
        self.secret = secret or os.environ.get("LOGLENS_WEBHOOK_SECRET", "")
        self.min_severity = min_severity.lower()
        self.cooldown = CooldownTracker(default_cooldown_seconds=cooldown_seconds)

    def _is_configured(self) -> bool:
        return bool(self.webhook_url and self.webhook_url.startswith("http"))

    def send_alert(self, finding: Finding, report_meta: ReportMetadata | None = None) -> bool:
        """Send finding payload to webhook."""
        f_lvl = SEVERITY_LEVELS.get(finding.rule_severity.lower(), 1)
        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        if f_lvl < min_lvl:
            return False

        if not self.cooldown.should_alert(finding):
            return False

        if not self._is_configured():
            logger.warning("Generic webhook URL is not configured.")
            return False

        payload = {
            "event_type": "finding_alert",
            "finding": finding.model_dump(),
            "source": report_meta.log_source if report_meta else "unknown",
        }
        return self._post_json(payload)

    def send_digest(self, findings: list[Finding], report_meta: ReportMetadata) -> bool:
        """Send complete digest payload to webhook."""
        if not self._is_configured():
            return False

        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        qualifying = [
            f for f in findings if SEVERITY_LEVELS.get(f.rule_severity.lower(), 1) >= min_lvl
        ]

        payload = {
            "event_type": "triage_digest",
            "metadata": report_meta.model_dump(),
            "findings": [f.model_dump() for f in qualifying],
        }
        return self._post_json(payload)

    def _post_json(self, data: dict[str, Any]) -> bool:
        body_bytes = json.dumps(data).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        if self.secret:
            sig = hmac.new(self.secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            headers["X-LogLens-Signature"] = f"sha256={sig}"

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(self.webhook_url, content=body_bytes, headers=headers)
                res.raise_for_status()
                return True
        except Exception as e:
            logger.error("Failed to post webhook payload: %s", e)
            return False
