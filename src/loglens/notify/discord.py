"""Discord Webhook notifier for security alerts and digests."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from loglens.models import Finding, ReportMetadata
from loglens.notify.base import SEVERITY_LEVELS, CooldownTracker

logger = logging.getLogger(__name__)

DISCORD_COLORS = {
    "critical": 0xFF0000,
    "high": 0xFF4500,
    "medium": 0xFFA500,
    "low": 0x1E90FF,
    "info": 0x808080,
}


class DiscordNotifier:
    """Delivers rich embed alerts to Discord channels via Webhooks."""

    name: str = "discord"

    def __init__(
        self,
        webhook_url: str | None = None,
        min_severity: str = "medium",
        cooldown_seconds: float = 3600.0,
    ) -> None:
        self.webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.min_severity = min_severity.lower()
        self.cooldown = CooldownTracker(default_cooldown_seconds=cooldown_seconds)

    def _is_configured(self) -> bool:
        return bool(self.webhook_url and self.webhook_url.startswith("http"))

    def send_alert(self, finding: Finding, report_meta: ReportMetadata | None = None) -> bool:
        """Send formatted Discord embed alert if meeting severity and cooldown."""
        f_lvl = SEVERITY_LEVELS.get(finding.rule_severity.lower(), 1)
        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        if f_lvl < min_lvl:
            return False

        if not self.cooldown.should_alert(finding):
            logger.info("Discord alert for %s suppressed by cooldown.", finding.id)
            return False

        if not self._is_configured():
            logger.warning("Discord webhook URL is not configured.")
            return False

        color = DISCORD_COLORS.get(finding.rule_severity.lower(), 0x808080)
        rules_str = ", ".join(finding.rule_ids) if finding.rule_ids else "Heuristic Detection"
        clusters_str = ", ".join(finding.cluster_ids)

        fields: list[dict[str, Any]] = [
            {"name": "Severity", "value": finding.rule_severity.upper(), "inline": True},
            {"name": "Rules", "value": rules_str, "inline": True},
            {"name": "Clusters", "value": clusters_str, "inline": True},
        ]

        description = f"Security finding detected on cluster(s) `{clusters_str}`."
        if finding.llm:
            description = finding.llm.summary
            fields.append(
                {
                    "name": "Threat Category",
                    "value": f"{finding.llm.attack_type or 'Unknown'} ({finding.llm.confidence * 100:.0f}% confidence)",
                    "inline": False,
                }
            )
            if finding.llm.recommended_actions:
                actions_text = "\n".join(f"• {act}" for act in finding.llm.recommended_actions[:3])
                fields.append(
                    {"name": "Recommended Actions", "value": actions_text, "inline": False}
                )

        embed = {
            "title": f"🚨 LogLens Finding: {finding.id}",
            "description": description,
            "color": color,
            "fields": fields,
            "footer": {"text": "LogLens AI-Assisted Security Log Triage"},
        }

        return self._post_payload({"embeds": [embed]})

    def send_digest(self, findings: list[Finding], report_meta: ReportMetadata) -> bool:
        """Send a digest embed summarizing all qualifying findings."""
        if not self._is_configured():
            return False

        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        qualifying = [
            f for f in findings if SEVERITY_LEVELS.get(f.rule_severity.lower(), 1) >= min_lvl
        ]

        embed = {
            "title": "📋 LogLens Triage Digest",
            "description": f"Log triage run summary for `{report_meta.log_source}`.",
            "color": 0x1E90FF,
            "fields": [
                {"name": "Total Lines", "value": str(report_meta.total_lines), "inline": True},
                {"name": "Parsed Events", "value": str(report_meta.parsed_events), "inline": True},
                {"name": "Total Findings", "value": str(len(qualifying)), "inline": True},
            ],
            "footer": {"text": "LogLens Security"},
        }
        return self._post_payload({"embeds": [embed]})

    def _post_payload(self, payload: dict[str, Any]) -> bool:
        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(self.webhook_url, json=payload)
                res.raise_for_status()
                return True
        except Exception as e:
            logger.error("Failed to deliver Discord notification: %s", e)
            return False
