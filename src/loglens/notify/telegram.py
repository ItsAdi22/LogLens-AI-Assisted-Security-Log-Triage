"""Telegram Bot notifier for urgent alerts and periodic digests."""

from __future__ import annotations

import html
import logging
import os

import httpx

from loglens.models import Finding, ReportMetadata
from loglens.notify.base import SEVERITY_LEVELS, CooldownTracker

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Delivers formatted HTML security alerts and digests via Telegram Bot API."""

    name: str = "telegram"

    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        min_severity: str = "medium",
        cooldown_seconds: float = 3600.0,
    ) -> None:
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
        self.min_severity = min_severity.lower()
        self.cooldown = CooldownTracker(default_cooldown_seconds=cooldown_seconds)

    def _is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send_alert(self, finding: Finding, report_meta: ReportMetadata | None = None) -> bool:
        """Send formatted urgent alert if meeting severity and not in cooldown."""
        f_lvl = SEVERITY_LEVELS.get(finding.rule_severity.lower(), 1)
        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        if f_lvl < min_lvl:
            return False

        if not self.cooldown.should_alert(finding):
            logger.info("Alert for finding %s suppressed by cooldown.", finding.id)
            return False

        if not self._is_configured():
            logger.warning(
                "Telegram notifier called but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing."
            )
            return False

        safe_id = html.escape(finding.id)
        safe_sev = html.escape(finding.rule_severity.upper())
        safe_rules = ", ".join(html.escape(r) for r in finding.rule_ids) or "Heuristic"

        lines = [
            f"🚨 <b>[{safe_sev}] LogLens Finding: {safe_id}</b>",
            f"<b>Rules:</b> <code>{safe_rules}</code>",
        ]

        if finding.llm:
            safe_attack = html.escape(finding.llm.attack_type or "Unknown")
            safe_summary = html.escape(finding.llm.summary)
            lines.append(
                f"<b>Threat:</b> {safe_attack} (Conf: {finding.llm.confidence * 100:.0f}%)"
            )
            lines.append(f"<b>Summary:</b> {safe_summary}")

            if finding.llm.recommended_actions:
                lines.append("\n<b>Recommended Actions:</b>")
                for act in finding.llm.recommended_actions[:3]:
                    lines.append(f"• {html.escape(act)}")

        message_html = "\n".join(lines)
        return self._send_message(message_html)

    def send_digest(self, findings: list[Finding], report_meta: ReportMetadata) -> bool:
        """Send a consolidated daily digest."""
        if not self._is_configured():
            return False

        min_lvl = SEVERITY_LEVELS.get(self.min_severity, 1)
        qualifying = [
            f for f in findings if SEVERITY_LEVELS.get(f.rule_severity.lower(), 1) >= min_lvl
        ]

        safe_src = html.escape(report_meta.log_source)
        lines = [
            "📋 <b>LogLens Triage Digest</b>",
            f"<b>Source:</b> <code>{safe_src}</code>",
            f"<b>Processed Lines:</b> {report_meta.total_lines:,}",
            f"<b>Total Findings:</b> {len(qualifying)} qualifying (out of {report_meta.findings_count} total)",
            "",
        ]

        if qualifying:
            lines.append("<b>Top Security Alerts:</b>")
            for idx, f in enumerate(qualifying[:5], 1):
                safe_id = html.escape(f.id)
                safe_sev = html.escape(f.rule_severity.upper())
                threat = html.escape(f.llm.attack_type or "Anomaly") if f.llm else "Rule Match"
                lines.append(f"{idx}. [{safe_sev}] <code>{safe_id}</code> - {threat}")
        else:
            lines.append(
                "✅ <i>No security findings exceeded severity threshold during this interval.</i>"
            )

        return self._send_message("\n".join(lines))

    def _send_message(self, text_html: str) -> bool:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text_html,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                return True
        except Exception as e:
            logger.error("Failed to deliver Telegram message: %s", e)
            return False
