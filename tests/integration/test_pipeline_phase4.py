"""Integration tests for Phase 4: Reports, Store, Watch, and Exit Code Semantics."""

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from typer.testing import CliRunner

from loglens.cli import app
from loglens.models import Report
from loglens.notify.telegram import TelegramNotifier
from loglens.store import StorageManager

runner = CliRunner()
EXAMPLES_DIR = Path("examples")


def test_cli_analyze_generates_markdown_report_file(tmp_path: Path) -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    out_file = tmp_path / "report.md"

    res = runner.invoke(app, ["analyze", str(auth_log), "--no-llm", "--out", str(out_file)])
    assert res.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "# LogLens Security Triage Report" in content
    assert "Actionable Security Findings" in content


def test_cli_analyze_generates_json_report_file(tmp_path: Path) -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    out_file = tmp_path / "report.json"

    res = runner.invoke(app, ["analyze", str(auth_log), "--no-llm", "--out", str(out_file)])
    assert res.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    rep = Report.model_validate_json(content)
    assert rep.metadata.log_source == str(auth_log)


def test_cli_analyze_generates_html_report_file(tmp_path: Path) -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    out_file = tmp_path / "report.html"

    res = runner.invoke(app, ["analyze", str(auth_log), "--no-llm", "--out", str(out_file)])
    assert res.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "LogLens Security Triage" in content


def test_cli_exit_code_semantics_fail_on_threshold() -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"

    # sample_auth.log has high severity SSH brute force -> fail_on high exits with code 2
    res_high = runner.invoke(app, ["analyze", str(auth_log), "--no-llm", "--fail-on", "high"])
    assert res_high.exit_code == 2
    assert "Fail-On Threshold Triggered" in res_high.output

    # fail_on none exits with code 0
    res_ok = runner.invoke(app, ["analyze", str(auth_log), "--no-llm", "--fail-on", "none"])
    assert res_ok.exit_code == 0


def test_cli_report_command_from_stored_history(tmp_path: Path) -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    # First analyze to populate store
    runner.invoke(app, ["analyze", str(auth_log), "--no-llm"])

    # Query report since 24h in markdown
    res_md = runner.invoke(app, ["report", "--since", "24h", "--format", "md"])
    assert res_md.exit_code == 0
    assert "LogLens Security Triage Report" in res_md.output

    # Query report in JSON and write to disk
    out_json = tmp_path / "stored_report.json"
    res_json = runner.invoke(
        app, ["report", "--since", "24h", "--format", "json", "--out", str(out_json)]
    )
    assert res_json.exit_code == 0
    assert out_json.exists()


def test_dod_telegram_daily_digest_and_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    """DoD: Daily digest runs from cron, sends one Telegram message, and doesn't repeat identical alerts within cooldown."""
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    runner.invoke(app, ["analyze", str(auth_log), "--no-llm"])

    storage = StorageManager()
    runs = storage.list_runs(limit=1)
    assert len(runs) > 0
    latest_run_id = runs[0]["run_id"]
    report = storage.get_run(latest_run_id)
    assert report is not None
    assert len(report.findings) > 0

    telegram_calls: list[dict[str, object]] = []

    def mock_post(url: str, json: dict[str, object], **kwargs: object) -> MagicMock:
        telegram_calls.append(json)
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        return resp

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.side_effect = mock_post
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    notifier = TelegramNotifier(
        bot_token="test-bot-token",
        chat_id="test-chat-id",
        min_severity="high",
        cooldown_seconds=3600.0,
    )

    # 1. Send daily digest: sends exactly one consolidated Telegram message
    digest_sent = notifier.send_digest(report.findings, report.metadata)
    assert digest_sent is True
    assert len(telegram_calls) == 1
    assert "LogLens Triage Digest" in str(telegram_calls[0]["text"])

    # 2. Immediate urgent alert for finding with severity >= high fires
    high_findings = [f for f in report.findings if f.rule_severity in ("high", "critical")]
    assert len(high_findings) > 0
    target_finding = high_findings[0]
    alert_1 = notifier.send_alert(target_finding, report.metadata)
    assert alert_1 is True
    assert len(telegram_calls) == 2

    # 3. Duplicate alert within cooldown window is suppressed!
    alert_2 = notifier.send_alert(target_finding, report.metadata)
    assert alert_2 is False
    assert len(telegram_calls) == 2  # No new message dispatched

    storage.close()
