"""Integration tests for Phase 3: Redaction, LLM triage, and CLI integration."""

from pathlib import Path

from typer.testing import CliRunner

from loglens.cli import app

runner = CliRunner()
EXAMPLES_DIR = Path("examples")


def test_cli_providers_test_mock() -> None:
    res = runner.invoke(app, ["providers", "test", "--provider", "mock"])
    assert res.exit_code == 0
    assert "Mock provider is operational" in res.output


def test_cli_analyze_dry_run_llm() -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    assert auth_log.exists()

    res = runner.invoke(
        app,
        ["analyze", str(auth_log), "--dry-run-llm", "--redaction", "standard"],
        env={"COLUMNS": "160"},
    )
    assert res.exit_code == 0
    assert "DRY RUN: LLM Triage Payload Preview" in res.output
    assert "<log_data>" in res.output
    assert "</log_data>" in res.output
    # Verification that redaction took place in the dry run output
    assert "[IP_" in res.output


def test_cli_analyze_with_mock_llm() -> None:
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    assert auth_log.exists()

    res = runner.invoke(
        app,
        ["analyze", str(auth_log), "--llm", "--provider", "mock"],
        env={"COLUMNS": "160"},
    )
    assert res.exit_code == 0
    assert "LogLens AI triaging top security clusters" in res.output
    assert "Triage Complete" in res.output
    assert "LLM Calls:" in res.output


def test_cli_analyze_unreachable_llm_graceful_fallback() -> None:
    """DoD: with LLM unreachable it still returns rule-based findings and exits cleanly."""
    auth_log = EXAMPLES_DIR / "sample_auth.log"
    assert auth_log.exists()

    # Point to an invalid local port that is guaranteed not to respond
    res = runner.invoke(
        app,
        [
            "analyze",
            str(auth_log),
            "--llm",
            "--provider",
            "ollama",
            "--base-url",
            "http://127.0.0.1:59999",
        ],
        env={"COLUMNS": "160"},
    )
    # Must exit cleanly (exit code 0) and still report rule-based security findings
    assert res.exit_code == 0
    assert "Security Findings" in res.output
    assert "Triage Complete" in res.output


def test_cli_analyze_strict_redaction() -> None:
    access_log = EXAMPLES_DIR / "sample_access.log"
    assert access_log.exists()

    res = runner.invoke(
        app,
        [
            "analyze",
            str(access_log),
            "--dry-run-llm",
            "--redaction",
            "strict",
        ],
        env={"COLUMNS": "160"},
    )
    assert res.exit_code == 0
    assert "DRY RUN" in res.output
