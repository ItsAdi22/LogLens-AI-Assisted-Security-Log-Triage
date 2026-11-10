"""Unit tests for the LogLens CLI interface."""

import re
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from loglens import __version__
from loglens.cli import app, main, version_callback


def test_cli_version_flag(cli_runner: CliRunner) -> None:
    """Verify `loglens --version` prints the version and exits 0."""
    result = cli_runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"LogLens v{__version__}" in result.output


def test_cli_short_version_flag(cli_runner: CliRunner) -> None:
    """Verify `loglens -v` prints the version and exits 0."""
    result = cli_runner.invoke(app, ["-v"])
    assert result.exit_code == 0
    assert f"LogLens v{__version__}" in result.output


def test_cli_help_flag(cli_runner: CliRunner) -> None:
    """Verify `loglens --help` displays help text."""
    result = cli_runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", result.output)
    assert "LogLens" in clean
    assert "version" in clean.lower()


def test_version_callback_false() -> None:
    """Verify version_callback does nothing when passed False."""
    version_callback(False)


def test_version_callback_true() -> None:
    """Verify version_callback raises typer.Exit when passed True."""
    with pytest.raises(typer.Exit):
        version_callback(True)


def test_main_function() -> None:
    """Verify main() invokes the app."""
    with patch("loglens.cli.app") as mock_app:
        main()
        mock_app.assert_called_once()


def test_cli_module_main() -> None:
    """Verify executing loglens.cli as __main__ exits cleanly with --version."""
    with (
        patch.object(sys, "argv", ["loglens", "--version"]),
        pytest.raises(SystemExit) as exc_info,
    ):
        runpy.run_module("loglens.cli", run_name="__main__")
    assert exc_info.value.code == 0


def test_cli_analyze_command(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens analyze` successfully parses log files."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Nov 09 14:02:11 web01 sshd[1234]: Failed password for root from 192.0.2.15 port 44212 ssh2\n"
        "Nov 09 14:05:00 web01 sshd[1235]: Accepted publickey for ubuntu from 192.0.2.50 port 51234 ssh2: RSA\n",
        encoding="utf-8",
    )
    result = cli_runner.invoke(app, ["analyze", str(log_file), "--no-llm"])
    assert result.exit_code == 0
    assert "Log Parsing Summary" in result.output
    assert "Parsed Events" in result.output
    assert "192.0.2.15" in result.output


def test_cli_analyze_web_log(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens analyze` with web format."""
    log_file = tmp_path / "access.log"
    log_file.write_text(
        '192.0.2.10 - - [09/Nov/2026:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "curl"\n',
        encoding="utf-8",
    )
    result = cli_runner.invoke(app, ["analyze", str(log_file), "-f", "web", "--no-llm"])
    assert result.exit_code == 0
    assert "Log Parsing Summary" in result.output


def test_cli_analyze_stdin(cli_runner: CliRunner) -> None:
    """Verify `loglens analyze -` reads from stdin."""
    sample_input = "2026-11-09 12:00:00 Warning: host down\n"
    result = cli_runner.invoke(app, ["analyze", "-", "--no-llm"], input=sample_input)
    assert result.exit_code == 0
    assert "Log Parsing Summary" in result.output


def test_cli_analyze_missing_file(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens analyze` reports error when file is missing."""
    result = cli_runner.invoke(app, ["analyze", str(tmp_path / "nonexistent.log")])
    assert result.exit_code == 1
    assert "Log file not found" in result.output


def test_cli_analyze_invalid_format(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens analyze` reports error on unknown format."""
    log_file = tmp_path / "test.log"
    log_file.write_text("some log\n", encoding="utf-8")
    result = cli_runner.invoke(app, ["analyze", str(log_file), "--format", "nonexistent_format"])
    assert result.exit_code == 1
    assert "Unknown log format" in result.output


def test_cli_rules_list(cli_runner: CliRunner) -> None:
    """Verify `loglens rules list` displays registered rules."""
    result = cli_runner.invoke(app, ["rules", "list"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    assert "Available Detection Rules" in result.output
    assert "ssh-bruteforce-001" in result.output


def test_cli_rules_validate_success(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens rules validate` succeeds on valid rule."""
    rule_file = tmp_path / "test_rule.yml"
    rule_file.write_text(
        "id: test-rule-001\n"
        "title: Test Rule\n"
        "description: Testing\n"
        "match:\n"
        "  message_regex: 'test'\n"
        "severity: high\n",
        encoding="utf-8",
    )
    result = cli_runner.invoke(app, ["rules", "validate", str(rule_file)])
    assert result.exit_code == 0
    assert "Valid: Rule 'test-rule-001'" in result.output


def test_cli_rules_validate_missing_file(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens rules validate` reports error on missing file."""
    result = cli_runner.invoke(app, ["rules", "validate", str(tmp_path / "missing.yml")])
    assert result.exit_code == 1
    assert "File not found" in result.output


def test_cli_rules_validate_invalid_syntax(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens rules validate` reports error on invalid schema."""
    rule_file = tmp_path / "invalid_rule.yml"
    rule_file.write_text("id: 'invalid rule id with spaces'\n", encoding="utf-8")
    result = cli_runner.invoke(app, ["rules", "validate", str(rule_file)])
    assert result.exit_code == 1
    assert "Validation Error" in result.output


def test_cli_rules_test_command(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens rules test` correctly evaluates a rule against a log."""
    rule_file = tmp_path / "probe_rule.yml"
    rule_file.write_text(
        "id: probe-test-001\n"
        "title: Probe Test\n"
        "description: Testing probe\n"
        "match:\n"
        "  message_regex: 'malicious_probe'\n"
        "severity: high\n",
        encoding="utf-8",
    )
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "2026-11-09 12:00:00 malicious_probe from 192.0.2.1\n2026-11-09 12:01:00 normal traffic\n",
        encoding="utf-8",
    )
    result = cli_runner.invoke(app, ["rules", "test", str(rule_file), "--against", str(log_file)])
    assert result.exit_code == 0
    assert "RULE FIRED" in result.output
    assert "probe-test-001" in result.output


def test_cli_rules_test_no_match(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens rules test` reports when no events match."""
    rule_file = tmp_path / "probe_rule.yml"
    rule_file.write_text(
        "id: probe-test-002\n"
        "title: Probe Test\n"
        "description: Testing probe\n"
        "match:\n"
        "  message_regex: 'never_appears'\n"
        "severity: high\n",
        encoding="utf-8",
    )
    log_file = tmp_path / "test.log"
    log_file.write_text("2026-11-09 12:00:00 clean line\n", encoding="utf-8")
    result = cli_runner.invoke(app, ["rules", "test", str(rule_file), "--against", str(log_file)])
    assert result.exit_code == 0
    assert "NO MATCH" in result.output


def test_cli_serve_help(cli_runner: CliRunner) -> None:
    """Verify `loglens serve --help` displays all flags."""
    result = cli_runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", result.output)
    assert "--host" in clean
    assert "--port" in clean
    assert "--db" in clean
    assert "--token" in clean
    assert "--provider" in clean


def test_cli_plugins_list(cli_runner: CliRunner) -> None:
    """Verify `loglens plugins list` command executes cleanly."""
    result = cli_runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0


def test_cli_rules_import_sigma(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Verify `loglens rules import-sigma` converts Sigma YAML file."""
    sigma_file = tmp_path / "test_sigma.yml"
    sigma_file.write_text(
        "title: Suspicious Curl Download\nid: curl-dl-01\nlevel: high\n"
        "detection:\n  selection:\n    message|contains: 'curl http://'\n  condition: selection\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "converted_rules"

    result = cli_runner.invoke(
        app,
        ["rules", "import-sigma", str(sigma_file), "--out", str(out_dir)],
    )
    assert result.exit_code == 0
    assert "Successfully converted 1 Sigma rule(s)" in result.output
    assert (out_dir / "sigma-curl-dl-01.yml").exists()
