"""Unit tests for the LogLens CLI interface."""

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
    assert "LogLens — AI-Assisted Security Log Triage" in result.output
    assert "--version" in result.output


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
    import runpy
    import sys

    with (
        patch.object(sys, "argv", ["loglens", "--version"]),
        pytest.raises(SystemExit) as exc_info,
    ):
        runpy.run_module("loglens.cli", run_name="__main__")
    assert exc_info.value.code == 0
