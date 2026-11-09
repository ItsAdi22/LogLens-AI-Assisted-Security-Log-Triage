"""Pytest fixtures and configuration for LogLens test suite."""

import pytest
from typer.testing import CliRunner


@pytest.fixture
def cli_runner() -> CliRunner:
    """Fixture providing a Typer CLI test runner."""
    return CliRunner()
