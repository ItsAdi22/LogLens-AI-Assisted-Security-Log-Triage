"""Unit tests for the `__main__` module."""

import runpy
from unittest.mock import patch


def test_main_module_execution() -> None:
    """Verify executing loglens.__main__ calls cli.main."""
    with patch("loglens.cli.main") as mock_main:
        runpy.run_module("loglens.__main__", run_name="__main__")
        mock_main.assert_called_once()
