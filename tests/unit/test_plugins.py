"""Unit tests for the Python entry points plugin architecture."""

from collections.abc import Sequence
from datetime import datetime
from unittest.mock import MagicMock, patch

from loglens.models import Event
from loglens.parsers import registry as parser_registry
from loglens.plugins import (
    PARSER_GROUP,
    list_installed_plugins,
    load_plugins,
)


class DummyCustomParser:
    name = "dummy_custom"
    description = "Dummy custom parser for testing plugin system"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        return 0.0

    def parse_line(
        self, raw_line: str, line_number: int, *, reference_dt: datetime | None = None
    ) -> Event | None:
        return None


def test_list_installed_plugins_returns_list() -> None:
    plugins = list_installed_plugins()
    assert isinstance(plugins, list)


def test_load_plugins_with_mock_entry_point() -> None:
    mock_ep = MagicMock()
    mock_ep.name = "dummy_parser"
    mock_ep.load.return_value = DummyCustomParser

    with patch("importlib.metadata.entry_points") as mock_eps:
        # Return mock entry point when called with PARSER_GROUP
        def side_effect(group: str) -> list[MagicMock]:
            if group == PARSER_GROUP:
                return [mock_ep]
            return []

        mock_eps.side_effect = side_effect

        loaded = load_plugins()
        assert "dummy_parser" in loaded[PARSER_GROUP]
        assert parser_registry.get("dummy_custom") is not None
