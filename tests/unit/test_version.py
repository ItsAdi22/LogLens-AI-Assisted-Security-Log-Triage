"""Unit tests for LogLens version definition."""

import loglens


def test_version_string() -> None:
    """Verify __version__ is defined and non-empty."""
    assert hasattr(loglens, "__version__")
    assert isinstance(loglens.__version__, str)
    assert len(loglens.__version__) > 0
