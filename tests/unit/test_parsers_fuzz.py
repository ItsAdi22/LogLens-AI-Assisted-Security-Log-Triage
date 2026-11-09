"""Property-based fuzz tests using Hypothesis.

Ensures all parsers never crash on arbitrary, malformed, or hostile inputs.
"""

from hypothesis import given
from hypothesis import strategies as st

from loglens.parsers import (
    AuthLogParser,
    GenericParser,
    JsonLinesParser,
    Parser,
    SyslogParser,
    WebAccessParser,
)

ALL_PARSERS: list[Parser] = [
    AuthLogParser(),
    WebAccessParser(),
    SyslogParser(),
    JsonLinesParser(),
    GenericParser(),
]


@given(st.text())
def test_parsers_never_crash_on_arbitrary_text(text: str) -> None:
    """Verify no parser throws uncaught exceptions on arbitrary text."""
    for parser in ALL_PARSERS:
        try:
            parser.parse_line(text, 1)
        except Exception as e:
            raise AssertionError(f"Parser {parser.name} crashed on input {text!r}") from e


@given(st.lists(st.text(max_size=100), max_size=20))
def test_matches_sample_never_crashes(sample: list[str]) -> None:
    """Verify matches_sample returns a valid score float between 0.0 and 1.0."""
    for parser in ALL_PARSERS:
        score = parser.matches_sample(sample)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


@given(st.binary())
def test_parsers_never_crash_on_binary_decoded_with_replace(data: bytes) -> None:
    """Verify decoded binary stream never triggers unhandled parser crashes."""
    text = data.decode("utf-8", errors="replace")
    for parser in ALL_PARSERS:
        parser.parse_line(text, 1)
