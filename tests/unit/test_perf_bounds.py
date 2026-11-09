"""Performance and memory boundedness unit tests."""

import tracemalloc
from datetime import UTC, datetime

from loglens.cluster import DrainClusterer
from loglens.parsers import AuthLogParser
from loglens.rules import RuleEngine, get_builtin_rules


def test_memory_bounded_streaming_clustering() -> None:
    """Verify that streaming through 5,000 log events maintains bounded peak memory."""
    parser = AuthLogParser()
    clusterer = DrainClusterer()
    engine = RuleEngine(get_builtin_rules())

    tracemalloc.start()

    events = []
    for i in range(5000):
        raw_line = (
            f"Nov 09 12:00:{i % 60:02d} server sshd[{1000 + (i % 20)}]: "
            f"Failed password for invalid user user{i % 10} from 192.0.2.{i % 5} port {50000 + i} ssh2"
        )
        ev = parser.parse_line(
            raw_line, i + 1, reference_dt=datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
        )
        if ev:
            events.append(ev)
            clusterer.add_event(ev)

    clusters = clusterer.get_clusters()
    findings = engine.evaluate(events, clusters)

    _current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak_mem / (1024 * 1024)
    # Peak memory for 5,000 parsed events and Drain3 clusters must remain well under 25MB
    assert peak_mb < 25.0
    assert len(clusters) > 0
    assert len(findings) > 0
