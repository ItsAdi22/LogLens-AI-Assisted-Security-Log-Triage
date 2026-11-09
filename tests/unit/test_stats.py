"""Unit tests for statistical anomaly detectors."""

from datetime import UTC, datetime, timedelta

from loglens.cluster.stats import (
    detect_entity_bursts,
    detect_rare_templates,
    detect_rate_spikes,
)
from loglens.models import Cluster, Event


def test_detect_entity_bursts() -> None:
    """Verify entity burst detection flags entities exceeding threshold."""
    now = datetime.now(UTC)
    events: list[Event] = []

    # Attacker generates 25 events within 1 minute
    for i in range(25):
        events.append(
            Event(
                ts=now + timedelta(seconds=i * 2),
                source="sshd",
                host="srv1",
                severity_hint="warning",
                message=f"Failed attempt {i}",
                fields={"ip": "192.0.2.100"},
                raw_hash=f"h{i}",
            )
        )

    # Benign IP generates only 3 events
    for i in range(3):
        events.append(
            Event(
                ts=now + timedelta(seconds=i * 10),
                source="sshd",
                host="srv1",
                severity_hint="info",
                message="Accepted key",
                fields={"ip": "192.0.2.200"},
                raw_hash=f"hb{i}",
            )
        )

    bursts = detect_entity_bursts(events, entity_field="ip", threshold_count=20, window_seconds=120)
    assert len(bursts) == 1
    assert bursts[0]["entity"] == "192.0.2.100"
    assert bursts[0]["burst_count"] == 25


def test_detect_rare_templates() -> None:
    """Verify rare template detector flags clusters with low relative frequency."""
    now = datetime.now(UTC)
    common_cluster = Cluster(
        id="c-1",
        template="Normal access <*> 200",
        count=99,
        first_seen=now,
        last_seen=now,
        top_fields={},
        sample_messages=[],
    )
    rare_cluster = Cluster(
        id="c-2",
        template="Kernel panic at <*>",
        count=1,
        first_seen=now,
        last_seen=now,
        top_fields={},
        sample_messages=[],
    )

    rare = detect_rare_templates(
        [common_cluster, rare_cluster], total_events=100, rarity_threshold=0.02
    )
    assert len(rare) == 1
    assert rare[0].id == "c-2"


def test_detect_rate_spikes() -> None:
    """Verify rate spike detector flags significant traffic spikes."""
    now = datetime.now(UTC)
    events: list[Event] = []

    # 10 minutes of baseline: 1 event per minute
    for m in range(10):
        events.append(
            Event(
                ts=now + timedelta(minutes=m),
                source="app",
                host=None,
                severity_hint="info",
                message="ping",
                fields={},
                raw_hash=f"p{m}",
            )
        )

    # Minute 11: 50 events spike
    for s in range(50):
        events.append(
            Event(
                ts=now + timedelta(minutes=11, seconds=s),
                source="app",
                host=None,
                severity_hint="info",
                message="spike",
                fields={},
                raw_hash=f"s{s}",
            )
        )

    spikes = detect_rate_spikes(events, bucket_seconds=60, z_threshold=2.5)
    assert len(spikes) >= 1
    assert spikes[0]["count"] == 50
