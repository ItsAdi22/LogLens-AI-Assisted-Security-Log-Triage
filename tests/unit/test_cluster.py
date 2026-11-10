"""Unit tests for Drain3 log template clustering."""

from datetime import UTC, datetime, timedelta

from loglens.cluster.drain import DrainClusterer
from loglens.models import Event, compute_raw_hash


def test_drain_clusterer_basic() -> None:
    """Verify DrainClusterer groups similar log messages and tracks metrics."""
    clusterer = DrainClusterer()
    now = datetime.now(UTC)

    # Add 3 similar SSH failed events
    for i in range(3):
        ev = Event(
            ts=now + timedelta(seconds=i),
            source="sshd",
            host="srv1",
            severity_hint="warning",
            message=f"Failed password for user{i} from 192.0.2.1 port 5000{i}",
            fields={"user": f"user{i}", "ip": "192.0.2.1", "port": 50000 + i},
            raw_hash=compute_raw_hash(f"ev{i}"),
        )
        clusterer.add_event(ev)

    clusters = clusterer.get_clusters()
    assert len(clusters) == 1
    c = clusters[0]
    assert c.count == 3
    assert "Failed password for" in c.template
    assert len(c.sample_messages) == 3
    assert "ip" in c.top_fields
    assert c.top_fields["ip"][0] == ("192.0.2.1", 3)


def test_drain_clusterer_multiple_templates() -> None:
    """Verify DrainClusterer segregates distinct message templates."""
    clusterer = DrainClusterer()
    now = datetime.now(UTC)

    ev_auth = Event(
        ts=now,
        source="sshd",
        host="srv1",
        severity_hint="warning",
        message="Failed password for root from 192.0.2.10 port 44321",
        fields={"ip": "192.0.2.10"},
        raw_hash="hash1",
    )
    ev_web = Event(
        ts=now + timedelta(seconds=1),
        source="web",
        host="srv1",
        severity_hint="info",
        message="GET /index.html 200",
        fields={"status": 200},
        raw_hash="hash2",
    )

    clusterer.add_events([ev_auth, ev_web])
    clusters = clusterer.get_clusters()
    assert len(clusters) == 2
    templates = [c.template for c in clusters]
    assert any("Failed password" in t for t in templates)
    assert any("GET" in t for t in templates)


def test_drain3_preprocessing_regression_no_timestamp() -> None:
    """Regression test: verify ISO8601 timestamps and leading host/program prefix are stripped."""
    clusterer = DrainClusterer()
    raw = (
        "2026-11-10T15:20:18.560675+05:30 mpanel (systemd): "
        "pam_unix(systemd-user:session): session opened for user root(uid=0) by root(uid=0)"
    )
    ev = Event(
        ts=datetime.now(UTC),
        source="systemd",
        host="mpanel",
        severity_hint="info",
        message=raw,
        fields={},
        raw_hash="reg_hash_01",
    )
    clusterer.add_event(ev)
    clusters = clusterer.get_clusters()
    assert len(clusters) == 1
    template = clusters[0].template
    assert "2026" not in template
    assert "15:20:18" not in template
    assert "+05:30" not in template
    assert "mpanel" not in template
    assert "pam_unix(systemd-user:session): session opened for user root" in template
