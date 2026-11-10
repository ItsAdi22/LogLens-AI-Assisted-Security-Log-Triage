"""Unit tests for application and system error classification."""

from datetime import UTC, datetime

from loglens.cluster.errors import (
    classify_cluster_error,
    extract_classified_errors,
)
from loglens.models import Cluster


def test_classify_cluster_error_database() -> None:
    c = Cluster(
        id="c-db-1",
        template="SQLSTATE[HY000] [<*>] Connection refused (Host: 127.0.0.1)",
        count=15,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        sample_messages=["SQLSTATE[HY000] [2002] Connection refused (Host: 127.0.0.1)"],
    )
    err = classify_cluster_error(c)
    assert err is not None
    assert err.category == "database_error"
    assert err.category_label == "Database / SQL Error"
    assert err.severity == "high"
    assert err.count == 15


def test_classify_cluster_error_exception() -> None:
    c = Cluster(
        id="c-exc-1",
        template="Uncaught Exception: Call to undefined function <*> at line <*>",
        count=5,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        sample_messages=["Uncaught Exception: Call to undefined function foo() at line 42"],
    )
    err = classify_cluster_error(c)
    assert err is not None
    assert err.category == "application_exception"
    assert err.severity == "critical"


def test_classify_cluster_error_network() -> None:
    c = Cluster(
        id="c-net-1",
        template="Upstream timed out (<*>) while connecting to upstream",
        count=8,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    err = classify_cluster_error(c)
    assert err is not None
    assert err.category == "network_failure"
    assert err.severity == "high"


def test_classify_cluster_error_warning() -> None:
    c = Cluster(
        id="c-warn-1",
        template="Deprecated: Using ${var} in strings is deprecated",
        count=20,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    err = classify_cluster_error(c)
    assert err is not None
    assert err.category == "runtime_warning"
    assert err.severity == "low"


def test_classify_cluster_error_benign_returns_none() -> None:
    c = Cluster(
        id="c-ok-1",
        template="GET /api/v1/health 200 OK (<*>ms)",
        count=500,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    assert classify_cluster_error(c) is None


def test_classify_cluster_error_sshd_never_misclassified_as_network_outage() -> None:
    """Verify sshd preauth reset lines are not classified as generic network/service outages."""
    c = Cluster(
        id="c-ssh-1",
        template="Connection reset by invalid user root <*> port <*> [preauth]",
        count=10,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        sample_messages=[
            "Connection reset by invalid user root 222.167.207.101 port 52342 [preauth]"
        ],
    )
    # Must return None so it never reaches application errors
    assert classify_cluster_error(c) is None


def test_extract_classified_errors_sorted() -> None:
    c1 = Cluster(
        id="c-1",
        template="Warning: Low disk space",
        count=100,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    c2 = Cluster(
        id="c-2",
        template="Fatal error: Out of memory",
        count=2,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    c3 = Cluster(
        id="c-3",
        template="SQLSTATE[42000] Syntax error in SQL statement",
        count=10,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    c4 = Cluster(
        id="c-4",
        template="User admin logged in successfully",
        count=50,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )

    errors = extract_classified_errors([c1, c2, c3, c4])
    assert len(errors) == 3
    # c2 is critical (top), c3 is high (second), c1 is low (third)
    assert errors[0].cluster_id == "c-2"
    assert errors[1].cluster_id == "c-3"
    assert errors[2].cluster_id == "c-1"
