"""Unit tests for SQLite storage manager, migrations, and run persistence."""

from datetime import UTC, datetime, timedelta

from loglens.models import Cluster, Finding, LLMAssessment, Report, ReportMetadata
from loglens.store import StorageManager


def create_test_report(source: str = "auth.log", findings_cnt: int = 1) -> Report:
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source=source,
        total_lines=100,
        parsed_events=95,
        unparsed_lines=5,
        total_clusters=2,
        findings_count=findings_cnt,
    )
    cluster = Cluster(
        id="c-001",
        template="Failed password for root from <*> port <*>",
        count=45,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("192.0.2.1", 45)]},
    )
    findings = []
    if findings_cnt > 0:
        findings.append(
            Finding(
                id="f-001",
                cluster_ids=["c-001"],
                rule_ids=["ssh-bruteforce-001"],
                rule_severity="high",
                llm=LLMAssessment(
                    summary="High volume brute force attempt.",
                    attack_type="ssh_bruteforce",
                    severity="high",
                    confidence=0.95,
                    evidence=["45 failures"],
                    recommended_actions=["Block IP"],
                    false_positive_likelihood="low",
                ),
            )
        )
    return Report(metadata=meta, findings=findings, clusters=[cluster], stats={"test": True})


def test_storage_save_and_get_run() -> None:
    storage = StorageManager(db_path=":memory:")
    rep = create_test_report()

    run_id = storage.save_run(rep, run_id="run-custom-001")
    assert run_id == "run-custom-001"

    retrieved = storage.get_run("run-custom-001")
    assert retrieved is not None
    assert retrieved.metadata.log_source == "auth.log"
    assert retrieved.metadata.total_lines == 100
    assert len(retrieved.findings) == 1
    assert retrieved.findings[0].id == "f-001"
    assert retrieved.findings[0].llm is not None
    assert retrieved.findings[0].llm.attack_type == "ssh_bruteforce"
    assert len(retrieved.clusters) == 1
    assert retrieved.clusters[0].id == "c-001"
    assert retrieved.stats == {"test": True}

    storage.close()


def test_storage_get_nonexistent_run() -> None:
    storage = StorageManager(db_path=":memory:")
    assert storage.get_run("nonexistent-run") is None
    storage.close()


def test_storage_list_runs() -> None:
    storage = StorageManager(db_path=":memory:")
    storage.save_run(create_test_report("app1.log"), run_id="run-1")
    storage.save_run(create_test_report("app2.log"), run_id="run-2")

    runs = storage.list_runs(limit=10)
    assert len(runs) == 2
    sources = [r["log_source"] for r in runs]
    assert "app1.log" in sources
    assert "app2.log" in sources
    storage.close()


def test_storage_get_findings_since_and_severity_filter() -> None:
    storage = StorageManager(db_path=":memory:")
    rep = create_test_report()
    storage.save_run(rep)

    past = datetime.now(UTC) - timedelta(hours=1)
    findings = storage.get_findings_since(past)
    assert len(findings) == 1

    # Filter with higher threshold
    crit_findings = storage.get_findings_since(past, min_severity="critical")
    assert len(crit_findings) == 0

    high_findings = storage.get_findings_since(past, min_severity="high")
    assert len(high_findings) == 1

    future = datetime.now(UTC) + timedelta(hours=1)
    future_findings = storage.get_findings_since(future)
    assert len(future_findings) == 0

    storage.close()
