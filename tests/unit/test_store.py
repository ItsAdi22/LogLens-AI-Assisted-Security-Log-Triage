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


def test_storage_get_finding_and_cluster() -> None:
    storage = StorageManager(db_path=":memory:")
    rep = create_test_report()
    run_id = storage.save_run(rep, run_id="run-fc-01")

    # get_finding
    finding = storage.get_finding(run_id, "f-001")
    assert finding is not None
    assert finding.id == "f-001"
    assert finding.rule_severity == "high"

    # get_finding not found
    assert storage.get_finding(run_id, "nonexistent") is None

    # get_cluster
    cluster = storage.get_cluster(run_id, "c-001")
    assert cluster is not None
    assert cluster.id == "c-001"
    assert "Failed password" in cluster.template

    # get_cluster not found
    assert storage.get_cluster(run_id, "nonexistent") is None

    # update_finding_assessment
    new_assessment = LLMAssessment(
        summary="Updated forensic explanation",
        attack_type="credential_stuffing",
        severity="critical",
        confidence=0.99,
        evidence=["Multiple IPs targeted same account"],
        recommended_actions=["Deploy rate limiting"],
        false_positive_likelihood="low",
    )
    success = storage.update_finding_assessment(run_id, "f-001", new_assessment)
    assert success is True

    updated_finding = storage.get_finding(run_id, "f-001")
    assert updated_finding is not None
    assert updated_finding.llm is not None
    assert updated_finding.llm.attack_type == "credential_stuffing"
    assert updated_finding.llm.confidence == 0.99

    storage.close()


def test_storage_global_and_timeline_stats() -> None:
    storage = StorageManager(db_path=":memory:")
    rep = create_test_report()
    storage.save_run(rep, run_id="run-stat-01")

    stats = storage.get_global_stats()
    assert stats["total_runs"] == 1
    assert stats["total_events"] == 95
    assert stats["total_clusters"] == 1
    assert stats["total_findings"] == 1
    assert stats["severity_counts"]["high"] == 1

    timeline = storage.get_timeline_stats(days=5)
    assert len(timeline) >= 1
    assert timeline[0]["run_count"] == 1
    assert timeline[0]["total_findings"] == 1

    storage.close()


def test_storage_settings() -> None:
    storage = StorageManager(db_path=":memory:")
    assert storage.get_setting("telegram_bot_token") is None
    assert storage.get_setting("telegram_bot_token", default="default-tok") == "default-tok"

    storage.set_setting("telegram_bot_token", "123456:ABC-DEF")
    assert storage.get_setting("telegram_bot_token") == "123456:ABC-DEF"

    storage.set_setting("discord_webhook_url", "https://discord.com/webhook")
    all_settings = storage.get_all_settings()
    assert all_settings["telegram_bot_token"] == "123456:ABC-DEF"
    assert all_settings["discord_webhook_url"] == "https://discord.com/webhook"

    storage.close()


def test_storage_delete_run_and_clear_all() -> None:
    storage = StorageManager(db_path=":memory:")
    rep1 = create_test_report()
    rep2 = create_test_report()
    run1 = storage.save_run(rep1, run_id="run-del-01")
    run2 = storage.save_run(rep2, run_id="run-del-02")

    assert storage.get_run(run1) is not None
    assert storage.get_run(run2) is not None

    # Delete single run
    assert storage.delete_run(run1) is True
    assert storage.get_run(run1) is None
    assert storage.get_run(run2) is not None
    assert storage.delete_run("nonexistent-run") is False

    # Clear all runs
    cleared = storage.clear_all_runs()
    assert cleared == 1
    assert storage.get_run(run2) is None
    assert storage.get_global_stats()["total_runs"] == 0

    storage.close()
