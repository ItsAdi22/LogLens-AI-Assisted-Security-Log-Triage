"""Unit and integration tests for the LogLens Web UI (FastAPI + HTMX)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from loglens.models import Cluster, Finding, LLMAssessment, Report, ReportMetadata
from loglens.store import StorageManager
from loglens.web.app import create_app


def create_sample_report() -> Report:
    """Construct a sample Report instance for web UI tests."""
    cluster1 = Cluster(
        id="c-01",
        template="Failed password for invalid user <*>",
        count=15,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={
            "user": [("admin", 10), ("root", 5)],
            "ip": [("203.0.113.195", 15)],
        },
    )
    cluster2 = Cluster(
        id="c-02",
        template="Accepted publickey for deploy",
        count=2,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"user": [("deploy", 2)]},
    )

    finding1 = Finding(
        id="f-01",
        cluster_ids=["c-01"],
        rule_ids=["ssh_bruteforce"],
        rule_severity="high",
        llm=None,
    )

    metadata = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="/var/log/auth.log",
        total_lines=50,
        parsed_events=48,
        unparsed_lines=2,
        total_clusters=2,
        findings_count=1,
    )

    return Report(
        metadata=metadata,
        findings=[finding1],
        clusters=[cluster1, cluster2],
        stats={"auth_failures": 15},
    )


def test_health_check(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


def test_security_headers(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/health")
    assert "Content-Security-Policy" in response.headers
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_dashboard_empty_db(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Security Triage Operations" in response.text
    assert "No triage runs recorded yet" in response.text


def test_dashboard_with_runs(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-test-123")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    assert run_id in response.text
    assert "/var/log/auth.log" in response.text
    assert "1 Findings" in response.text


def test_run_detail_found(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-detail-456")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get(f"/runs/{run_id}")
    assert response.status_code == 200
    assert run_id in response.text
    assert "Failed password for invalid user" in response.text
    assert "ssh_bruteforce" in response.text
    assert "Explain with AI" in response.text


def test_run_detail_not_found(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/runs/nonexistent-run")
    assert response.status_code == 404
    assert "not found" in response.text


def test_explain_finding_on_demand_htmx(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-explain-789")
    storage.close()

    app = create_app(db_path=db_file, provider_name="mock")
    client = TestClient(app)

    # Post HTMX explain request
    response = client.post(f"/runs/{run_id}/findings/f-01/explain")
    assert response.status_code == 200
    assert "AI Threat Assessment" in response.text
    assert "Confidence:" in response.text

    # Verify assessment persisted in SQLite
    storage2 = StorageManager(db_file)
    updated_run = storage2.get_run(run_id)
    assert updated_run is not None
    assert updated_run.findings[0].llm is not None
    assert isinstance(updated_run.findings[0].llm, LLMAssessment)
    storage2.close()


def test_token_authentication(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    secret_token = "secret-soc-token-99"
    app = create_app(db_path=db_file, auth_token=secret_token)
    client = TestClient(app)

    # Missing token -> 401
    resp_unauth = client.get("/")
    assert resp_unauth.status_code == 401

    # Invalid token -> 401
    resp_bad = client.get("/", headers={"Authorization": "Bearer wrong-token"})
    assert resp_bad.status_code == 401

    # Valid Bearer header -> 200
    resp_ok = client.get("/", headers={"Authorization": f"Bearer {secret_token}"})
    assert resp_ok.status_code == 200

    # Valid query param -> 200
    resp_query = client.get(f"/?token={secret_token}")
    assert resp_query.status_code == 200


def test_api_endpoints(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-api-001")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # /api/stats
    resp_stats = client.get("/api/stats")
    assert resp_stats.status_code == 200
    stats = resp_stats.json()
    assert stats["total_runs"] == 1
    assert stats["total_findings"] == 1
    assert stats["severity_counts"]["high"] == 1

    # /api/runs
    resp_runs = client.get("/api/runs")
    assert resp_runs.status_code == 200
    runs = resp_runs.json()
    assert len(runs) == 1
    assert runs[0]["run_id"] == run_id

    # /api/runs/{run_id}
    resp_run = client.get(f"/api/runs/{run_id}")
    assert resp_run.status_code == 200
    run_data = resp_run.json()
    assert run_data["metadata"]["total_lines"] == 50
    assert len(run_data["findings"]) == 1


def test_analyze_page_get(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/analyze")
    assert response.status_code == 200
    assert "Analyze & Triage Logs" in response.text
    assert "Log Input Source" in response.text


def test_analyze_submit_pasted_text(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    log_snippet = (
        "Nov 10 12:00:01 server sshd[1024]: Failed password for root from 198.51.100.22 port 51234 ssh2\n"
        "Nov 10 12:00:02 server sshd[1025]: Failed password for root from 198.51.100.22 port 51235 ssh2\n"
    )

    response = client.post(
        "/analyze",
        data={
            "log_text": log_snippet,
            "format": "auth",
            "provider": "mock",
            "enable_llm": "true",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    redirect_url = response.headers["location"]
    assert redirect_url.startswith("/runs/run-")

    # Verify run view
    resp_run = client.get(redirect_url)
    assert resp_run.status_code == 200
    assert "Failed password for root" in resp_run.text


def test_analyze_submit_uploaded_file(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    log_snippet = (
        "Nov 10 12:00:01 server sshd[1024]: Accepted publickey for user admin from 198.51.100.22 port 51234 ssh2\n"
    )

    response = client.post(
        "/analyze",
        data={"format": "auto", "provider": "mock"},
        files={"file": ("test_auth.log", log_snippet.encode("utf-8"), "text/plain")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    redirect_url = response.headers["location"]

    resp_run = client.get(redirect_url)
    assert resp_run.status_code == 200
    assert "test_auth.log" in resp_run.text


def test_analyze_submit_empty_fails(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.post(
        "/analyze",
        data={"log_text": "   ", "format": "auto"},
    )
    assert response.status_code == 400


def test_settings_page_and_save(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    # GET /settings
    res_get = client.get("/settings")
    assert res_get.status_code == 200
    assert "Third-Party Alerts & Notifications" in res_get.text

    # POST /settings
    res_post = client.post(
        "/settings",
        data={
            "telegram_bot_token": "tok123",
            "telegram_chat_id": "chat456",
            "discord_webhook_url": "https://discord.com/webhook/test",
            "generic_webhook_url": "https://example.com/siem",
            "generic_webhook_secret": "sec789",
        },
    )
    assert res_post.status_code == 200
    assert "Settings Saved Successfully!" in res_post.text
    assert "tok123" in res_post.text
    assert "chat456" in res_post.text


def test_notify_test_api(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    # Telegram without token -> delivery failed
    res_fail = client.post("/api/notify/test?channel=telegram")
    assert res_fail.status_code == 200
    assert "Delivery Failed" in res_fail.text

    # Unsupported channel
    res_bad = client.post("/api/notify/test?channel=unsupported")
    assert res_bad.status_code == 200
    assert "Error:" in res_bad.text


def test_run_notify_and_finding_notify(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-notify-123")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # Digest notify (unconfigured)
    resp_digest = client.post(f"/runs/{run_id}/notify?channel=telegram")
    assert resp_digest.status_code == 200
    assert "Failed sending" in resp_digest.text or "Error" in resp_digest.text

    # Finding notify (unconfigured)
    resp_finding = client.post(f"/runs/{run_id}/findings/f-01/notify?channel=discord")
    assert resp_finding.status_code == 200
    assert "Delivery to Discord failed" in resp_finding.text or "Error" in resp_finding.text


def test_export_firewall_actions(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-fw-123")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # nftables
    resp_nft = client.get(f"/runs/{run_id}/actions/nftables")
    assert resp_nft.status_code == 200
    assert "LOGLENS GENERATED ADVISORY ACTIONS" in resp_nft.text

    # iptables
    resp_ipt = client.get(f"/runs/{run_id}/actions/iptables")
    assert resp_ipt.status_code == 200
    assert "iptables" in resp_ipt.text

    # cloudflare
    resp_cf = client.get(f"/runs/{run_id}/actions/cloudflare")
    assert resp_cf.status_code == 200
    assert "203.0.113.195" in resp_cf.text

    # invalid target
    resp_inv = client.get(f"/runs/{run_id}/actions/invalid")
    assert resp_inv.status_code == 400


def test_run_detail_with_errors_and_grid(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="laravel-2026-11-10.log",
        total_lines=10,
        parsed_events=10,
        unparsed_lines=0,
        total_clusters=2,
        findings_count=0,
    )
    err_cluster = Cluster(
        id="c-error-99",
        template="SQLSTATE[HY000] [<*>] Connection refused (Host: 127.0.0.1)",
        count=10,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        sample_messages=["SQLSTATE[HY000] [2002] Connection refused (Host: 127.0.0.1, Port: 3306)"],
    )
    report = Report(metadata=meta, findings=[], clusters=[err_cluster])
    run_id = storage.save_run(report, run_id="run-laravel-01")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    resp = client.get(f"/runs/{run_id}")
    assert resp.status_code == 200
    assert "findings-grid" in resp.text
    assert "Application & System Errors" in resp.text
    assert "Database / SQL Error" in resp.text
    assert "Explain Error with AI" in resp.text


def test_explain_cluster_on_demand_htmx(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="laravel.log",
        total_lines=5,
        parsed_events=5,
        unparsed_lines=0,
        total_clusters=1,
        findings_count=0,
    )
    cluster = Cluster(
        id="c-error-42",
        template="Fatal error: Call to undefined function foo()",
        count=5,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    report = Report(metadata=meta, findings=[], clusters=[cluster])
    run_id = storage.save_run(report, run_id="run-err-explain")
    storage.close()

    app = create_app(db_path=db_file, provider_name="mock")
    client = TestClient(app)

    # Post HTMX explain request for cluster
    response = client.post(f"/runs/{run_id}/clusters/c-error-42/explain")
    assert response.status_code == 200
    assert "AI Root Cause Diagnosis" in response.text
    assert "Confidence:" in response.text


def test_notify_cluster_error(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="app.log",
        total_lines=5,
        parsed_events=5,
        unparsed_lines=0,
        total_clusters=1,
        findings_count=0,
    )
    cluster = Cluster(
        id="c-net-77",
        template="Upstream timed out (<*>) while connecting to upstream",
        count=3,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    report = Report(metadata=meta, findings=[], clusters=[cluster])
    run_id = storage.save_run(report, run_id="run-net-err")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # Test notify on error cluster
    res_tg = client.post(f"/runs/{run_id}/clusters/c-net-77/notify?channel=telegram")
    assert res_tg.status_code == 200
    assert "Delivery to Telegram failed" in res_tg.text or "Error" in res_tg.text


