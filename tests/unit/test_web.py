"""Unit and integration tests for the LogLens Web UI (FastAPI + HTMX)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
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
    assert "1 findings" in response.text


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
    assert "Forensic assessment" in response.text
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
    assert "New analysis" in response.text
    assert "File upload" in response.text


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

    log_snippet = "Nov 10 12:00:01 server sshd[1024]: Accepted publickey for user admin from 198.51.100.22 port 51234 ssh2\n"

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


def test_analyze_submit_panel_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    class MockResponse:
        status_code = 200
        text = "Nov 10 12:00:01 server sshd[1024]: Failed password for root from 192.168.1.50 port 22 ssh2\n"

    orig_get = httpx.Client.get

    def mock_get(self: Any, url: Any, *args: Any, **kwargs: Any) -> Any:
        if "pelican.example.com" in str(url):
            return MockResponse()
        return orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    response = client.post(
        "/analyze",
        data={
            "panel_url": "https://pelican.example.com",
            "panel_api_key": "ptlc_testkey123",
            "panel_server_id": "srv-99",
            "panel_file_path": "logs/latest.log",
            "format": "auto",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    redirect_url = response.headers["location"]
    resp_run = client.get(redirect_url)
    assert resp_run.status_code == 200
    assert "pelican://srv-99/logs/latest.log" in resp_run.text


def test_analyze_submit_panel_api_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    class MockErrorResponse:
        status_code = 403
        text = "Forbidden"

    orig_get = httpx.Client.get

    def mock_get_error(self: Any, url: Any, *args: Any, **kwargs: Any) -> Any:
        if "pelican.example.com" in str(url):
            return MockErrorResponse()
        return orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", mock_get_error)

    response = client.post(
        "/analyze",
        data={
            "panel_url": "https://pelican.example.com",
            "panel_api_key": "ptlc_badkey",
            "panel_server_id": "srv-99",
            "format": "auto",
        },
    )
    assert response.status_code == 400
    assert "Panel API returned HTTP 403" in response.text


def test_settings_page_and_save(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    # GET /settings
    res_get = client.get("/settings")
    assert res_get.status_code == 200
    assert "Alert settings" in res_get.text

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
    assert "Settings saved successfully" in res_post.text
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
    assert "Application errors" in resp.text
    assert "Database / SQL Error" in resp.text
    assert "Explain error" in resp.text


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


def test_delete_run_and_clear_all_runs_endpoints(tmp_path: Path) -> None:
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
    rep1 = Report(metadata=meta, findings=[], clusters=[])
    rep2 = Report(metadata=meta, findings=[], clusters=[])
    run1 = storage.save_run(rep1, run_id="run-web-del-1")
    run2 = storage.save_run(rep2, run_id="run-web-del-2")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # 1. Delete single run via standard POST
    res_del = client.post(f"/runs/{run1}/delete", follow_redirects=False)
    assert res_del.status_code == 303
    assert res_del.headers["location"] == "/"

    # Verify run1 gone, run2 exists
    res_get1 = client.get(f"/runs/{run1}")
    assert res_get1.status_code == 404
    res_get2 = client.get(f"/runs/{run2}")
    assert res_get2.status_code == 200

    # 2. Delete with HTMX header
    res_htmx = client.post(f"/runs/{run2}/delete", headers={"HX-Request": "true"})
    assert res_htmx.status_code == 200
    assert res_htmx.headers.get("HX-Redirect") == "/"

    # Re-add runs to test clear all
    storage = StorageManager(db_file)
    storage.save_run(rep1, run_id="run-web-del-3")
    storage.save_run(rep2, run_id="run-web-del-4")
    storage.close()

    # 3. Clear all runs via standard POST
    res_clear = client.post("/api/runs/clear", follow_redirects=False)
    assert res_clear.status_code == 303
    assert res_clear.headers["location"] == "/"

    # 4. Clear all runs via HTMX
    res_clear_htmx = client.post("/api/runs/clear", headers={"HX-Request": "true"})
    assert res_clear_htmx.status_code == 200
    assert res_clear_htmx.headers.get("HX-Redirect") == "/"

    # Verify table empty
    res_dash = client.get("/")
    assert res_dash.status_code == 200
    assert "No triage runs recorded yet" in res_dash.text


def test_live_monitoring_endpoints(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    dummy_log = tmp_path / "srv_auth.log"
    dummy_log.write_text("Nov 10 10:00:00 srv sshd[1]: Test line\n", encoding="utf-8")

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # 1. GET /live page
    res_live = client.get("/live")
    assert res_live.status_code == 200
    assert "Live server monitor" in res_live.text
    assert "Remote server forwarding" in res_live.text

    # 2. POST /live/start missing file fails with 404
    res_fail = client.post("/live/start", data={"log_path": str(tmp_path / "none.log")})
    assert res_fail.status_code == 404

    # 3. POST /live/start real file succeeds
    res_start = client.post(
        "/live/start", data={"log_path": str(dummy_log), "interval": 1.0}, follow_redirects=False
    )
    assert res_start.status_code == 303
    assert res_start.headers["location"] == "/live"

    # 4. Check /api/live/feed
    res_feed = client.get("/api/live/feed")
    assert res_feed.status_code == 200

    # 5. POST /live/stop
    res_page = client.get("/live")
    assert res_page.status_code == 200
    # Stop watcher
    res_stop = client.post("/live/stop", data={"session_id": "watch-dummy"}, follow_redirects=False)
    assert res_stop.status_code == 303


def test_remote_stream_ingest_and_auto_notify(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    # Enable auto notify with high threshold and discord webhook
    storage.set_setting("auto_notify_enabled", "true")
    storage.set_setting("auto_notify_min_severity", "high")
    storage.set_setting("discord_webhook_url", "https://discord.com/api/webhooks/test")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # 1. Stream attack log (triggers SSH brute force)
    attack_payload = (
        "Nov 10 12:00:01 srv sshd[100]: Failed password for invalid user root from 198.51.100.42 port 50001 ssh2\n"
        "Nov 10 12:00:02 srv sshd[101]: Failed password for invalid user root from 198.51.100.42 port 50002 ssh2\n"
        "Nov 10 12:00:03 srv sshd[102]: Failed password for invalid user root from 198.51.100.42 port 50003 ssh2\n"
        "Nov 10 12:00:04 srv sshd[103]: Failed password for invalid user root from 198.51.100.42 port 50004 ssh2\n"
        "Nov 10 12:00:05 srv sshd[104]: Failed password for invalid user root from 198.51.100.42 port 50005 ssh2\n"
        "Nov 10 12:00:06 srv sshd[105]: Failed password for invalid user root from 198.51.100.42 port 50006 ssh2\n"
    )

    res_stream = client.post(
        "/api/ingest/stream",
        content=attack_payload,
        headers={"X-Log-Source": "vps-pterodactyl.log"},
    )
    assert res_stream.status_code == 200
    data = res_stream.json()
    assert data["status"] == "success"
    assert data["parsed_events"] == 6
    assert data["findings_count"] >= 1
    assert data["run_id"].startswith("run-")

    # 2. Empty payload fails
    res_empty = client.post("/api/ingest/stream", content="")
    assert res_empty.status_code == 400


def test_settings_auto_notify_anti_spam(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    # Save anti-spam and auto-notify options
    res = client.post(
        "/settings",
        data={
            "auto_notify_enabled": "true",
            "auto_notify_min_severity": "high",
            "auto_notify_telegram": "true",
            "auto_notify_discord": "true",
            "telegram_bot_token": "tok123",
            "telegram_chat_id": "chat456",
            "discord_webhook_url": "https://discord.com/webhook",
        },
    )
    assert res.status_code == 200
    assert "Settings saved successfully" in res.text

    storage = StorageManager(db_file)
    assert storage.get_setting("auto_notify_enabled") == "true"
    assert storage.get_setting("auto_notify_min_severity") == "high"
    assert storage.get_setting("auto_notify_telegram") == "true"
    assert storage.get_setting("auto_notify_discord") == "true"
    storage.close()


def test_live_ssh_start_endpoint(tmp_path: Path) -> None:
    from unittest.mock import MagicMock, patch

    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    # 1. Missing host fails with 400
    res_bad = client.post("/live/ssh/start", data={"host": "", "username": "root"})
    assert res_bad.status_code == 400

    # 2. Mock paramiko client to simulate remote stream
    mock_client = MagicMock()
    mock_channel = MagicMock()
    mock_channel.recv.return_value = b""  # Clean EOF
    mock_channel.exit_status_ready.return_value = True
    mock_channel.recv_exit_status.return_value = 0
    mock_stdout = MagicMock()
    mock_stdout.channel = mock_channel
    mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

    with patch("paramiko.SSHClient", return_value=mock_client):
        res = client.post(
            "/live/ssh/start",
            data={
                "host": "222.167.207.101",
                "port": 22,
                "username": "root",
                "password": "secretpassword",
                "preset": "pelican-app",
            },
            follow_redirects=False,
        )
        assert res.status_code == 303
        assert res.headers["location"] == "/live"

    # Verify live page reflects watcher session
    res_live = client.get("/live")
    assert res_live.status_code == 200
    assert "222.167.207.101" in res_live.text


def test_live_ssh_test_endpoint(tmp_path: Path) -> None:
    from unittest.mock import MagicMock, patch

    db_file = tmp_path / "test.db"
    app = create_app(db_path=db_file)
    client = TestClient(app)

    # 1. Missing host returns warning snippet
    res_bad = client.post("/api/live/ssh/test", data={"host": "", "username": "root"})
    assert res_bad.status_code == 200
    assert "Host IP is required" in res_bad.text

    # 2. Mock paramiko client for successful diagnosis
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = (
        b"---OS---\nLinux mpanel 5.15\n---DOCKER---\n/usr/bin/docker\n"
        b"---PELICAN---\n/root/pelican-panel\n---OLS---\n/usr/local/lsws\n"
    )
    mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

    with patch("paramiko.SSHClient", return_value=mock_client):
        res = client.post(
            "/api/live/ssh/test",
            data={
                "host": "222.167.207.101",
                "port": 22,
                "username": "root",
                "password": "secretpassword",
            },
        )
        assert res.status_code == 200
        assert "Connected to root@222.167.207.101" in res.text
        assert "Pelican directory" in res.text


def test_format_ist_filter() -> None:
    from loglens.web.app import format_ist

    # 1. UTC datetime to IST (+5:30)
    dt_utc = datetime(2026, 11, 10, 9, 0, 0, tzinfo=UTC)
    formatted = format_ist(dt_utc)
    assert formatted == "2026-11-10 14:30:00 IST"

    # 2. Naive datetime assumes UTC
    dt_naive = datetime(2026, 11, 10, 9, 0, 0)
    assert format_ist(dt_naive) == "2026-11-10 14:30:00 IST"

    # 3. ISO string format
    iso_str = "2026-11-10T09:00:00Z"
    assert format_ist(iso_str) == "2026-11-10 14:30:00 IST"

    # 4. Fallback for non-date string
    assert format_ist("not-a-date") == "not-a-date"
    assert format_ist(None) == ""


def test_finding_title_preserves_rule_id_after_explain(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)

    cluster = Cluster(
        id="c-01",
        template="Accepted password for root from <*>",
        count=1,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("222.167.207.101", 1)]},
    )
    finding = Finding(
        id="finding-ssh-root-login-003",
        cluster_ids=["c-01"],
        rule_ids=["ssh-root-login-003"],
        rule_severity="low",
        llm=None,
    )
    metadata = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source="vps-stream",
        total_lines=10,
        parsed_events=10,
        unparsed_lines=0,
        total_clusters=1,
        findings_count=1,
    )
    report = Report(metadata=metadata, findings=[finding], clusters=[cluster])
    run_id = storage.save_run(report, run_id="run-reanalyze-test")
    storage.close()

    app = create_app(db_path=db_file, provider_name="mock")
    client = TestClient(app)

    # Post HTMX explain request
    response = client.post(f"/runs/{run_id}/findings/finding-ssh-root-login-003/explain")
    assert response.status_code == 200

    # Ensure title retains concrete rule ID and does NOT change to generic Security Anomaly
    assert "ssh-root-login-003" in response.text
    # Ensure form targets the outer card to avoid nesting card inside assessment block
    assert 'hx-target="#finding-finding-ssh-root-login-003-card"' in response.text
    assert 'hx-swap="outerHTML"' in response.text


def test_ist_rendered_in_index_and_run_detail(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)
    report = create_sample_report()
    run_id = storage.save_run(report, run_id="run-ist-test")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    # Index page should render IST in history table
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "IST" in res_index.text

    # Run detail page should render IST in header and clusters table
    res_run = client.get(f"/runs/{run_id}")
    assert res_run.status_code == 200
    assert "IST" in res_run.text


def test_run_detail_security_events_and_noise_separation(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    storage = StorageManager(db_file)

    now = datetime.now(UTC)
    c_sec = Cluster(
        id="c-sec-01",
        template="Connection reset by invalid user <*> port <*> [preauth]",
        count=1,
        first_seen=now,
        last_seen=now,
        sample_messages=["Connection reset by invalid user admin 203.0.113.1 port 44212 [preauth]"],
    )
    c_benign = Cluster(
        id="c-cron-01",
        template="CRON[<*>]: (root) CMD (<*>)",
        count=10,
        first_seen=now,
        last_seen=now,
        sample_messages=["CRON[100]: (root) CMD (/usr/bin/backup.sh)"],
    )
    c_err = Cluster(
        id="c-err-01",
        template="SQLSTATE[HY000] Connection refused to database",
        count=2,
        first_seen=now,
        last_seen=now,
        sample_messages=["SQLSTATE[HY000] Connection refused to database"],
    )

    f_sec = Finding(
        id="finding-ssh-invalid-user",
        cluster_ids=["c-sec-01"],
        rule_ids=["ssh-invalid-user"],
        rule_severity="low",
        llm=None,  # No LLM -> should be pure rule-based
    )
    f_noise = Finding(
        id="finding-benign-cron-session",
        cluster_ids=["c-cron-01"],
        rule_ids=["benign-cron-session"],
        rule_severity="info",
        llm=None,
    )

    meta = ReportMetadata(
        generated_at=now,
        log_source="server-auth.log",
        total_lines=50,
        parsed_events=48,
        unparsed_lines=2,
        total_clusters=3,
        findings_count=2,
    )
    report = Report(
        metadata=meta,
        findings=[f_sec, f_noise],
        clusters=[c_sec, c_benign, c_err],
    )
    run_id = storage.save_run(report, run_id="run-separation-test")
    storage.close()

    app = create_app(db_path=db_file)
    client = TestClient(app)

    res = client.get(f"/runs/{run_id}")
    assert res.status_code == 200

    # 1. Separated sections
    assert "Security events" in res.text
    assert "Application errors" in res.text
    assert "Noise & benign activity" in res.text

    # 2. Rule-based display with NO confidence percentage when no LLM triage exists
    assert "Rule-based" in res.text
    # Finding card without LLM should NOT have Confidence: XX%
    assert "Confidence:" not in res.text

    # 3. Fallback remediation text is rule-specific
    assert "PasswordAuthentication no" in res.text or "firewall" in res.text

    # 4. Deduped sample excerpt: since c_err sample_message == template, "Sample excerpt" should NOT appear for it
    assert "Sample excerpt" not in res.text




