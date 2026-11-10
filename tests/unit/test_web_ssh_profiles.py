"""Unit tests for web endpoints handling saved VPS profiles and SSH stream launch."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from loglens.store.db import StorageManager
from loglens.web.app import create_app


def test_web_ssh_profiles_api() -> None:
    storage = StorageManager(":memory:")
    storage.save_vps_profile(
        name="Test VPS",
        host="192.168.1.50",
        port=22,
        username="root",
        password="TestSecretPassword",
    )

    app = create_app(db_path=":memory:")
    # Inject storage with existing profile into app
    client = TestClient(app)

    # List profiles endpoint
    resp = client.get("/api/live/ssh/profiles")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_web_ssh_start_with_remember_server() -> None:
    app = create_app(db_path=":memory:")
    client = TestClient(app)

    with patch("loglens.watch.LiveWatchManager.start_ssh_watch") as mock_start:
        mock_start.return_value = "watch-ssh-test"

        resp = client.post(
            "/live/ssh/start",
            data={
                "host": "10.0.0.1",
                "port": 22,
                "username": "root",
                "password": "SecretVaultPassword!",
                "preset": "smart-auto",
                "remember_server": "true",
                "profile_name": "My Prod Server",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        mock_start.assert_called_once()
        assert mock_start.call_args[1]["preset"] == "smart-auto"
        assert mock_start.call_args[1]["host"] == "10.0.0.1"
        assert mock_start.call_args[1]["password"] == "SecretVaultPassword!"


def test_web_ssh_profile_delete_endpoint() -> None:
    app = create_app(db_path=":memory:")
    client = TestClient(app)

    # First start with remember server to persist one
    with patch("loglens.watch.LiveWatchManager.start_ssh_watch"):
        client.post(
            "/live/ssh/start",
            data={
                "host": "10.0.0.2",
                "port": 22,
                "username": "root",
                "password": "TestPassword",
                "preset": "smart-auto",
                "remember_server": "true",
                "profile_name": "To Delete Server",
            },
        )

    # List profiles to get ID
    list_resp = client.get("/api/live/ssh/profiles")
    profiles = list_resp.json()
    assert len(profiles) >= 1
    prof_id = profiles[0]["id"]

    # Delete profile
    del_resp = client.delete(f"/api/live/ssh/profiles/{prof_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "ok"

    # Deleting again returns 404
    del_again = client.delete(f"/api/live/ssh/profiles/{prof_id}")
    assert del_again.status_code == 404
