"""Unit tests for VPS profiles storage and encrypted credential persistence."""

from __future__ import annotations

from pathlib import Path

from loglens.store.db import StorageManager


def test_storage_vps_profile_crud_in_memory() -> None:
    storage = StorageManager(":memory:")

    # 1. Save profile
    pid = storage.save_vps_profile(
        name="Production Host",
        host="222.167.207.101",
        port=22,
        username="root",
        password="MySecretPassword!",
        key_content="-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
        default_preset="smart-auto",
    )
    assert pid.startswith("vps-")

    # 2. List profiles - secrets must not be exposed in plaintext or token
    profiles = storage.list_vps_profiles()
    assert len(profiles) == 1
    p = profiles[0]
    assert p["id"] == pid
    assert p["name"] == "Production Host"
    assert p["host"] == "222.167.207.101"
    assert p["username"] == "root"
    assert p["has_password"] is True
    assert p["has_key"] is True
    assert "password" not in p
    assert "key_content" not in p

    # 3. Get profile without decrypt
    masked = storage.get_vps_profile(pid, decrypt=False)
    assert masked is not None
    assert "password" not in masked
    assert masked["has_password"] is True

    # 4. Get profile with decrypt
    decrypted = storage.get_vps_profile(pid, decrypt=True)
    assert decrypted is not None
    assert decrypted["password"] == "MySecretPassword!"
    assert "BEGIN RSA PRIVATE KEY" in decrypted["key_content"]

    # 5. Update profile without overwriting password
    updated_id = storage.save_vps_profile(
        name="Production VPS Renamed",
        host="222.167.207.101",
        port=2222,
        username="root",
        password=None,  # keep existing
        profile_id=pid,
    )
    assert updated_id == pid

    updated_prof = storage.get_vps_profile(pid, decrypt=True)
    assert updated_prof is not None
    assert updated_prof["name"] == "Production VPS Renamed"
    assert updated_prof["port"] == 2222
    assert updated_prof["password"] == "MySecretPassword!"

    # 6. Delete profile
    deleted = storage.delete_vps_profile(pid)
    assert deleted is True
    assert storage.get_vps_profile(pid) is None
    assert len(storage.list_vps_profiles()) == 0


def test_storage_vps_profile_persists_across_instances(tmp_path: Path) -> None:
    db_file = tmp_path / "test_vps.db"
    storage1 = StorageManager(db_file)
    pid = storage1.save_vps_profile(
        name="Persistent Server",
        host="1.2.3.4",
        username="admin",
        password="PassWordAcrossRestarts!",
    )

    # Re-instantiate storage pointing to the same file
    storage2 = StorageManager(db_file)
    prof = storage2.get_vps_profile(pid, decrypt=True)
    assert prof is not None
    assert prof["name"] == "Persistent Server"
    assert prof["password"] == "PassWordAcrossRestarts!"
