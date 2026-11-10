"""Unit tests for LocalVault cryptographic credential storage."""

from __future__ import annotations

from pathlib import Path

from loglens.store.vault import LocalVault


def test_vault_ephemeral_roundtrip() -> None:
    vault = LocalVault(ephemeral=True)
    secret = "SuperSecretP@ssw0rd!123"
    token = vault.encrypt(secret)
    assert token != secret
    assert vault.decrypt(token) == secret


def test_vault_persistent_key(tmp_path: Path) -> None:
    key_file = tmp_path / "custom.key"
    vault1 = LocalVault(key_path=key_file)
    assert key_file.exists()

    token = vault1.encrypt("MyPrivateKeyData")
    assert token

    # Instantiate new vault pointing to same key file
    vault2 = LocalVault(key_path=key_file)
    decrypted = vault2.decrypt(token)
    assert decrypted == "MyPrivateKeyData"


def test_vault_empty_and_invalid() -> None:
    vault = LocalVault(ephemeral=True)
    assert vault.encrypt("") == ""
    assert vault.decrypt("") == ""
    # Corrupt or invalid token
    assert vault.decrypt("invalid-token-string") == ""
