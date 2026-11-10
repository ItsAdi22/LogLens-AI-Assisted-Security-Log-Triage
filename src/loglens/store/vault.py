"""Local cryptographic vault for securely storing server credentials at rest."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

DEFAULT_VAULT_KEY_PATH = Path.home() / ".config" / "loglens" / ".vault.key"


class LocalVault:
    """Provides local AES-based encryption and decryption using a persistent machine key."""

    def __init__(self, key_path: Path | str | None = None, ephemeral: bool = False) -> None:
        self.ephemeral = ephemeral
        if ephemeral:
            self.key_path = None
            self._fernet = Fernet(Fernet.generate_key())
        else:
            if key_path is None:
                key_path = DEFAULT_VAULT_KEY_PATH
            self.key_path = Path(key_path)
            self._fernet = self._load_or_create_key(self.key_path)

    @staticmethod
    def _load_or_create_key(path: Path) -> Fernet:
        """Load the persistent encryption key from disk or generate a new cryptographically strong key."""
        if path.exists():
            try:
                raw_key = path.read_bytes().strip()
                return Fernet(raw_key)
            except Exception as e:
                logger.warning(
                    "Failed to read existing vault key at %s (%s). Re-generating key.", path, e
                )

        path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        try:
            # Create file with restricted read/write permissions for current user only
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(str(path), flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
        except Exception:
            # Fallback for systems with non-POSIX permission handlers
            path.write_bytes(key)

        return Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string into a base64 ciphertext token."""
        if not plaintext:
            return ""
        encrypted_bytes = self._fernet.encrypt(plaintext.encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base64 ciphertext token into the original plaintext string."""
        if not ciphertext:
            return ""
        try:
            decrypted_bytes = self._fernet.decrypt(ciphertext.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken:
            logger.error("Failed to decrypt vault token: invalid key or corrupted ciphertext")
            return ""
        except Exception as exc:
            logger.error("Unexpected error during vault decryption: %s", exc)
            return ""
