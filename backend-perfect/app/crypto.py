"""AES-256-GCM protection for TOTP provisioning secrets."""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretDecryptionError(RuntimeError):
    """Raised without exposing whether a key, nonce, ciphertext, or tag failed."""


@dataclass(frozen=True, slots=True)
class EncryptedSecret:
    """Bytes encoded for database transport; none of these fields is plaintext."""

    ciphertext_b64: str
    nonce_b64: str
    tag_b64: str
    key_version: str


class TOTPSecretCipher:
    """Encrypts each secret with a fresh 96-bit nonce and authenticated AAD."""

    _NONCE_BYTES = 12
    _TAG_BYTES = 16

    def __init__(self, key: bytes, key_version: str) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires exactly 32 key bytes.")
        self._aesgcm = AESGCM(key)
        self._key_version = key_version

    @staticmethod
    def _aad(user_id: UUID) -> bytes:
        # Bind a credential cryptographically to its account and its intended use.
        return f"totp-secret:v1:{user_id}".encode("ascii")

    @staticmethod
    def _to_b64(value: bytes) -> str:
        # Base64 only represents encrypted binary data for a text database column.
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _from_b64(value: str) -> bytes:
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except (AttributeError, UnicodeEncodeError, binascii.Error) as exc:
            raise SecretDecryptionError("Protected TOTP data is invalid.") from exc

    def encrypt(self, secret_base32: str, user_id: UUID) -> EncryptedSecret:
        nonce = secrets.token_bytes(self._NONCE_BYTES)
        encrypted_with_tag = self._aesgcm.encrypt(
            nonce,
            secret_base32.encode("ascii"),
            self._aad(user_id),
        )
        ciphertext = encrypted_with_tag[: -self._TAG_BYTES]
        tag = encrypted_with_tag[-self._TAG_BYTES :]
        return EncryptedSecret(
            ciphertext_b64=self._to_b64(ciphertext),
            nonce_b64=self._to_b64(nonce),
            tag_b64=self._to_b64(tag),
            key_version=self._key_version,
        )

    def decrypt(self, encrypted: EncryptedSecret, user_id: UUID) -> str:
        try:
            if encrypted.key_version != self._key_version:
                raise SecretDecryptionError("Protected TOTP data uses an unavailable key version.")
            nonce = self._from_b64(encrypted.nonce_b64)
            ciphertext = self._from_b64(encrypted.ciphertext_b64)
            tag = self._from_b64(encrypted.tag_b64)
            if len(nonce) != self._NONCE_BYTES or len(tag) != self._TAG_BYTES or not ciphertext:
                raise SecretDecryptionError("Protected TOTP data is invalid.")
            plaintext = self._aesgcm.decrypt(
                nonce,
                ciphertext + tag,
                self._aad(user_id),
            )
            return plaintext.decode("ascii")
        except (InvalidTag, UnicodeDecodeError, ValueError) as exc:
            raise SecretDecryptionError("Protected TOTP data could not be authenticated.") from exc
