"""Argon2id password hashing kept separate from reversible TOTP encryption."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type


class PasswordService:
    """Hash and verify passwords using Argon2id with a fresh random salt."""

    def __init__(self) -> None:
        # 64 MiB, 3 iterations, and 4 lanes are deliberately explicit rather
        # than relying on package defaults which can change between releases.
        self._hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        # An unknown email still follows the Argon2 verification path. This
        # reduces observable timing differences between existing and absent
        # accounts without storing any user password.
        self._dummy_hash = self._hasher.hash("not-a-real-user-password")

    def hash_password(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False

    def verify_dummy(self, password: str) -> None:
        """Perform a deliberately ignored verification for an unknown email."""
        self.verify_password(self._dummy_hash, password)
