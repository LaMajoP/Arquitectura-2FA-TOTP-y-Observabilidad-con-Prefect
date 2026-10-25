"""TOTP enrollment use cases, separated from HTTP, storage, and cryptography."""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from totp import verify_totp

from .crypto import SecretDecryptionError, TOTPSecretCipher
from .database import DatabaseError, SupabaseTOTPRepository


PENDING_VERIFICATION = "PENDING_VERIFICATION"
ACTIVE = "ACTIVE"


class EnrollmentConflictError(RuntimeError):
    """The account already has a pending or active TOTP credential."""


class EnrollmentNotFoundError(RuntimeError):
    """There is no pending credential to verify for this authenticated account."""


class InvalidVerificationCodeError(RuntimeError):
    """The submitted first TOTP code did not validate."""


class VerificationRateLimitError(RuntimeError):
    """This account temporarily exhausted its shared verification allowance."""

    def __init__(self, locked_until: datetime) -> None:
        super().__init__("TOTP verification is temporarily locked.")
        self.locked_until = locked_until


class SecureStorageError(RuntimeError):
    """The encrypted credential cannot safely be used."""


@dataclass(frozen=True, slots=True)
class EnrollmentStart:
    secret_base32: str
    status: str


def generate_provisioning_secret() -> str:
    """Create a 160-bit RFC 4648 Base32 secret using the OS CSPRNG."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


class TOTPActivationService:
    """Starts and confirms enrollment without exposing decrypted data externally."""

    def __init__(
        self,
        repository: SupabaseTOTPRepository,
        cipher: TOTPSecretCipher,
        *,
        verify_max_attempts: int = 5,
        verify_lock_seconds: int = 900,
    ) -> None:
        self._repository = repository
        self._cipher = cipher
        self._verify_max_attempts = verify_max_attempts
        self._verify_lock_seconds = verify_lock_seconds

    def start_enrollment(self, user_id: UUID) -> EnrollmentStart:
        try:
            existing = self._repository.get_configuration(user_id)
        except DatabaseError as exc:
            raise SecureStorageError("TOTP storage is unavailable.") from exc

        if existing is not None:
            raise EnrollmentConflictError("A TOTP enrollment already exists for this account.")

        secret_base32 = generate_provisioning_secret()
        encrypted = self._cipher.encrypt(secret_base32, user_id)
        try:
            self._repository.ensure_user(user_id)
            self._repository.create_pending_configuration(user_id, encrypted)
        except DatabaseError as exc:
            # The plaintext exists only in this stack frame and is never logged.
            raise SecureStorageError("TOTP storage is unavailable.") from exc

        return EnrollmentStart(secret_base32=secret_base32, status=PENDING_VERIFICATION)

    def verify_initial_code(self, user_id: UUID, code: str) -> str:
        try:
            configuration = self._repository.get_configuration(user_id)
        except DatabaseError as exc:
            raise SecureStorageError("TOTP storage is unavailable.") from exc

        if configuration is None:
            raise EnrollmentNotFoundError("No TOTP enrollment exists for this account.")
        if configuration.status != PENDING_VERIFICATION:
            raise EnrollmentConflictError("TOTP enrollment is not awaiting verification.")

        # Reserve this code check before examining the code.  This is a single,
        # row-locked database operation, rather than per-process memory, so a
        # burst distributed across workers cannot bypass the allowance.
        try:
            permission = self._repository.consume_verification_attempt(
                user_id,
                self._verify_max_attempts,
                self._verify_lock_seconds,
            )
        except DatabaseError as exc:
            raise SecureStorageError("TOTP storage is unavailable.") from exc
        if not permission.allowed:
            if permission.locked_until is None:
                raise SecureStorageError("TOTP verification state is invalid.")
            raise VerificationRateLimitError(permission.locked_until)

        try:
            secret_base32 = self._cipher.decrypt(configuration.encrypted_secret, user_id)
        except SecretDecryptionError as exc:
            raise SecureStorageError("Protected TOTP data could not be used.") from exc

        # This deliberately calls the pre-existing TOTP implementation unchanged.
        try:
            verification = verify_totp(secret_base32, code)
        except (TypeError, ValueError) as exc:
            raise SecureStorageError("Protected TOTP data could not be used.") from exc
        if not verification.valid:
            raise InvalidVerificationCodeError("The TOTP code is invalid.")

        try:
            changed = self._repository.activate_pending_configuration(user_id)
        except DatabaseError as exc:
            raise SecureStorageError("TOTP storage is unavailable.") from exc

        if changed:
            return ACTIVE

        # A second valid request may have observed PENDING before the first
        # transaction committed.  It did not perform the transition itself and
        # must not receive a successful activation response.
        raise EnrollmentConflictError("TOTP enrollment state changed during verification.")
