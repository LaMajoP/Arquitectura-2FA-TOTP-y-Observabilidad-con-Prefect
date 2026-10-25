"""Registration, password login, and TOTP Step-Up application use cases."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from totp import verify_totp

from .crypto import SecretDecryptionError, TOTPSecretCipher
from .database import DatabaseError, DuplicateEmailError, SupabaseTOTPRepository
from .passwords import PasswordService
from .totp_service import ACTIVE, PENDING_VERIFICATION


LOGIN_RATE_LIMIT_SCOPE = "LOGIN"
MFA_RATE_LIMIT_SCOPE = "MFA"


class RegistrationConflictError(RuntimeError):
    """The normalized email address is already registered."""


class InvalidCredentialsError(RuntimeError):
    """The supplied email/password pair cannot authenticate."""


class MFAAuthenticationError(RuntimeError):
    """The Step-Up attempt cannot complete without exposing the reason."""


class AuthenticationRateLimitError(RuntimeError):
    """A shared login or Step-Up allowance is temporarily exhausted."""

    def __init__(self, locked_until: datetime) -> None:
        super().__init__("Authentication is temporarily locked.")
        self.locked_until = locked_until


class AuthenticationStorageError(RuntimeError):
    """Authentication state is unavailable or cannot be safely used."""


@dataclass(frozen=True, slots=True)
class LoginResult:
    """The exact next auth step, determined only after password verification."""

    user_id: UUID
    requires_mfa: bool


def derive_rate_limit_subject(rate_limit_key: bytes, scope: str, value: str) -> str:
    """Create a non-reversible stable key for shared authentication limits."""
    message = f"auth-rate-limit:v1:{scope}:{value}".encode("utf-8")
    return hmac.new(rate_limit_key, message, hashlib.sha256).hexdigest()


class RegistrationService:
    def __init__(self, repository: SupabaseTOTPRepository, passwords: PasswordService) -> None:
        self._repository = repository
        self._passwords = passwords

    def register(self, email: str, password: str) -> UUID:
        # Argon2id creates its own random salt for every invocation. The
        # password only survives in this stack frame and is never logged.
        password_hash = self._passwords.hash_password(password)
        try:
            return self._repository.create_password_user(email, password_hash)
        except DuplicateEmailError as exc:
            raise RegistrationConflictError("Registration cannot be completed.") from exc
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc


class PasswordLoginService:
    def __init__(
        self,
        repository: SupabaseTOTPRepository,
        passwords: PasswordService,
        *,
        rate_limit_key: bytes,
        max_attempts: int,
        lock_seconds: int,
    ) -> None:
        self._repository = repository
        self._passwords = passwords
        self._rate_limit_key = rate_limit_key
        self._max_attempts = max_attempts
        self._lock_seconds = lock_seconds

    def login(self, email: str, password: str) -> LoginResult:
        subject_key = derive_rate_limit_subject(self._rate_limit_key, LOGIN_RATE_LIMIT_SCOPE, email)
        try:
            permission = self._repository.consume_auth_attempt(
                LOGIN_RATE_LIMIT_SCOPE,
                subject_key,
                self._max_attempts,
                self._lock_seconds,
            )
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        if not permission.allowed:
            if permission.locked_until is None:
                raise AuthenticationStorageError("Authentication state is invalid.")
            raise AuthenticationRateLimitError(permission.locked_until)

        try:
            account = self._repository.get_password_user_by_email(email)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc

        if account is None:
            self._passwords.verify_dummy(password)
            raise InvalidCredentialsError("Credentials are invalid.")
        if not self._passwords.verify_password(account.password_hash, password):
            raise InvalidCredentialsError("Credentials are invalid.")

        # Only a complete successful password check clears attempts. A failed
        # check remains reserved in Supabase across all backend instances.
        try:
            self._repository.clear_auth_attempts(LOGIN_RATE_LIMIT_SCOPE, subject_key)
            configuration = self._repository.get_configuration(account.user_id)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc

        if configuration is not None and configuration.status not in {PENDING_VERIFICATION, ACTIVE}:
            raise AuthenticationStorageError("TOTP configuration is invalid.")
        return LoginResult(user_id=account.user_id, requires_mfa=bool(configuration and configuration.status == ACTIVE))


class StepUpService:
    """Verify a TOTP code without exposing its decrypted provisioning secret."""

    def __init__(
        self,
        repository: SupabaseTOTPRepository,
        cipher: TOTPSecretCipher,
        *,
        rate_limit_key: bytes,
        max_attempts: int,
        lock_seconds: int,
    ) -> None:
        self._repository = repository
        self._cipher = cipher
        self._rate_limit_key = rate_limit_key
        self._max_attempts = max_attempts
        self._lock_seconds = lock_seconds

    def verify(self, user_id: UUID, code: str) -> None:
        try:
            configuration = self._repository.get_configuration(user_id)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        if configuration is None or configuration.status != ACTIVE:
            raise MFAAuthenticationError("MFA authentication cannot be completed.")

        subject_key = derive_rate_limit_subject(
            self._rate_limit_key, MFA_RATE_LIMIT_SCOPE, str(user_id)
        )
        try:
            permission = self._repository.consume_auth_attempt(
                MFA_RATE_LIMIT_SCOPE,
                subject_key,
                self._max_attempts,
                self._lock_seconds,
            )
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        if not permission.allowed:
            if permission.locked_until is None:
                raise AuthenticationStorageError("Authentication state is invalid.")
            raise AuthenticationRateLimitError(permission.locked_until)

        try:
            secret_base32 = self._cipher.decrypt(configuration.encrypted_secret, user_id)
            verification = verify_totp(secret_base32, code)
        except (SecretDecryptionError, TypeError, ValueError) as exc:
            raise AuthenticationStorageError("Protected TOTP data could not be used.") from exc

        if not verification.valid:
            # The reserved row deliberately remains as a failed Step-Up check.
            raise MFAAuthenticationError("MFA authentication cannot be completed.")

        try:
            self._repository.clear_auth_attempts(MFA_RATE_LIMIT_SCOPE, subject_key)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
