"""Registration, password login, and TOTP Step-Up application use cases."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable
from uuid import UUID, uuid4

from .database import DatabaseError, DuplicateEmailError, SupabaseTOTPRepository
from .mfa_strategies import (
    MFAValidationError,
    MFAValidationResult,
    MFAValidationStorageError,
    MFAValidationStrategy,
)
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


class MFAReplayDetectedError(MFAAuthenticationError):
    """A TOTP counter already consumed by this account was submitted again."""


class PreAuthTokenReusedError(MFAAuthenticationError):
    """A previously consumed pre-auth JTI was submitted again."""


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
        reservation_id = self._reserve_attempt(subject_key)

        try:
            account = self._repository.get_password_user_by_email(email)
        except DatabaseError as exc:
            # A backend read failure did not verify an invalid credential, so
            # release only this request's reservation without touching peers.
            self._complete_attempt(reservation_id, succeeded=True)
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc

        if account is None:
            self._passwords.verify_dummy(password)
            self._complete_attempt(reservation_id, succeeded=False)
            raise InvalidCredentialsError("Credentials are invalid.")
        if not self._passwords.verify_password(account.password_hash, password):
            self._complete_attempt(reservation_id, succeeded=False)
            raise InvalidCredentialsError("Credentials are invalid.")

        self._complete_attempt(reservation_id, succeeded=True)
        try:
            configuration = self._repository.get_configuration(account.user_id)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc

        if configuration is not None and configuration.status not in {PENDING_VERIFICATION, ACTIVE}:
            raise AuthenticationStorageError("TOTP configuration is invalid.")
        return LoginResult(user_id=account.user_id, requires_mfa=bool(configuration and configuration.status == ACTIVE))

    def _reserve_attempt(self, subject_key: str) -> UUID:
        reservation_id = uuid4()
        try:
            reservation = self._repository.reserve_auth_attempt(
                LOGIN_RATE_LIMIT_SCOPE,
                subject_key,
                reservation_id,
                self._max_attempts,
                self._lock_seconds,
            )
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        if not reservation.allowed:
            if reservation.locked_until is None:
                raise AuthenticationStorageError("Authentication state is invalid.")
            raise AuthenticationRateLimitError(reservation.locked_until)
        if reservation.reservation_id is None:
            raise AuthenticationStorageError("Authentication state is invalid.")
        return reservation.reservation_id

    def _complete_attempt(self, reservation_id: UUID, *, succeeded: bool) -> None:
        """Finalize only this request's receipt; concurrent attempts persist."""
        try:
            self._repository.complete_auth_attempt(reservation_id, succeeded=succeeded)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc


class StepUpService:
    """Apply one MFA strategy, then atomically consume factor and pre-auth JTI."""

    def __init__(
        self,
        repository: SupabaseTOTPRepository,
        strategies: Iterable[MFAValidationStrategy],
        *,
        rate_limit_key: bytes,
        max_attempts: int,
        lock_seconds: int,
    ) -> None:
        self._repository = repository
        self._strategies = {strategy.method: strategy for strategy in strategies}
        if len(self._strategies) < 1:
            raise ValueError("At least one MFA validation strategy is required.")
        self._rate_limit_key = rate_limit_key
        self._max_attempts = max_attempts
        self._lock_seconds = lock_seconds

    def verify(
        self,
        user_id: UUID,
        *,
        method: str,
        credential: str,
        pre_auth_token_id: UUID,
        pre_auth_expires_at: datetime,
    ) -> None:
        subject_key = derive_rate_limit_subject(
            self._rate_limit_key, MFA_RATE_LIMIT_SCOPE, str(user_id)
        )
        reservation_id = self._reserve_attempt(subject_key)

        try:
            strategy = self._strategies[method]
            validation = strategy.validate(user_id, credential)
        except KeyError as exc:
            self._complete_attempt(reservation_id, succeeded=False)
            raise MFAAuthenticationError("MFA authentication cannot be completed.")
        except MFAValidationError as exc:
            self._complete_attempt(reservation_id, succeeded=False)
            raise MFAAuthenticationError("MFA authentication cannot be completed.") from exc
        except MFAValidationStorageError as exc:
            # A backend/storage error is not an invalid credential and must not
            # consume the user's shared MFA allowance.
            self._complete_attempt(reservation_id, succeeded=True)
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc

        self._confirm_factor_and_token(
            user_id,
            pre_auth_token_id,
            pre_auth_expires_at,
            validation,
            reservation_id,
        )

    def _confirm_factor_and_token(
        self,
        user_id: UUID,
        pre_auth_token_id: UUID,
        pre_auth_expires_at: datetime,
        validation: MFAValidationResult,
        reservation_id: UUID,
    ) -> None:
        try:
            confirmed = self._repository.confirm_mfa_step_up(
                user_id=user_id,
                pre_auth_token_id=pre_auth_token_id,
                pre_auth_expires_at=pre_auth_expires_at,
                method=validation.method,
                totp_counter=validation.totp_counter,
                backup_code_id=validation.backup_code_id,
            )
        except DatabaseError as exc:
            self._complete_attempt(reservation_id, succeeded=True)
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        if not confirmed:
            self._complete_attempt(reservation_id, succeeded=False)
            self._raise_confirmation_failure(user_id, pre_auth_token_id, validation)

        self._complete_attempt(reservation_id, succeeded=True)

    def _raise_confirmation_failure(
        self,
        user_id: UUID,
        pre_auth_token_id: UUID,
        validation: MFAValidationResult,
    ) -> None:
        """Classify a failed atomic confirmation only for internal telemetry."""
        try:
            if self._repository.is_pre_auth_token_consumed(user_id, pre_auth_token_id):
                raise PreAuthTokenReusedError("MFA authentication cannot be completed.")
            if (
                validation.totp_counter is not None
                and self._repository.is_totp_counter_consumed(user_id, validation.totp_counter)
            ):
                raise MFAReplayDetectedError("MFA authentication cannot be completed.")
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        raise MFAAuthenticationError("MFA authentication cannot be completed.")

    def _reserve_attempt(self, subject_key: str) -> UUID:
        reservation_id = uuid4()
        try:
            reservation = self._repository.reserve_auth_attempt(
                MFA_RATE_LIMIT_SCOPE,
                subject_key,
                reservation_id,
                self._max_attempts,
                self._lock_seconds,
            )
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
        if not reservation.allowed:
            if reservation.locked_until is None:
                raise AuthenticationStorageError("Authentication state is invalid.")
            raise AuthenticationRateLimitError(reservation.locked_until)
        if reservation.reservation_id is None:
            raise AuthenticationStorageError("Authentication state is invalid.")
        return reservation.reservation_id

    def _complete_attempt(self, reservation_id: UUID, *, succeeded: bool) -> None:
        """Finalize only this request's receipt; concurrent attempts persist."""
        try:
            self._repository.complete_auth_attempt(reservation_id, succeeded=succeeded)
        except DatabaseError as exc:
            raise AuthenticationStorageError("Authentication storage is unavailable.") from exc
