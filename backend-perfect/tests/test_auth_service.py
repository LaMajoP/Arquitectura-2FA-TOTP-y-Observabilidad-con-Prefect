from __future__ import annotations

from datetime import datetime, timezone
from unittest import TestCase
from uuid import uuid4

from app.auth import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_PRE_AUTH,
    AuthorizationError,
    TokenIssuer,
    authenticate_token,
)
from app.auth_api import LoginRequest, RegistrationRequest
from app.auth_service import (
    LOGIN_RATE_LIMIT_SCOPE,
    MFA_RATE_LIMIT_SCOPE,
    AuthenticationRateLimitError,
    InvalidCredentialsError,
    MFAAuthenticationError,
    PasswordLoginService,
    StepUpService,
)
from app.config import Settings
from app.crypto import EncryptedSecret
from app.database import (
    AuthAttemptReservation,
    StoredPasswordUser,
    StoredTOTPConfiguration,
    VerificationAttemptPermission,
)
from app.mfa_strategies import MFAValidationError, MFAValidationResult
from app.passwords import PasswordService
from app.totp_service import ACTIVE


def make_settings() -> Settings:
    return Settings(
        supabase_url="https://example.supabase.co",
        supabase_service_role_key="service-role-key",
        jwt_signing_key="x" * 32,
        jwt_algorithm="HS256",
        jwt_issuer="https://issuer.example.test",
        jwt_audience="totp-api",
        auth_rate_limit_key=b"y" * 32,
        totp_encryption_key=b"z" * 32,
        totp_encryption_key_version="v1",
        require_https=False,
        totp_verify_max_attempts=5,
        totp_verify_lock_seconds=900,
        login_max_attempts=5,
        login_lock_seconds=900,
        pre_auth_token_ttl_seconds=300,
        provisioning_token_ttl_seconds=900,
        access_token_ttl_seconds=3600,
        backup_code_recent_mfa_seconds=300,
    )


class StubPasswords:
    def __init__(self, accepted_password: str = "correct-password") -> None:
        self.accepted_password = accepted_password
        self.dummy_calls = 0

    def verify_password(self, password_hash: str, password: str) -> bool:
        return password_hash == "stored-hash" and password == self.accepted_password

    def verify_dummy(self, password: str) -> None:
        self.dummy_calls += 1


class StubRepository:
    def __init__(
        self,
        *,
        account: StoredPasswordUser | None = None,
        configuration: StoredTOTPConfiguration | None = None,
        permission: VerificationAttemptPermission | None = None,
    ) -> None:
        self.account = account
        self.configuration = configuration
        self.permission = permission or VerificationAttemptPermission(allowed=True, locked_until=None)
        self.reservation_calls: list[tuple[str, str, int, int]] = []
        self.completion_calls: list[tuple[object, bool]] = []
        self.mfa_confirmation_calls: list[dict[str, object]] = []
        self.mfa_confirmation_result = True

    def reserve_auth_attempt(
        self,
        scope: str,
        subject_key: str,
        reservation_id: object,
        max_attempts: int,
        lock_seconds: int,
    ) -> AuthAttemptReservation:
        self.reservation_calls.append((scope, subject_key, max_attempts, lock_seconds))
        if not self.permission.allowed:
            return AuthAttemptReservation(
                allowed=False,
                reservation_id=None,
                locked_until=self.permission.locked_until,
            )
        return AuthAttemptReservation(
            allowed=True,
            reservation_id=reservation_id,  # type: ignore[arg-type]
            locked_until=None,
        )

    def complete_auth_attempt(self, reservation_id: object, *, succeeded: bool) -> None:
        self.completion_calls.append((reservation_id, succeeded))

    def get_password_user_by_email(self, email: str) -> StoredPasswordUser | None:
        return self.account

    def get_configuration(self, user_id: object) -> StoredTOTPConfiguration | None:
        return self.configuration

    def confirm_mfa_step_up(self, **kwargs: object) -> bool:
        self.mfa_confirmation_calls.append(kwargs)
        return self.mfa_confirmation_result


class StubMFAStrategy:
    method = "totp"

    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid

    def validate(self, user_id: object, credential: str) -> MFAValidationResult:
        if not self.valid:
            raise MFAValidationError("MFA authentication cannot be completed.")
        return MFAValidationResult(method=self.method, totp_counter=1)


def active_configuration(user_id: object) -> StoredTOTPConfiguration:
    return StoredTOTPConfiguration(
        user_id=user_id,  # type: ignore[arg-type]
        status=ACTIVE,
        encrypted_secret=EncryptedSecret("ciphertext", "nonce", "tag", "v1"),
    )


class TokenPurposeTests(TestCase):
    def test_tokens_are_accepted_only_for_their_exact_purpose_and_mfa_state(self) -> None:
        settings = make_settings()
        user_id = uuid4()
        issuer = TokenIssuer(settings)

        pre_auth = issuer.issue_pre_auth_token(user_id)
        authenticated = authenticate_token(
            pre_auth.token,
            settings,
            expected_token_type=TOKEN_TYPE_PRE_AUTH,
            expected_mfa_verified=False,
        )
        self.assertEqual(authenticated.user_id, user_id)
        self.assertFalse(authenticated.mfa_verified)

        with self.assertRaises(AuthorizationError):
            authenticate_token(
                pre_auth.token,
                settings,
                expected_token_type=TOKEN_TYPE_ACCESS,
                expected_mfa_verified=True,
            )
        with self.assertRaises(AuthorizationError):
            authenticate_token(
                pre_auth.token + "tampered",
                settings,
                expected_token_type=TOKEN_TYPE_PRE_AUTH,
                expected_mfa_verified=False,
            )


class PasswordTests(TestCase):
    def test_argon2id_hash_never_equals_the_password_and_verifies_correctly(self) -> None:
        passwords = PasswordService()
        password = "correct horse battery staple"
        password_hash = passwords.hash_password(password)

        self.assertTrue(password_hash.startswith("$argon2id$"))
        self.assertNotEqual(password_hash, password)
        self.assertTrue(passwords.verify_password(password_hash, password))
        self.assertFalse(passwords.verify_password(password_hash, "incorrect"))

    def test_email_is_normalized_for_registration_and_login(self) -> None:
        registration = RegistrationRequest(email="Person@Example.COM", password="long-enough-password")
        login = LoginRequest(email="Person@Example.COM", password="x")
        self.assertEqual(registration.email, "person@example.com")
        self.assertEqual(login.email, "person@example.com")


class PasswordLoginServiceTests(TestCase):
    def test_active_totp_requires_step_up_after_successful_password_login(self) -> None:
        user_id = uuid4()
        repository = StubRepository(
            account=StoredPasswordUser(user_id=user_id, password_hash="stored-hash"),
            configuration=active_configuration(user_id),
        )
        service = PasswordLoginService(
            repository,  # type: ignore[arg-type]
            StubPasswords(),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        result = service.login("person@example.com", "correct-password")

        self.assertEqual(result.user_id, user_id)
        self.assertTrue(result.requires_mfa)
        self.assertEqual(repository.reservation_calls[0][0], LOGIN_RATE_LIMIT_SCOPE)
        self.assertEqual([succeeded for _, succeeded in repository.completion_calls], [True])

    def test_missing_user_uses_dummy_hash_and_has_generic_failure(self) -> None:
        passwords = StubPasswords()
        repository = StubRepository()
        service = PasswordLoginService(
            repository,  # type: ignore[arg-type]
            passwords,  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with self.assertRaises(InvalidCredentialsError):
            service.login("missing@example.com", "incorrect")

        self.assertEqual(passwords.dummy_calls, 1)
        self.assertEqual([succeeded for _, succeeded in repository.completion_calls], [False])

    def test_success_finalizes_only_its_own_reservation(self) -> None:
        user_id = uuid4()
        repository = StubRepository(
            account=StoredPasswordUser(user_id=user_id, password_hash="stored-hash"),
        )
        passwords = StubPasswords()
        service = PasswordLoginService(
            repository,  # type: ignore[arg-type]
            passwords,  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with self.assertRaises(InvalidCredentialsError):
            service.login("person@example.com", "incorrect")
        self.assertEqual([succeeded for _, succeeded in repository.completion_calls], [False])

        self.assertFalse(service.login("person@example.com", "correct-password").requires_mfa)
        # The successful request finalizes only its own reservation, so a
        # failure that raced with it remains represented in shared state.
        self.assertEqual([succeeded for _, succeeded in repository.completion_calls], [False, True])
        self.assertNotEqual(
            repository.completion_calls[0][0], repository.completion_calls[1][0]
        )

    def test_locked_login_does_not_read_or_verify_password(self) -> None:
        repository = StubRepository(
            permission=VerificationAttemptPermission(
                allowed=False,
                locked_until=datetime.now(timezone.utc),
            )
        )
        service = PasswordLoginService(
            repository,  # type: ignore[arg-type]
            StubPasswords(),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with self.assertRaises(AuthenticationRateLimitError):
            service.login("person@example.com", "incorrect")


class StepUpServiceTests(TestCase):
    def test_successful_step_up_finalizes_only_its_own_reservation(self) -> None:
        user_id = uuid4()
        repository = StubRepository(configuration=active_configuration(user_id))
        service = StepUpService(
            repository,  # type: ignore[arg-type]
            (StubMFAStrategy(),),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        service.verify(
            user_id,
            method="totp",
            credential="123456",
            pre_auth_token_id=uuid4(),
            pre_auth_expires_at=datetime.now(timezone.utc),
        )

        self.assertEqual(repository.reservation_calls[0][0], MFA_RATE_LIMIT_SCOPE)
        self.assertEqual([succeeded for _, succeeded in repository.completion_calls], [True])
        self.assertEqual(len(repository.mfa_confirmation_calls), 1)

    def test_invalid_step_up_code_records_a_shared_failure(self) -> None:
        user_id = uuid4()
        repository = StubRepository(configuration=active_configuration(user_id))
        service = StepUpService(
            repository,  # type: ignore[arg-type]
            (StubMFAStrategy(valid=False),),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with self.assertRaises(MFAAuthenticationError):
            service.verify(
                user_id,
                method="totp",
                credential="123456",
                pre_auth_token_id=uuid4(),
                pre_auth_expires_at=datetime.now(timezone.utc),
            )

        self.assertEqual(repository.reservation_calls[0][0], MFA_RATE_LIMIT_SCOPE)
        self.assertEqual([succeeded for _, succeeded in repository.completion_calls], [False])

    def test_invalid_strategy_can_never_complete_step_up(self) -> None:
        user_id = uuid4()
        repository = StubRepository(configuration=active_configuration(user_id))
        service = StepUpService(
            repository,  # type: ignore[arg-type]
            (StubMFAStrategy(valid=False),),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with self.assertRaises(MFAAuthenticationError):
            service.verify(
                user_id,
                method="totp",
                credential="123456",
                pre_auth_token_id=uuid4(),
                pre_auth_expires_at=datetime.now(timezone.utc),
            )
        self.assertEqual(repository.reservation_calls[0][0], MFA_RATE_LIMIT_SCOPE)
