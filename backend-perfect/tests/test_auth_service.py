from __future__ import annotations

from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import patch
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
    StoredPasswordUser,
    StoredTOTPConfiguration,
    VerificationAttemptPermission,
)
from app.passwords import PasswordService
from app.totp_service import ACTIVE, PENDING_VERIFICATION
from totp import TOTPVerificationResult


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
        self.consume_calls: list[tuple[str, str, int, int]] = []
        self.clear_calls: list[tuple[str, str]] = []

    def consume_auth_attempt(
        self, scope: str, subject_key: str, max_attempts: int, lock_seconds: int
    ) -> VerificationAttemptPermission:
        self.consume_calls.append((scope, subject_key, max_attempts, lock_seconds))
        return self.permission

    def clear_auth_attempts(self, scope: str, subject_key: str) -> None:
        self.clear_calls.append((scope, subject_key))

    def get_password_user_by_email(self, email: str) -> StoredPasswordUser | None:
        return self.account

    def get_configuration(self, user_id: object) -> StoredTOTPConfiguration | None:
        return self.configuration


class StubCipher:
    def decrypt(self, encrypted: EncryptedSecret, user_id: object) -> str:
        return "JBSWY3DPEHPK3PXP"


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
        self.assertEqual(repository.consume_calls[0][0], LOGIN_RATE_LIMIT_SCOPE)
        self.assertEqual(repository.clear_calls[0][0], LOGIN_RATE_LIMIT_SCOPE)

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
        self.assertEqual(repository.clear_calls, [])

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
    def test_successful_step_up_clears_only_mfa_attempts(self) -> None:
        user_id = uuid4()
        repository = StubRepository(configuration=active_configuration(user_id))
        service = StepUpService(
            repository,  # type: ignore[arg-type]
            StubCipher(),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with patch(
            "app.auth_service.verify_totp",
            return_value=TOTPVerificationResult(valid=True, counter=1, window=0),
        ):
            service.verify(user_id, "123456")

        self.assertEqual(repository.consume_calls[0][0], MFA_RATE_LIMIT_SCOPE)
        self.assertEqual(repository.clear_calls[0][0], MFA_RATE_LIMIT_SCOPE)

    def test_invalid_step_up_code_consumes_a_shared_attempt_without_clearing_it(self) -> None:
        user_id = uuid4()
        repository = StubRepository(configuration=active_configuration(user_id))
        service = StepUpService(
            repository,  # type: ignore[arg-type]
            StubCipher(),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with patch(
            "app.auth_service.verify_totp",
            return_value=TOTPVerificationResult(valid=False, counter=None, window=None),
        ):
            with self.assertRaises(MFAAuthenticationError):
                service.verify(user_id, "123456")

        self.assertEqual(repository.consume_calls[0][0], MFA_RATE_LIMIT_SCOPE)
        self.assertEqual(repository.clear_calls, [])

    def test_pending_totp_can_never_complete_step_up(self) -> None:
        user_id = uuid4()
        configuration = active_configuration(user_id)
        configuration = StoredTOTPConfiguration(
            user_id=configuration.user_id,
            status=PENDING_VERIFICATION,
            encrypted_secret=configuration.encrypted_secret,
        )
        repository = StubRepository(configuration=configuration)
        service = StepUpService(
            repository,  # type: ignore[arg-type]
            StubCipher(),  # type: ignore[arg-type]
            rate_limit_key=b"r" * 32,
            max_attempts=5,
            lock_seconds=900,
        )

        with self.assertRaises(MFAAuthenticationError):
            service.verify(user_id, "123456")
        self.assertEqual(repository.consume_calls, [])
