from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from app.crypto import EncryptedSecret
from app.database import StoredTOTPConfiguration, VerificationAttemptPermission
from app.auth import AuthenticatedUser
from app.totp_api import VerifyEnrollmentRequest, verify_totp_enrollment
from app.totp_service import (
    ACTIVE,
    PENDING_VERIFICATION,
    EnrollmentConflictError,
    TOTPActivationService,
    VerificationRateLimitError,
)
from totp import TOTPVerificationResult
from fastapi import HTTPException


class StubCipher:
    def decrypt(self, encrypted_secret: EncryptedSecret, user_id: object) -> str:
        return "JBSWY3DPEHPK3PXP"


class StubRepository:
    def __init__(self, permission: VerificationAttemptPermission, activation_results: list[bool]) -> None:
        self.configuration = StoredTOTPConfiguration(
            user_id=uuid4(),
            status=PENDING_VERIFICATION,
            encrypted_secret=EncryptedSecret("ciphertext", "nonce", "tag", "v1"),
        )
        self.permission = permission
        self.activation_results = activation_results
        self.consume_calls = 0
        self.activate_calls = 0

    def get_configuration(self, user_id: object) -> StoredTOTPConfiguration:
        # It intentionally remains PENDING to model two requests that both read
        # the old state before either conditional update completes.
        return self.configuration

    def consume_verification_attempt(
        self, user_id: object, max_attempts: int, lock_seconds: int
    ) -> VerificationAttemptPermission:
        self.consume_calls += 1
        return self.permission

    def activate_pending_configuration(self, user_id: object) -> bool:
        self.activate_calls += 1
        return self.activation_results.pop(0)


class TOTPActivationServiceTests(TestCase):
    def test_temporary_lock_stops_code_verification(self) -> None:
        repository = StubRepository(
            VerificationAttemptPermission(
                allowed=False,
                locked_until=datetime.now(timezone.utc) + timedelta(minutes=15),
            ),
            activation_results=[],
        )
        service = TOTPActivationService(repository, StubCipher())

        with patch("app.totp_service.verify_totp") as verify:
            with self.assertRaises(VerificationRateLimitError):
                service.verify_initial_code(uuid4(), "123456")

        self.assertEqual(repository.consume_calls, 1)
        self.assertEqual(repository.activate_calls, 0)
        verify.assert_not_called()

    def test_only_conditional_transition_winner_reports_active(self) -> None:
        repository = StubRepository(
            VerificationAttemptPermission(allowed=True, locked_until=None),
            activation_results=[True, False],
        )
        service = TOTPActivationService(repository, StubCipher())
        valid = TOTPVerificationResult(valid=True, counter=1, window=0)
        user_id = uuid4()

        with patch("app.totp_service.verify_totp", return_value=valid):
            self.assertEqual(service.verify_initial_code(user_id, "123456"), ACTIVE)
            with self.assertRaises(EnrollmentConflictError):
                service.verify_initial_code(user_id, "123456")

        self.assertEqual(repository.activate_calls, 2)

    def test_http_rate_limit_response_includes_retry_after(self) -> None:
        locked_until = datetime.now(timezone.utc) + timedelta(seconds=120)

        class LockedService:
            def verify_initial_code(self, user_id: object, code: str) -> str:
                raise VerificationRateLimitError(locked_until)

        with self.assertRaises(HTTPException) as raised:
            verify_totp_enrollment(
                VerifyEnrollmentRequest(code="123456"),
                AuthenticatedUser(user_id=uuid4()),
                LockedService(),  # type: ignore[arg-type]
            )

        error = raised.exception
        self.assertEqual(error.status_code, 429)
        self.assertEqual(error.detail, "Too many verification attempts. Please try again later.")
        self.assertIsNotNone(error.headers)
        self.assertGreaterEqual(int(error.headers["Retry-After"]), 1)
        self.assertLessEqual(int(error.headers["Retry-After"]), 120)
