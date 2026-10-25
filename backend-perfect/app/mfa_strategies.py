"""MFA validation strategies with no token issuance or persistence side effects."""

from __future__ import annotations

import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from totp import verify_totp
from totp.core import TIME_STEP_SECONDS

from .crypto import SecretDecryptionError, TOTPSecretCipher
from .database import DatabaseError, SupabaseTOTPRepository
from .passwords import PasswordService
from .totp_service import ACTIVE


TOTP_METHOD = "totp"
BACKUP_CODE_METHOD = "backup_code"
BACKUP_CODE_COUNT = 10
_BACKUP_CODE_RANDOM_BYTES = 16


class MFAValidationError(RuntimeError):
    """The submitted factor is invalid without disclosing its state."""


class MFAValidationStorageError(RuntimeError):
    """The factor cannot be safely validated because protected state failed."""


@dataclass(frozen=True, slots=True)
class MFAValidationResult:
    """A validated factor proof for the later atomic database confirmation."""

    method: str
    totp_counter: int | None = None
    # The accepted counter's offset from the verifier's current counter. This
    # is observability metadata only; the SQL confirmation consumes the exact
    # counter and remains the anti-replay authority.
    totp_window: int | None = None
    backup_code_id: UUID | None = None


class MFAValidationStrategy(ABC):
    """Contract for one MFA method; validation never emits an access token."""

    method: str

    @abstractmethod
    def validate(self, user_id: UUID, credential: str) -> MFAValidationResult:
        """Validate a factor and return only the proof needed for consumption."""


class TOTPStrategy(MFAValidationStrategy):
    """Use the existing TOTP verifier and backend-only AES-GCM decrypt path."""

    method = TOTP_METHOD

    def __init__(self, repository: SupabaseTOTPRepository, cipher: TOTPSecretCipher) -> None:
        self._repository = repository
        self._cipher = cipher

    def validate(self, user_id: UUID, credential: str) -> MFAValidationResult:
        try:
            configuration = self._repository.get_configuration(user_id)
        except DatabaseError as exc:
            raise MFAValidationStorageError("TOTP configuration is unavailable.") from exc
        if configuration is None or configuration.status != ACTIVE:
            raise MFAValidationError("MFA authentication cannot be completed.")

        try:
            secret_base32 = self._cipher.decrypt(configuration.encrypted_secret, user_id)
            verification_timestamp = time.time()
            verification = verify_totp(
                secret_base32,
                credential,
                timestamp=verification_timestamp,
            )
        except (SecretDecryptionError, TypeError, ValueError) as exc:
            raise MFAValidationStorageError("Protected TOTP data could not be used.") from exc

        if not verification.valid or verification.counter is None:
            raise MFAValidationError("MFA authentication cannot be completed.")
        verifier_counter = int(verification_timestamp // TIME_STEP_SECONDS)
        return MFAValidationResult(
            method=self.method,
            totp_counter=verification.counter,
            totp_window=verification.counter - verifier_counter,
        )


class BackupCodeStrategy(MFAValidationStrategy):
    """Match an unused Argon2id-hashed recovery code without exposing it."""

    method = BACKUP_CODE_METHOD

    def __init__(self, repository: SupabaseTOTPRepository, passwords: PasswordService) -> None:
        self._repository = repository
        self._passwords = passwords

    def validate(self, user_id: UUID, credential: str) -> MFAValidationResult:
        try:
            candidates = self._repository.get_unused_backup_codes(user_id)
        except DatabaseError as exc:
            raise MFAValidationStorageError("Backup-code storage is unavailable.") from exc

        for candidate in candidates:
            if self._passwords.verify_password(candidate.code_hash, credential):
                return MFAValidationResult(method=self.method, backup_code_id=candidate.code_id)
        raise MFAValidationError("MFA authentication cannot be completed.")


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """Generate distinct high-entropy URL-safe recovery codes with the CSPRNG."""
    if not 1 <= count <= BACKUP_CODE_COUNT:
        raise ValueError("Backup-code count is invalid.")

    codes: set[str] = set()
    while len(codes) < count:
        codes.add(secrets.token_urlsafe(_BACKUP_CODE_RANDOM_BYTES))
    return list(codes)


class BackupCodeManagementService:
    """Regenerate a user's recovery codes after an MFA-complete access session."""

    def __init__(self, repository: SupabaseTOTPRepository, passwords: PasswordService) -> None:
        self._repository = repository
        self._passwords = passwords

    def regenerate(self, user_id: UUID) -> list[str]:
        codes = generate_backup_codes()
        code_hashes = [self._passwords.hash_password(code) for code in codes]
        try:
            self._repository.replace_backup_codes(user_id, code_hashes)
        except DatabaseError as exc:
            raise MFAValidationStorageError("Backup-code storage is unavailable.") from exc
        return codes
