"""Supabase data access. This module never decrypts or returns TOTP plaintext."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from supabase import Client, create_client

from .config import Settings
from .crypto import EncryptedSecret


class DatabaseError(RuntimeError):
    """A non-sensitive representation of a failed persistence operation."""


class DuplicateEmailError(DatabaseError):
    """A password account already exists for the normalized email address."""


@dataclass(frozen=True, slots=True)
class StoredTOTPConfiguration:
    """The encrypted record stored in Supabase."""

    user_id: UUID
    status: str
    encrypted_secret: EncryptedSecret


@dataclass(frozen=True, slots=True)
class StoredPasswordUser:
    """The authentication fields fetched only by the server-side repository."""

    user_id: UUID
    password_hash: str


@dataclass(frozen=True, slots=True)
class VerificationAttemptPermission:
    """The atomic shared-state decision for one submitted verification code."""

    allowed: bool
    locked_until: datetime | None


class SupabaseTOTPRepository:
    """Server-only repository for TOTP, password accounts, and shared limits."""

    _USERS_TABLE = "app_users"
    _CREDENTIALS_TABLE = "totp_credentials"

    @staticmethod
    def _is_unique_violation(exc: Exception) -> bool:
        """Recognize PostgreSQL's stable uniqueness code without echoing errors."""
        return getattr(exc, "code", None) == "23505"

    def __init__(self, client: Client) -> None:
        self._client = client

    @staticmethod
    def _record_from_row(row: dict[str, Any]) -> StoredTOTPConfiguration:
        return StoredTOTPConfiguration(
            user_id=UUID(row["user_id"]),
            status=row["status"],
            encrypted_secret=EncryptedSecret(
                ciphertext_b64=row["secret_ciphertext"],
                nonce_b64=row["secret_nonce"],
                tag_b64=row["secret_tag"],
                key_version=row["encryption_key_version"],
            ),
        )

    def get_configuration(self, user_id: UUID) -> StoredTOTPConfiguration | None:
        try:
            response = (
                self._client.table(self._CREDENTIALS_TABLE)
                .select(
                    "user_id,status,secret_ciphertext,secret_nonce,secret_tag,encryption_key_version"
                )
                .eq("user_id", str(user_id))
                .limit(1)
                .execute()
            )
        except Exception as exc:
            raise DatabaseError("Unable to read TOTP configuration.") from exc

        rows = response.data or []
        if not rows:
            return None
        try:
            return self._record_from_row(rows[0])
        except (KeyError, TypeError, ValueError) as exc:
            raise DatabaseError("Stored TOTP configuration is invalid.") from exc

    def create_password_user(self, email: str, password_hash: str) -> UUID:
        """Atomically persist a newly generated UUID, email, and Argon2id hash."""
        user_id = uuid4()
        try:
            self._client.table(self._USERS_TABLE).insert(
                {
                    "id": str(user_id),
                    "email": email,
                    "password_hash": password_hash,
                }
            ).execute()
        except Exception as exc:
            if self._is_unique_violation(exc):
                raise DuplicateEmailError("A password account already exists.") from exc
            raise DatabaseError("Unable to persist application user.") from exc
        return user_id

    def get_password_user_by_email(self, email: str) -> StoredPasswordUser | None:
        """Fetch a single Argon2id hash through a parameterized Supabase query."""
        try:
            response = (
                self._client.table(self._USERS_TABLE)
                .select("id,password_hash")
                .eq("email", email)
                .limit(1)
                .execute()
            )
        except Exception as exc:
            raise DatabaseError("Unable to read application user.") from exc

        rows = response.data or []
        if not rows:
            return None
        try:
            row = rows[0]
            password_hash = row["password_hash"]
            if not isinstance(password_hash, str) or not password_hash:
                raise ValueError("Password hash is missing.")
            return StoredPasswordUser(user_id=UUID(row["id"]), password_hash=password_hash)
        except (KeyError, TypeError, ValueError) as exc:
            raise DatabaseError("Stored password account is invalid.") from exc

    def ensure_user(self, user_id: UUID) -> None:
        try:
            self._client.table(self._USERS_TABLE).upsert(
                {"id": str(user_id)}, on_conflict="id"
            ).execute()
        except Exception as exc:
            raise DatabaseError("Unable to persist application user.") from exc

    def create_pending_configuration(self, user_id: UUID, encrypted: EncryptedSecret) -> None:
        record = {
            "user_id": str(user_id),
            "status": "PENDING_VERIFICATION",
            "secret_ciphertext": encrypted.ciphertext_b64,
            "secret_nonce": encrypted.nonce_b64,
            "secret_tag": encrypted.tag_b64,
            "encryption_key_version": encrypted.key_version,
        }
        try:
            self._client.table(self._CREDENTIALS_TABLE).insert(record).execute()
        except Exception as exc:
            raise DatabaseError("Unable to create TOTP configuration.") from exc

    def activate_pending_configuration(self, user_id: UUID) -> bool:
        """Atomically transition only a pending record into ACTIVE."""
        try:
            response = (
                self._client.table(self._CREDENTIALS_TABLE)
                .update(
                    {
                        "status": "ACTIVE",
                        "activated_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                .eq("user_id", str(user_id))
                .eq("status", "PENDING_VERIFICATION")
                .execute()
            )
        except Exception as exc:
            raise DatabaseError("Unable to activate TOTP configuration.") from exc
        return bool(response.data)

    def consume_verification_attempt(
        self, user_id: UUID, max_attempts: int, lock_seconds: int
    ) -> VerificationAttemptPermission:
        """Atomically reserve a code verification or report the current lock.

        The database function serializes requests for a user with a row lock, so
        this remains effective across ASGI workers and application instances.
        """
        try:
            response = self._client.rpc(
                "consume_totp_verification_attempt",
                {
                    "p_user_id": str(user_id),
                    "p_max_attempts": max_attempts,
                    "p_lock_seconds": lock_seconds,
                },
            ).execute()
            rows = response.data or []
            if not isinstance(rows, list) or len(rows) != 1:
                raise ValueError("Unexpected verification-attempt response.")

            row = rows[0]
            if not isinstance(row, dict) or type(row.get("allowed")) is not bool:
                raise ValueError("Unexpected verification-attempt response.")

            allowed = row["allowed"]
            raw_locked_until = row.get("locked_until")
            if allowed:
                if raw_locked_until is not None:
                    raise ValueError("Unexpected verification-attempt response.")
                return VerificationAttemptPermission(allowed=True, locked_until=None)

            if isinstance(raw_locked_until, datetime):
                locked_until = raw_locked_until
            elif isinstance(raw_locked_until, str):
                locked_until = datetime.fromisoformat(raw_locked_until.replace("Z", "+00:00"))
            else:
                raise ValueError("Unexpected verification-attempt response.")
            if locked_until.tzinfo is None:
                raise ValueError("Unexpected verification-attempt response.")
            return VerificationAttemptPermission(
                allowed=False,
                locked_until=locked_until.astimezone(timezone.utc),
            )
        except Exception as exc:
            raise DatabaseError("Unable to record TOTP verification attempt.") from exc

    def consume_auth_attempt(
        self, scope: str, subject_key: str, max_attempts: int, lock_seconds: int
    ) -> VerificationAttemptPermission:
        """Atomically reserve a login or Step-Up check in shared Supabase state."""
        try:
            response = self._client.rpc(
                "consume_auth_rate_limit_attempt",
                {
                    "p_scope": scope,
                    "p_subject_key": subject_key,
                    "p_max_attempts": max_attempts,
                    "p_lock_seconds": lock_seconds,
                },
            ).execute()
            rows = response.data or []
            if not isinstance(rows, list) or len(rows) != 1:
                raise ValueError("Unexpected authentication-attempt response.")

            row = rows[0]
            if not isinstance(row, dict) or type(row.get("allowed")) is not bool:
                raise ValueError("Unexpected authentication-attempt response.")

            allowed = row["allowed"]
            raw_locked_until = row.get("locked_until")
            if allowed:
                if raw_locked_until is not None:
                    raise ValueError("Unexpected authentication-attempt response.")
                return VerificationAttemptPermission(allowed=True, locked_until=None)

            if isinstance(raw_locked_until, datetime):
                locked_until = raw_locked_until
            elif isinstance(raw_locked_until, str):
                locked_until = datetime.fromisoformat(raw_locked_until.replace("Z", "+00:00"))
            else:
                raise ValueError("Unexpected authentication-attempt response.")
            if locked_until.tzinfo is None:
                raise ValueError("Unexpected authentication-attempt response.")
            return VerificationAttemptPermission(
                allowed=False,
                locked_until=locked_until.astimezone(timezone.utc),
            )
        except Exception as exc:
            raise DatabaseError("Unable to record authentication attempt.") from exc

    def clear_auth_attempts(self, scope: str, subject_key: str) -> None:
        """Clear reserved failures after a successful credential verification."""
        try:
            self._client.rpc(
                "clear_auth_rate_limit_attempts",
                {"p_scope": scope, "p_subject_key": subject_key},
            ).execute()
        except Exception as exc:
            raise DatabaseError("Unable to clear authentication attempts.") from exc


def create_repository(settings: Settings) -> SupabaseTOTPRepository:
    """Create the server-only client; its key must never reach a frontend."""
    try:
        client = create_client(settings.supabase_url, settings.supabase_service_role_key)
    except Exception as exc:
        raise DatabaseError("Unable to configure the Supabase client.") from exc
    return SupabaseTOTPRepository(client)
