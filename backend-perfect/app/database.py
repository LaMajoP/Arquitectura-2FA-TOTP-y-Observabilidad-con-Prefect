"""Supabase data access. This module never decrypts or returns TOTP plaintext."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from supabase import Client, create_client

from .config import Settings
from .crypto import EncryptedSecret


class DatabaseError(RuntimeError):
    """A non-sensitive representation of a failed persistence operation."""


@dataclass(frozen=True, slots=True)
class StoredTOTPConfiguration:
    """The encrypted record stored in Supabase."""

    user_id: UUID
    status: str
    encrypted_secret: EncryptedSecret


@dataclass(frozen=True, slots=True)
class VerificationAttemptPermission:
    """The atomic shared-state decision for one submitted verification code."""

    allowed: bool
    locked_until: datetime | None


class SupabaseTOTPRepository:
    """Repository used exclusively by the backend service-role client."""

    _USERS_TABLE = "app_users"
    _CREDENTIALS_TABLE = "totp_credentials"

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


def create_repository(settings: Settings) -> SupabaseTOTPRepository:
    """Create the server-only client; its key must never reach a frontend."""
    try:
        client = create_client(settings.supabase_url, settings.supabase_service_role_key)
    except Exception as exc:
        raise DatabaseError("Unable to configure the Supabase client.") from exc
    return SupabaseTOTPRepository(client)
