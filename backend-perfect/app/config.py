"""Runtime configuration kept outside source control."""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


class ConfigurationError(RuntimeError):
    """Raised when the server is not safely configured to handle TOTP data."""


_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
_ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


def _required(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise ConfigurationError("The TOTP service is not configured.")
    return value.strip()


def _read_secret_bytes(name: str) -> bytes:
    """Read a non-trivial UTF-8 secret without exposing it in errors."""
    value = _required(name).encode("utf-8")
    if len(value) < 32:
        raise ConfigurationError("The TOTP service is not configured.")
    return value


def _read_boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ConfigurationError("The TOTP service is not configured.")


def _read_choice(name: str, default: str, *, allowed: frozenset[str]) -> str:
    value = os.getenv(name, default).strip().lower()
    if value not in allowed:
        raise ConfigurationError("The TOTP service is not configured.")
    return value


def get_cors_allowed_origins() -> tuple[str, ...]:
    """Read public browser origins without loading or validating server secrets."""
    load_dotenv(_ENV_FILE, override=False)
    origins = tuple(
        part.strip().rstrip("/")
        for part in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
        if part.strip()
    )
    for origin in origins:
        parsed = urlparse(origin)
        if (
            origin == "*"
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path
            or parsed.params
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ConfigurationError("The TOTP service is not configured.")
    return origins


def _read_bounded_positive_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    """Read a safe operational limit without accepting unbounded values."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value.strip())
    except (AttributeError, ValueError) as exc:
        raise ConfigurationError("The TOTP service is not configured.") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigurationError("The TOTP service is not configured.")
    return parsed


def _decode_aes_key(encoded_key: str) -> bytes:
    """Decode the Base64 *representation* of a 32-byte AES key."""
    try:
        key = base64.b64decode(encoded_key.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ConfigurationError("The TOTP service is not configured.") from exc

    if len(key) != 32:
        raise ConfigurationError("The TOTP service is not configured.")
    return key


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated secrets and identifiers required by the protected endpoints."""

    supabase_url: str
    supabase_service_role_key: str
    jwt_signing_key: str
    jwt_algorithm: str
    jwt_issuer: str
    jwt_audience: str
    auth_rate_limit_key: bytes
    totp_encryption_key: bytes
    totp_encryption_key_version: str
    require_https: bool
    totp_verify_max_attempts: int
    totp_verify_lock_seconds: int
    login_max_attempts: int
    login_lock_seconds: int
    pre_auth_token_ttl_seconds: int
    provisioning_token_ttl_seconds: int
    access_token_ttl_seconds: int
    backup_code_recent_mfa_seconds: int
    prefect_mfa_failure_mode: str

    @classmethod
    def from_environment(cls) -> "Settings":
        # This permits local development with backend-perfect/.env while a real
        # deployment continues to use environment variables supplied by its host.
        load_dotenv(_ENV_FILE, override=False)

        algorithm = _required("JWT_ALGORITHM")
        if algorithm not in _ALLOWED_JWT_ALGORITHMS:
            raise ConfigurationError("The TOTP service is not configured.")

        jwt_signing_key = _required("JWT_SECRET_KEY")
        if len(jwt_signing_key.encode("utf-8")) < 32:
            raise ConfigurationError("The TOTP service is not configured.")

        key_version = os.getenv("TOTP_ENCRYPTION_KEY_VERSION", "v1").strip()
        if not key_version:
            raise ConfigurationError("The TOTP service is not configured.")

        return cls(
            supabase_url=_required("SUPABASE_URL"),
            supabase_service_role_key=_required("SUPABASE_SERVICE_ROLE_KEY"),
            jwt_signing_key=jwt_signing_key,
            jwt_algorithm=algorithm,
            jwt_issuer=_required("JWT_ISSUER"),
            jwt_audience=_required("JWT_AUDIENCE"),
            # This separate HMAC key derives opaque rate-limit subjects. It
            # prevents the shared database table from becoming an email list.
            auth_rate_limit_key=_read_secret_bytes("AUTH_RATE_LIMIT_KEY"),
            totp_encryption_key=_decode_aes_key(_required("TOTP_ENCRYPTION_KEY")),
            totp_encryption_key_version=key_version,
            require_https=_read_boolean("TOTP_REQUIRE_HTTPS", True),
            # These defaults allow five code checks, then block further requests
            # for 15 minutes. Bounds avoid accidentally disabling the control.
            totp_verify_max_attempts=_read_bounded_positive_int(
                "TOTP_VERIFY_MAX_ATTEMPTS", 5, minimum=1, maximum=20
            ),
            totp_verify_lock_seconds=_read_bounded_positive_int(
                "TOTP_VERIFY_LOCK_SECONDS", 900, minimum=60, maximum=86_400
            ),
            login_max_attempts=_read_bounded_positive_int(
                "AUTH_LOGIN_MAX_ATTEMPTS", 5, minimum=1, maximum=20
            ),
            login_lock_seconds=_read_bounded_positive_int(
                "AUTH_LOGIN_LOCK_SECONDS", 900, minimum=60, maximum=86_400
            ),
            pre_auth_token_ttl_seconds=_read_bounded_positive_int(
                "AUTH_PRE_AUTH_TOKEN_TTL_SECONDS", 300, minimum=60, maximum=900
            ),
            provisioning_token_ttl_seconds=_read_bounded_positive_int(
                "AUTH_PROVISIONING_TOKEN_TTL_SECONDS", 900, minimum=60, maximum=3_600
            ),
            access_token_ttl_seconds=_read_bounded_positive_int(
                "AUTH_ACCESS_TOKEN_TTL_SECONDS", 3_600, minimum=300, maximum=86_400
            ),
            backup_code_recent_mfa_seconds=_read_bounded_positive_int(
                "AUTH_BACKUP_CODE_RECENT_MFA_SECONDS", 300, minimum=60, maximum=900
            ),
            prefect_mfa_failure_mode=_read_choice(
                "PREFECT_MFA_FAILURE_MODE",
                "fail_closed",
                allowed=frozenset({"fail_closed", "direct_fallback"}),
            ),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build settings only on first protected request, not at import time."""
    return Settings.from_environment()
