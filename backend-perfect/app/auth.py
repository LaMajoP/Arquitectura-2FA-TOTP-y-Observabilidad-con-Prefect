"""Purpose-bound JWT issuance and validation for the application auth flows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
from jwt import InvalidTokenError

from .config import Settings


TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_PRE_AUTH = "pre_auth"
TOKEN_TYPE_PROVISIONING = "provisioning"


class AuthorizationError(RuntimeError):
    """Raised for an absent, expired, invalid, or unsuitable bearer token."""


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """A verified identity and its intentionally narrow token authorization."""

    user_id: UUID
    # Defaults preserve the small direct unit-test seam from phase 2. Values
    # returned from a real token are always explicitly validated below.
    token_type: str = TOKEN_TYPE_ACCESS
    mfa_verified: bool = True
    token_id: UUID | None = None
    token_expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """A freshly signed JWT plus its bounded lifetime for an API response."""

    token: str
    expires_in: int


class TokenIssuer:
    """Issue JWTs with the least authority needed for one auth-flow step."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def issue_pre_auth_token(self, user_id: UUID) -> IssuedToken:
        return self._issue(
            user_id,
            token_type=TOKEN_TYPE_PRE_AUTH,
            mfa_verified=False,
            ttl_seconds=self._settings.pre_auth_token_ttl_seconds,
        )

    def issue_provisioning_token(self, user_id: UUID) -> IssuedToken:
        return self._issue(
            user_id,
            token_type=TOKEN_TYPE_PROVISIONING,
            mfa_verified=False,
            ttl_seconds=self._settings.provisioning_token_ttl_seconds,
        )

    def issue_access_token(self, user_id: UUID) -> IssuedToken:
        return self._issue(
            user_id,
            token_type=TOKEN_TYPE_ACCESS,
            mfa_verified=True,
            ttl_seconds=self._settings.access_token_ttl_seconds,
        )

    def _issue(
        self,
        user_id: UUID,
        *,
        token_type: str,
        mfa_verified: bool,
        ttl_seconds: int,
    ) -> IssuedToken:
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(user_id),
            "iss": self._settings.jwt_issuer,
            "aud": self._settings.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "token_type": token_type,
            "mfa_verified": mfa_verified,
            "jti": str(uuid4()),
        }
        token = jwt.encode(
            claims,
            self._settings.jwt_signing_key,
            algorithm=self._settings.jwt_algorithm,
        )
        return IssuedToken(token=token, expires_in=ttl_seconds)


def _extract_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise AuthorizationError("A bearer token is required.")

    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        raise AuthorizationError("A bearer token is required.")
    return token.strip()


def authenticate_token(
    token: str,
    settings: Settings,
    *,
    expected_token_type: str,
    expected_mfa_verified: bool,
) -> AuthenticatedUser:
    """Validate one JWT purpose, never merely a valid signature.

    A caller cannot turn a provisioning or pre-auth JWT into an access JWT by
    editing claims: signature, issuer, audience, expiration, token purpose,
    MFA state, UUID subject, and UUID JTI are all checked.
    """
    try:
        claims = jwt.decode(
            token,
            settings.jwt_signing_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": [
                    "exp",
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "token_type",
                    "mfa_verified",
                    "jti",
                ],
            },
        )
        user_id = UUID(claims["sub"])
        token_id = UUID(claims["jti"])
        token_type = claims["token_type"]
        mfa_verified = claims["mfa_verified"]
        issued_at = claims["iat"]
        expiration = claims["exp"]
        if (
            not isinstance(token_type, str)
            or token_type != expected_token_type
            or type(mfa_verified) is not bool
            or mfa_verified is not expected_mfa_verified
            or type(issued_at) is not int
            or type(expiration) is not int
        ):
            raise ValueError("JWT authorization claims are invalid.")
        token_expires_at = datetime.fromtimestamp(expiration, timezone.utc)
    except (InvalidTokenError, KeyError, OSError, OverflowError, TypeError, ValueError) as exc:
        raise AuthorizationError("The token is invalid, expired, or unsuitable.") from exc

    return AuthenticatedUser(
        user_id=user_id,
        token_type=token_type,
        mfa_verified=mfa_verified,
        token_id=token_id,
        token_expires_at=token_expires_at,
    )


def authenticate_bearer_token(
    authorization: str | None,
    settings: Settings,
    *,
    expected_token_type: str = TOKEN_TYPE_ACCESS,
    expected_mfa_verified: bool = True,
) -> AuthenticatedUser:
    """Extract and validate a bearer JWT for the exact endpoint purpose."""
    return authenticate_token(
        _extract_bearer_token(authorization),
        settings,
        expected_token_type=expected_token_type,
        expected_mfa_verified=expected_mfa_verified,
    )
