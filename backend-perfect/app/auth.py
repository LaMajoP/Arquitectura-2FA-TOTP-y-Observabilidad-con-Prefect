"""JWT validation for operations that are allowed to decrypt a TOTP secret."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import jwt
from jwt import InvalidTokenError

from .config import Settings


class AuthorizationError(RuntimeError):
    """Raised for an absent, expired, invalid, or unsuitable bearer token."""


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """The verified account identity; it is never taken from a request body."""

    user_id: UUID


def authenticate_bearer_token(authorization: str | None, settings: Settings) -> AuthenticatedUser:
    """Cryptographically validate a JWT and return its bound user identity.

    ``jwt.decode`` verifies the signature and ``exp`` by default. Requiring an
    issuer, audience, and subject prevents a token issued for another service
    from authorizing a TOTP decrypt operation.
    """
    if authorization is None:
        raise AuthorizationError("A bearer token is required.")

    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        raise AuthorizationError("A bearer token is required.")

    try:
        claims = jwt.decode(
            token.strip(),
            settings.jwt_signing_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "sub", "iss", "aud"]},
        )
        subject = claims["sub"]
        user_id = UUID(subject)
    except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        raise AuthorizationError("The bearer token is invalid or expired.") from exc

    return AuthenticatedUser(user_id=user_id)
