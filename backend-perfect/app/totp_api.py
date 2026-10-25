"""Minimal authenticated HTTP surface for one-time TOTP enrollment."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .auth import AuthenticatedUser, AuthorizationError, authenticate_bearer_token
from .config import ConfigurationError, Settings, get_settings
from .crypto import TOTPSecretCipher
from .database import DatabaseError, create_repository
from .totp_service import (
    EnrollmentConflictError,
    EnrollmentNotFoundError,
    InvalidVerificationCodeError,
    SecureStorageError,
    TOTPActivationService,
    VerificationRateLimitError,
)


router = APIRouter(prefix="/v1/totp", tags=["totp"])


class StartEnrollmentResponse(BaseModel):
    status: Literal["PENDING_VERIFICATION"]
    secret_base32: str


class VerifyEnrollmentRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class VerifyEnrollmentResponse(BaseModel):
    status: Literal["ACTIVE"]


def _service_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="The TOTP service is temporarily unavailable.",
    )


def get_runtime_settings() -> Settings:
    try:
        return get_settings()
    except ConfigurationError as exc:
        raise _service_unavailable() from exc


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_runtime_settings),
) -> AuthenticatedUser:
    try:
        return authenticate_bearer_token(authorization, settings)
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_activation_service(
    settings: Settings = Depends(get_runtime_settings),
) -> TOTPActivationService:
    try:
        repository = create_repository(settings)
        cipher = TOTPSecretCipher(
            settings.totp_encryption_key,
            settings.totp_encryption_key_version,
        )
        return TOTPActivationService(
            repository,
            cipher,
            verify_max_attempts=settings.totp_verify_max_attempts,
            verify_lock_seconds=settings.totp_verify_lock_seconds,
        )
    except (DatabaseError, ValueError) as exc:
        raise _service_unavailable() from exc


def require_secure_transport(request: Request, settings: Settings = Depends(get_runtime_settings)) -> None:
    """Do not return the provisioning secret over a clear-text connection."""
    if settings.require_https and request.url.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Secure transport is required for TOTP operations.",
        )


@router.post(
    "/setup",
    response_model=StartEnrollmentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_secure_transport)],
)
def start_totp_enrollment(
    response: Response,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TOTPActivationService = Depends(get_activation_service),
) -> StartEnrollmentResponse:
    """Create a pending encrypted credential and return its secret exactly once."""
    try:
        enrollment = service.start_enrollment(current_user.user_id)
    except EnrollmentConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="TOTP enrollment already exists for this account.",
        ) from exc
    except SecureStorageError as exc:
        raise _service_unavailable() from exc

    # Avoid persistence by compliant browsers/proxies of the only plaintext response.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return StartEnrollmentResponse(status=enrollment.status, secret_base32=enrollment.secret_base32)


@router.post(
    "/verify",
    response_model=VerifyEnrollmentResponse,
    dependencies=[Depends(require_secure_transport)],
)
def verify_totp_enrollment(
    payload: VerifyEnrollmentRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TOTPActivationService = Depends(get_activation_service),
) -> VerifyEnrollmentResponse:
    """Verify the initial code server-side before atomically enabling TOTP."""
    try:
        result = service.verify_initial_code(current_user.user_id, payload.code)
    except EnrollmentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No pending TOTP enrollment exists for this account.",
        ) from exc
    except EnrollmentConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="TOTP enrollment is not awaiting verification.",
        ) from exc
    except InvalidVerificationCodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification code is invalid.",
        ) from exc
    except VerificationRateLimitError as exc:
        retry_after_seconds = max(
            1,
            math.ceil((exc.locked_until - datetime.now(timezone.utc)).total_seconds()),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification attempts. Please try again later.",
            headers={"Retry-After": str(retry_after_seconds)},
        ) from exc
    except SecureStorageError as exc:
        raise _service_unavailable() from exc

    return VerifyEnrollmentResponse(status=result)
