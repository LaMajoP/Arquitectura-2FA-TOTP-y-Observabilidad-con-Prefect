"""HTTP endpoints for registration, password login, and TOTP Step-Up."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from functools import lru_cache
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator

from .auth import TOKEN_TYPE_PRE_AUTH, AuthorizationError, TokenIssuer, authenticate_token
from .auth_service import (
    AuthenticationRateLimitError,
    AuthenticationStorageError,
    InvalidCredentialsError,
    MFAAuthenticationError,
    PasswordLoginService,
    RegistrationConflictError,
    RegistrationService,
    StepUpService,
)
from .crypto import TOTPSecretCipher
from .database import DatabaseError, SupabaseTOTPRepository, create_repository
from .passwords import PasswordService
from .totp_api import get_runtime_settings, require_secure_transport
from .config import Settings


router = APIRouter(prefix="/v1/auth", tags=["auth"])


class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=1_024)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        # Application account identity is deliberately case-insensitive.
        return str(value).lower()

    @field_validator("password")
    @classmethod
    def reject_blank_password(cls, value: str) -> str:
        if value.isspace():
            raise ValueError("Password must not be blank.")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    # Login deliberately permits any nonempty length so a bad password gets the
    # same generic credential response rather than revealing registration rules.
    password: str = Field(min_length=1, max_length=1_024)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).lower()


class RegistrationResponse(BaseModel):
    status: Literal["REGISTERED"]


class LoginResponse(BaseModel):
    status: Literal["MFA_REQUIRED", "TOTP_ENROLLMENT_REQUIRED"]
    pre_auth_token: str | None = None
    provisioning_token: str | None = None
    expires_in: int


class VerifyMFARequest(BaseModel):
    pre_auth_token: str = Field(min_length=1, max_length=8_192)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class VerifyMFAResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int


def _service_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="The authentication service is temporarily unavailable.",
    )


def _authentication_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication could not be completed.",
    )


def _rate_limited(error: AuthenticationRateLimitError) -> HTTPException:
    retry_after_seconds = max(
        1,
        math.ceil((error.locked_until - datetime.now(timezone.utc)).total_seconds()),
    )
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many authentication attempts. Please try again later.",
        headers={"Retry-After": str(retry_after_seconds)},
    )


@lru_cache(maxsize=1)
def get_password_service() -> PasswordService:
    """Keep one Argon2 configuration and dummy hash per process."""
    return PasswordService()


def get_auth_repository(settings: Settings = Depends(get_runtime_settings)) -> SupabaseTOTPRepository:
    try:
        return create_repository(settings)
    except DatabaseError as exc:
        raise _service_unavailable() from exc


def get_registration_service(
    repository: SupabaseTOTPRepository = Depends(get_auth_repository),
) -> RegistrationService:
    return RegistrationService(repository, get_password_service())


def get_login_service(
    settings: Settings = Depends(get_runtime_settings),
    repository: SupabaseTOTPRepository = Depends(get_auth_repository),
) -> PasswordLoginService:
    return PasswordLoginService(
        repository,
        get_password_service(),
        rate_limit_key=settings.auth_rate_limit_key,
        max_attempts=settings.login_max_attempts,
        lock_seconds=settings.login_lock_seconds,
    )


def get_step_up_service(
    settings: Settings = Depends(get_runtime_settings),
    repository: SupabaseTOTPRepository = Depends(get_auth_repository),
) -> StepUpService:
    try:
        cipher = TOTPSecretCipher(settings.totp_encryption_key, settings.totp_encryption_key_version)
    except ValueError as exc:
        raise _service_unavailable() from exc
    return StepUpService(
        repository,
        cipher,
        rate_limit_key=settings.auth_rate_limit_key,
        max_attempts=settings.totp_verify_max_attempts,
        lock_seconds=settings.totp_verify_lock_seconds,
    )


@router.post(
    "/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_secure_transport)],
)
def register(
    payload: RegistrationRequest,
    service: RegistrationService = Depends(get_registration_service),
) -> RegistrationResponse:
    try:
        service.register(payload.email, payload.password)
    except RegistrationConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration cannot be completed with these details.",
        ) from exc
    except AuthenticationStorageError as exc:
        raise _service_unavailable() from exc
    return RegistrationResponse(status="REGISTERED")


@router.post(
    "/login",
    response_model=LoginResponse,
    response_model_exclude_none=True,
    dependencies=[Depends(require_secure_transport)],
)
def login(
    payload: LoginRequest,
    response: Response,
    settings: Settings = Depends(get_runtime_settings),
    service: PasswordLoginService = Depends(get_login_service),
) -> LoginResponse:
    try:
        result = service.login(payload.email, payload.password)
    except InvalidCredentialsError as exc:
        # The identical response covers a missing email and a wrong password.
        raise _authentication_failed() from exc
    except AuthenticationRateLimitError as exc:
        raise _rate_limited(exc) from exc
    except AuthenticationStorageError as exc:
        raise _service_unavailable() from exc

    issuer = TokenIssuer(settings)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if result.requires_mfa:
        issued = issuer.issue_pre_auth_token(result.user_id)
        return LoginResponse(
            status="MFA_REQUIRED",
            pre_auth_token=issued.token,
            expires_in=issued.expires_in,
        )

    issued = issuer.issue_provisioning_token(result.user_id)
    return LoginResponse(
        status="TOTP_ENROLLMENT_REQUIRED",
        provisioning_token=issued.token,
        expires_in=issued.expires_in,
    )


@router.post(
    "/verify-mfa",
    response_model=VerifyMFAResponse,
    dependencies=[Depends(require_secure_transport)],
)
def verify_mfa(
    payload: VerifyMFARequest,
    response: Response,
    settings: Settings = Depends(get_runtime_settings),
    service: StepUpService = Depends(get_step_up_service),
) -> VerifyMFAResponse:
    try:
        pre_authenticated_user = authenticate_token(
            payload.pre_auth_token,
            settings,
            expected_token_type=TOKEN_TYPE_PRE_AUTH,
            expected_mfa_verified=False,
        )
    except AuthorizationError as exc:
        raise _authentication_failed() from exc

    try:
        service.verify(pre_authenticated_user.user_id, payload.code)
    except MFAAuthenticationError as exc:
        raise _authentication_failed() from exc
    except AuthenticationRateLimitError as exc:
        raise _rate_limited(exc) from exc
    except AuthenticationStorageError as exc:
        raise _service_unavailable() from exc

    issued = TokenIssuer(settings).issue_access_token(pre_authenticated_user.user_id)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return VerifyMFAResponse(access_token=issued.token, expires_in=issued.expires_in)
