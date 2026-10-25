
"""FastAPI entry point for the application-owned TOTP activation flow."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth_api import router as auth_router
from app.config import get_cors_allowed_origins
from app.totp_api import router as totp_router


app = FastAPI(title="2FA Authentication API")
cors_allowed_origins = get_cors_allowed_origins()
if cors_allowed_origins:
    # Bearer tokens are sent explicitly by the app. Keep the origin allow-list
    # narrow; wildcard origins are not appropriate for this auth API.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Cache-Control"],
        max_age=600,
    )
app.include_router(auth_router)
app.include_router(totp_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "Backend funcionando"}


@app.get("/health")
def health() -> dict[str, str]:
    """Health check intentionally does not require external credentials."""
    return {"status": "ok"}
