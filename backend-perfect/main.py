
"""FastAPI entry point for the application-owned TOTP activation flow."""

from fastapi import FastAPI

from app.totp_api import router as totp_router


app = FastAPI(title="2FA Authentication API")
app.include_router(totp_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "Backend funcionando"}


@app.get("/health")
def health() -> dict[str, str]:
    """Health check intentionally does not require external credentials."""
    return {"status": "ok"}
