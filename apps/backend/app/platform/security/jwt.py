"""
JWT token issuance and verification.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt

from app.config.constants import JWT_ALGORITHM
from app.config.settings import get_settings


class TokenError(Exception):
    pass


def create_access_token(subject: str, claims: dict[str, Any] | None = None) -> str:
    settings = get_settings()

    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=settings.jwt_expiry_minutes)

    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expires_at,
    }

    if claims:
        payload.update(claims)

    return jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()

    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise TokenError("Invalid or expired token") from exc
