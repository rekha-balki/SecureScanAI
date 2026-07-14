from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config.settings import get_settings


def register_trusted_hosts(app: FastAPI) -> None:
    """Register trusted host middleware."""

    settings = get_settings()

    app.add_middleware(
        TrustedHostMiddleware,
        #allowed_hosts=settings.trusted_hosts,
        allowed_hosts=[
            "localhost",
            "127.0.0.1",
            "testserver",
        ]
    )