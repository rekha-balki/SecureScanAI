from fastapi import FastAPI

from app.api.router import api_router
from app.platform.errors import register_exception_handlers
from app.platform.middleware import register_middlewares
from app.platform.security import register_security


def bootstrap_application(app: FastAPI) -> None:
    """Register all platform components."""

    register_exception_handlers(app)
    register_middlewares(app)
    register_security(app)

    app.include_router(api_router)