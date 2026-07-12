from fastapi import FastAPI

from app.api.router import api_router
from app.config.settings import get_settings
from app.platform.errors import register_exception_handlers
from app.platform.middleware import register_middlewares


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
    )

    register_exception_handlers(app)

    register_middlewares(app)

    app.include_router(api_router)

    return app