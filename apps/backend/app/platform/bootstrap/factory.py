from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config.settings import get_settings
from app.platform.lifecycle import (
    startup_platform,
    shutdown_platform,
)

from .registry import bootstrap_application


@asynccontextmanager
async def lifespan(app: FastAPI):
    await startup_platform()

    yield

    await shutdown_platform()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )

    bootstrap_application(app)

    return app