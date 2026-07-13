from fastapi import FastAPI
from app.config.settings import get_settings
from .registry import bootstrap_application

def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
    )

    bootstrap_application(app)

    return app