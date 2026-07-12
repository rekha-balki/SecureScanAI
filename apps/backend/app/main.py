from fastapi import FastAPI

from app.config.settings import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)


@app.get("/")
async def root():
    return {
        "application": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/health")
async def health():
    return {
        "status": "UP",
        "environment": settings.environment,
        "version": settings.app_version,
    }