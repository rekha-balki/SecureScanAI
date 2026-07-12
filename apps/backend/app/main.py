from fastapi import FastAPI

from app.config.settings import get_settings
from app.platform.log import get_logger

settings = get_settings()

logger = get_logger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)


@app.on_event("startup")
async def startup():
    logger.info("SecureScan AI started")


@app.on_event("shutdown")
async def shutdown():
    logger.info("SecureScan AI stopped")


@app.get("/")
async def root():
    logger.info("Root endpoint called")

    return {
        "application": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/health")
async def health():
    logger.info("Health endpoint called")

    return {
        "status": "UP",
        "environment": settings.environment,
        "version": settings.app_version,
    }