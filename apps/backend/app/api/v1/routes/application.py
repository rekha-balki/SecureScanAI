from fastapi import APIRouter

from app.config.settings import get_settings
from app.platform import get_logger
from app.shared.kernel.responses import ResponseBuilder

application_router = APIRouter()

logger = get_logger(__name__)

settings = get_settings()


@application_router.get("/", summary="Application Root")
async def get_application_info():

    logger.info("Root endpoint called")

    return ResponseBuilder.success(
        "SecureScan AI is running.",
        {
            "application": settings.app_name,
            "version": settings.app_version,
        },
    )