from fastapi import APIRouter

from app.platform import get_logger
from app.platform.health import HealthManager
from app.shared.kernel.responses import ResponseBuilder

health_router = APIRouter()

logger = get_logger(__name__)


@health_router.get("/health", summary="Health Check")
async def get_health_status():
    logger.info("Health endpoint called")

    return ResponseBuilder.success(
        "Health check completed successfully.",
        HealthManager.get_health(),
    )