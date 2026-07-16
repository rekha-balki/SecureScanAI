"""
Persistence lifecycle management.
"""

from app.platform.logging.logger import get_logger
from app.platform.persistence.mongodb import (
    close_client,
    get_client,
)
from app.platform.persistence.redis_store import close_redis, get_redis

logger = get_logger(__name__)


async def startup_persistence() -> None:
    """
    Initialize persistence infrastructure.
    """

    logger.info("Initializing MongoDB client")

    get_client()

    logger.info("Initializing Redis client")

    try:
        redis = get_redis()
        await redis.ping()
        logger.info("Redis connection verified")
    except Exception:  # noqa: BLE001 - Redis is optional; rate limiting fails open
        logger.warning(
            "Redis is not reachable at startup; rate limiting will fail open "
            "until it becomes available."
        )

    logger.info("Persistence initialized")


async def shutdown_persistence() -> None:
    """
    Shutdown persistence infrastructure.
    """

    logger.info("Closing MongoDB client")

    close_client()

    logger.info("Closing Redis client")

    await close_redis()

    logger.info("Persistence shutdown completed")