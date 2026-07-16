"""
Persistence lifecycle management.
"""

from app.platform.logging.logger import get_logger
from app.platform.persistence.mongodb import (
    close_client,
    get_client,
)

logger = get_logger(__name__)


async def startup_persistence() -> None:
    """
    Initialize persistence infrastructure.
    """

    logger.info("Initializing MongoDB client")

    get_client()

    logger.info("Persistence initialized")


async def shutdown_persistence() -> None:
    """
    Shutdown persistence infrastructure.
    """

    logger.info("Closing MongoDB client")

    close_client()

    logger.info("Persistence shutdown completed")