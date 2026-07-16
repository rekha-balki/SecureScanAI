"""
Platform startup orchestration.
"""

from app.platform.logging.logger import get_logger
from app.platform.persistence import startup_persistence

logger = get_logger(__name__)


async def startup_platform() -> None:
    """
    Initialize all platform services.
    """

    logger.info("Starting platform services...")

    await startup_persistence()

    logger.info("Platform startup completed.")