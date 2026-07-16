"""
Platform shutdown orchestration.
"""

from app.platform.logging.logger import get_logger
from app.platform.persistence import shutdown_persistence

logger = get_logger(__name__)


async def shutdown_platform() -> None:
    """
    Shutdown all platform services.
    """

    logger.info("Stopping platform services...")

    await shutdown_persistence()

    logger.info("Platform shutdown completed.")