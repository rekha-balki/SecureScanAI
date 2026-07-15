"""
MongoDB database provider.
"""

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.config.settings import settings
from app.platform.persistence.mongodb.client import get_client


def get_database() -> AsyncIOMotorDatabase:
    """
    Return the configured MongoDB database.
    """

    client = get_client()

    return client[settings.mongodb_database]