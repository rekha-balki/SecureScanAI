"""
MongoDB client provider.
"""

from motor.motor_asyncio import AsyncIOMotorClient

from app.config.settings import settings


_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    """
    Return the singleton MongoDB client.
    """

    global _client

    if _client is None:
        _client = AsyncIOMotorClient(
            settings.mongodb_uri,
            minPoolSize=settings.mongodb_min_pool_size,
            maxPoolSize=settings.mongodb_max_pool_size,
            connectTimeoutMS=settings.mongodb_connect_timeout_ms,
            serverSelectionTimeoutMS=settings.mongodb_server_selection_timeout_ms,
        )

    return _client


def close_client() -> None:
    """
    Close the MongoDB client.
    """

    global _client

    if _client is not None:
        _client.close()
        _client = None