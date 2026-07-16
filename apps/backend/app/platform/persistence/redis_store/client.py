"""
Redis client provider.

Used for rate limiting (FRS Section 15) and future caching /
session-adjacent needs. Callers must tolerate Redis being unavailable
(see rate_limit middleware, which fails open).
"""

from redis.asyncio import Redis

from app.config.settings import settings

_client: Redis | None = None


def get_redis() -> Redis:
    """
    Return the singleton Redis client.
    """

    global _client

    if _client is None:
        _client = Redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )

    return _client


async def close_redis() -> None:
    """
    Close the Redis client.
    """

    global _client

    if _client is not None:
        await _client.aclose()
        _client = None
