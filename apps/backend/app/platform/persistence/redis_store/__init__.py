"""
Redis persistence package.
"""

from .client import get_redis, close_redis

__all__ = ["get_redis", "close_redis"]
