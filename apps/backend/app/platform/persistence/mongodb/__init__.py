"""
MongoDB persistence package.
"""

from .client import (
    close_client,
    get_client,
)

from .database import (
    get_database,
)

from .collections import (
    Collections,
    get_collection,
)

__all__ = [
    "get_client",
    "close_client",
    "get_database",
    "Collections",
    "get_collection",
]