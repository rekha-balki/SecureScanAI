"""
Persistence platform.
"""

from .lifecycle import (
    startup_persistence,
    shutdown_persistence,
)

__all__ = [
    "startup_persistence",
    "shutdown_persistence",
]