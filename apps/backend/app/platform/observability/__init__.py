"""
Observability package.

Provides request context, correlation IDs,
distributed tracing and metrics support.
"""

from .constants import (
    HEADER_REQUEST_ID,
    HEADER_CORRELATION_ID,
)

__all__ = [
    "HEADER_REQUEST_ID",
    "HEADER_CORRELATION_ID",
]