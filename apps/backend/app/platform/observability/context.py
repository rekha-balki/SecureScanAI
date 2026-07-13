"""
Request context management.

Provides request-scoped context using ContextVar.
"""

from contextvars import ContextVar
from typing import Optional

from app.platform.observability.constants import (
    CORRELATION_ID_CONTEXT,
    REQUEST_ID_CONTEXT,
)

_request_id: ContextVar[Optional[str]] = ContextVar(
    REQUEST_ID_CONTEXT,
    default=None,
)

_correlation_id: ContextVar[Optional[str]] = ContextVar(
    CORRELATION_ID_CONTEXT,
    default=None,
)


def set_request_id(request_id: str) -> None:
    """Store the current request ID."""
    _request_id.set(request_id)


def get_request_id() -> Optional[str]:
    """Return the current request ID."""
    return _request_id.get()


def clear_request_id() -> None:
    """Clear the current request ID."""
    _request_id.set(None)


def set_correlation_id(correlation_id: str) -> None:
    """Store the current correlation ID."""
    _correlation_id.set(correlation_id)


def get_correlation_id() -> Optional[str]:
    """Return the current correlation ID."""
    return _correlation_id.get()


def clear_correlation_id() -> None:
    """Clear the current correlation ID."""
    _correlation_id.set(None)


def clear_context() -> None:
    """Clear the entire request context."""
    clear_request_id()
    clear_correlation_id()