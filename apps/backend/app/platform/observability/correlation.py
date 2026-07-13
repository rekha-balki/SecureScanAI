"""
Correlation ID management.

Responsible for generating and validating correlation IDs
for distributed request tracing.
"""

from uuid import uuid4

from app.platform.observability.context import (
    get_correlation_id,
    set_correlation_id,
)


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""

    return str(uuid4())


def ensure_correlation_id(existing: str | None = None) -> str:
    """
    Return a correlation ID.

    Reuses an incoming correlation ID if supplied,
    otherwise generates a new one.
    """

    correlation_id = existing or generate_correlation_id()

    set_correlation_id(correlation_id)

    return correlation_id


def current_correlation_id() -> str | None:
    """Return the current correlation ID."""

    return get_correlation_id()