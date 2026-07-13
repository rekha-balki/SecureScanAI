"""
Identifier generation utilities.

Provides centralized generation of request and correlation identifiers.
"""

from uuid import uuid4


def generate_request_id() -> str:
    """Generate a unique request identifier."""

    return str(uuid4())


def generate_correlation_id() -> str:
    """Generate a unique correlation identifier."""

    return str(uuid4())