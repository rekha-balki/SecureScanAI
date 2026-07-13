"""
Observability registry.

Registers observability components with the FastAPI application.
"""

from fastapi import FastAPI

from app.platform.observability.middleware import (
    ObservabilityMiddleware,
)


def register_observability(app: FastAPI) -> None:
    """Register observability middleware."""

    app.add_middleware(ObservabilityMiddleware)