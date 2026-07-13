"""
Observability package.

Provides request context, correlation IDs,
distributed tracing and metrics support.
"""

from .registry import register_observability

__all__ = [
    "register_observability",
]