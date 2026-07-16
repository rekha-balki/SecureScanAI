"""
HTTP middleware registry.

Registers all HTTP middleware used by the SecureScan AI application.
"""

from fastapi import FastAPI

from app.platform.middleware.rate_limit import RateLimitMiddleware
from app.platform.middleware.request_logging import (
    RequestLoggingMiddleware,
)
from app.platform.middleware.request_timer import (
    RequestTimerMiddleware,
)
from app.platform.middleware.security_headers import (
    SecurityHeadersMiddleware,
)


def register_http_middlewares(app: FastAPI) -> None:
    """
    Register all HTTP middleware.

    Middleware execution order (Request):
        1. Request Logging
        2. Request Timer
        3. Security Headers
        4. Rate Limiting
        5. FastAPI Routes

    Response processing happens in the reverse order.
    """

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestTimerMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)