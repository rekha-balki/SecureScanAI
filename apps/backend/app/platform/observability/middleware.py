"""
Observability middleware.

Creates request-scoped observability context.
"""

from app.platform.observability.identifiers import (
    generate_request_id,
)

from starlette.middleware.base import BaseHTTPMiddleware

from app.platform import get_logger
from app.platform.observability.constants import (
    HEADER_CORRELATION_ID,
    HEADER_REQUEST_ID,
)
from app.platform.observability.context import (
    clear_context,
    set_request_id,
)
from app.platform.observability.correlation import (
    ensure_correlation_id,
)

logger = get_logger(__name__)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Attach request and correlation IDs to every request."""

    async def dispatch(self, request, call_next):

        request_id = generate_request_id()

        set_request_id(request_id)

        correlation_id = ensure_correlation_id(
            request.headers.get(HEADER_CORRELATION_ID)
        )

        try:
            response = await call_next(request)

            response.headers[HEADER_REQUEST_ID] = request_id
            response.headers[HEADER_CORRELATION_ID] = correlation_id

            return response

        finally:
            clear_context()