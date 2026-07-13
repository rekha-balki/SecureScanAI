from starlette.middleware.base import BaseHTTPMiddleware

from app.platform import get_logger

logger = get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every incoming request."""

    async def dispatch(self, request, call_next):

        logger.info(
            "Incoming %s %s",
            request.method,
            request.url.path,
        )

        response = await call_next(request)

        logger.info(
            "Completed %s -> %s",
            request.url.path,
            response.status_code,
        )

        return response