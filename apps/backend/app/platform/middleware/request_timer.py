import time

from starlette.middleware.base import BaseHTTPMiddleware

from app.platform import get_logger

logger = get_logger(__name__)


class RequestTimerMiddleware(BaseHTTPMiddleware):
    """Measure request processing time."""

    async def dispatch(self, request, call_next):

        start = time.perf_counter()

        response = await call_next(request)

        duration = round((time.perf_counter() - start) * 1000, 2)

        response.headers["X-Process-Time"] = f"{duration} ms"

        logger.info(
            "%s %s completed in %s ms",
            request.method,
            request.url.path,
            duration,
        )

        return response