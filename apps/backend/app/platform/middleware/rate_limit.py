"""
Rate limiting middleware (FRS Section 15: "All APIs ... Rate Limited").

Fixed-window counter per client (IP, or user ID once authenticated)
backed by Redis. If Redis is unreachable the middleware fails open
(logs a warning, allows the request) rather than taking the API down -
availability of the platform should not depend on Redis being healthy.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config.settings import get_settings
from app.platform.logging.logger import get_logger
from app.platform.persistence.redis_store import get_redis

logger = get_logger(__name__)

_EXEMPT_PREFIXES = ("/docs", "/openapi.json", "/redoc", "/api/v1/health")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Applies a per-client requests-per-window limit to all API routes.
    """

    async def dispatch(self, request, call_next):
        settings = get_settings()

        if not settings.rate_limit_enabled or request.url.path.startswith(
            _EXEMPT_PREFIXES
        ):
            return await call_next(request)

        client_key = self._client_key(request)
        bucket = f"ratelimit:{client_key}:{request.url.path}"

        try:
            redis = get_redis()
            current = await redis.incr(bucket)
            if current == 1:
                await redis.expire(bucket, settings.rate_limit_window_seconds)
        except Exception:  # noqa: BLE001 - fail open if Redis is unavailable
            logger.warning("Rate limiter unavailable; allowing request through.")
            return await call_next(request)

        if current > settings.rate_limit_requests_per_window:
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "message": "Too many requests. Please slow down and try again shortly.",
                    "data": None,
                },
                headers={"Retry-After": str(settings.rate_limit_window_seconds)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(
            settings.rate_limit_requests_per_window
        )
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, settings.rate_limit_requests_per_window - current)
        )
        return response

    @staticmethod
    def _client_key(request) -> str:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            # Bucket authenticated users by their token rather than shared
            # IPs (offices, NAT, corporate proxies) where possible.
            return f"token:{hash(auth_header) & 0xFFFFFFFF}"

        client = request.client
        return f"ip:{client.host if client else 'unknown'}"
