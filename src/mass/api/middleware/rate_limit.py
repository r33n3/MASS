"""Rate limiting middleware.

Implements distributed rate limiting backed by Redis so the limit is
shared across all API replicas.  Falls back to a simple per-process
counter when Redis is unavailable.
"""

import logging
import time
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from mass.core.config import get_settings

logger = logging.getLogger(__name__)

# Redis key prefix for rate-limit counters
_RL_PREFIX = "mass:ratelimit:api"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for distributed rate limiting.

    Uses Redis INCR + EXPIRE for a sliding-window counter keyed by
    client identity and the current minute.  Shared across all API
    replicas so the effective limit equals the configured limit
    regardless of replica count.
    """

    def __init__(self, app):
        super().__init__(app)
        settings = get_settings()
        self.requests_per_minute = settings.api_rate_limit
        self._redis = None
        self._redis_failed = False

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    async def _get_redis(self):
        """Lazily acquire a Redis connection."""
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as aioredis
            settings = get_settings()
            self._redis = aioredis.from_url(
                settings.redis.url,
                decode_responses=True,
                socket_connect_timeout=2,
            )
            # Quick connectivity check
            await self._redis.ping()
            self._redis_failed = False
            return self._redis
        except Exception:
            self._redis = None
            if not self._redis_failed:
                logger.warning("Rate-limiter falling back to pass-through: Redis unavailable")
                self._redis_failed = True
            return None

    async def _check_rate_limit(self, client_key: str) -> tuple[bool, int]:
        """Check the rate limit for *client_key*.

        Returns (allowed, current_count).  Uses a per-minute Redis key
        with a 120-second TTL for safety.
        """
        r = await self._get_redis()
        if r is None:
            # Redis down — allow request (fail-open)
            return True, 0

        current_minute = int(time.time()) // 60
        redis_key = f"{_RL_PREFIX}:{client_key}:{current_minute}"

        try:
            count = await r.incr(redis_key)
            if count == 1:
                await r.expire(redis_key, 120)  # 2-minute TTL for safety
            remaining = max(0, self.requests_per_minute - count)
            return count <= self.requests_per_minute, remaining
        except Exception:
            # Redis error — fail open
            return True, 0

    # ------------------------------------------------------------------
    # Client identification
    # ------------------------------------------------------------------

    @staticmethod
    def _get_client_key(request: Request) -> str:
        """Get the rate limit key for a client.

        Uses API key if available, otherwise IP address.
        """
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key[:20]}"

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return f"key:{auth_header[7:27]}"

        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"

    # ------------------------------------------------------------------
    # Middleware dispatch
    # ------------------------------------------------------------------

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Check rate limits and process request."""
        # Skip rate limiting for health endpoints
        if request.url.path in {"/health", "/ready", "/metrics"}:
            return await call_next(request)

        client_key = self._get_client_key(request)
        allowed, remaining = await self._check_rate_limit(client_key)

        if not allowed:
            retry_after = 60  # Wait until next minute window
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response
