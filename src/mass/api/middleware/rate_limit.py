"""Rate limiting middleware.

Implements token bucket rate limiting per API key/IP.
"""

import asyncio
import time
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from mass.core.config import get_settings


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, tokens_per_second: float, bucket_size: int):
        self.tokens_per_second = tokens_per_second
        self.bucket_size = bucket_size
        self.tokens = bucket_size
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket.

        Returns True if tokens were consumed, False if rate limited.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Add tokens based on elapsed time
            self.tokens = min(
                self.bucket_size,
                self.tokens + elapsed * self.tokens_per_second,
            )

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    @property
    def retry_after(self) -> float:
        """Get seconds until a token is available."""
        if self.tokens >= 1:
            return 0
        return (1 - self.tokens) / self.tokens_per_second


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting.

    Implements per-client rate limiting using token buckets.
    """

    def __init__(self, app):
        super().__init__(app)
        settings = get_settings()
        self.requests_per_minute = settings.api_rate_limit

        # Token buckets per client (API key or IP)
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(
                tokens_per_second=self.requests_per_minute / 60,
                bucket_size=self.requests_per_minute,
            )
        )

        # Cleanup task for old buckets
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.monotonic()

    def _get_client_key(self, request: Request) -> str:
        """Get the rate limit key for a client.

        Uses API key if available, otherwise IP address.
        """
        # Try API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key[:20]}"

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return f"key:{auth_header[7:27]}"

        # Fall back to IP
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"

    async def _cleanup_old_buckets(self) -> None:
        """Clean up old token buckets to prevent memory leaks."""
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now
        threshold = now - 3600  # Remove buckets unused for 1 hour

        keys_to_remove = [
            key
            for key, bucket in self._buckets.items()
            if bucket.last_update < threshold
        ]

        for key in keys_to_remove:
            del self._buckets[key]

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Check rate limits and process request."""
        # Skip rate limiting for health endpoints
        if request.url.path in {"/health", "/ready", "/metrics"}:
            return await call_next(request)

        # Get client key and bucket
        client_key = self._get_client_key(request)
        bucket = self._buckets[client_key]

        # Try to consume a token
        if not await bucket.consume():
            retry_after = int(bucket.retry_after) + 1
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(int(bucket.tokens))

        # Periodic cleanup
        await self._cleanup_old_buckets()

        return response
