"""Request logging middleware.

Logs all API requests and responses for audit and debugging.
"""

import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("mass.api")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging.

    Logs all requests with timing information and request IDs.
    """

    # Paths to exclude from logging (health checks, etc.)
    EXCLUDE_PATHS = {"/health", "/ready", "/metrics"}

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Log the request and response."""
        # Skip logging for excluded paths
        if request.url.path in self.EXCLUDE_PATHS:
            return await call_next(request)

        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Start timing
        start_time = time.perf_counter()

        # Get client info
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")

        # Log request
        logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "user_agent": user_agent,
            },
        )

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            # Log exception
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "Request failed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "duration_ms": duration_ms,
                },
            )
            raise

        # Calculate duration
        duration_ms = (time.perf_counter() - start_time) * 1000

        # Log response
        logger.info(
            "Request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        # Record metrics
        from mass.core.metrics import METRICS
        labels = {"method": request.method, "endpoint": request.url.path, "status": str(response.status_code)}
        METRICS.inc("mass_api_requests_total", labels=labels, help_text="Total API requests")
        METRICS.observe(
            "mass_api_latency_seconds",
            duration_ms / 1000,
            labels={"endpoint": request.url.path},
            help_text="API request latency in seconds",
        )

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


def get_request_id(request: Request) -> str:
    """Get the request ID from the current request."""
    return getattr(request.state, "request_id", "unknown")
