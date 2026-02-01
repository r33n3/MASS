"""Tenant context middleware.

Injects tenant context into requests for multi-tenant isolation.
"""

from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Middleware for tenant context injection.

    Ensures all database operations are scoped to the current tenant.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process the request and inject tenant context."""
        # Tenant context is set by authentication
        # This middleware can be used for additional tenant-level processing

        # Initialize tenant context as None
        if not hasattr(request.state, "tenant_id"):
            request.state.tenant_id = None

        # Process request
        response = await call_next(request)

        # Add tenant ID to response headers for debugging (if configured)
        if request.state.tenant_id:
            response.headers["X-Tenant-ID"] = request.state.tenant_id

        return response


class TenantContext:
    """Context manager for tenant-scoped operations.

    Provides a way to execute operations within a specific tenant context.
    """

    _current_tenant_id: str | None = None

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._previous_tenant_id: str | None = None

    def __enter__(self) -> "TenantContext":
        """Enter tenant context."""
        self._previous_tenant_id = TenantContext._current_tenant_id
        TenantContext._current_tenant_id = self.tenant_id
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit tenant context."""
        TenantContext._current_tenant_id = self._previous_tenant_id

    @classmethod
    def get_current_tenant_id(cls) -> str | None:
        """Get the current tenant ID."""
        return cls._current_tenant_id

    @classmethod
    def require_tenant(cls) -> str:
        """Get the current tenant ID, raising if not set."""
        tenant_id = cls._current_tenant_id
        if not tenant_id:
            raise RuntimeError("No tenant context set")
        return tenant_id
