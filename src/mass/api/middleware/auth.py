"""Authentication middleware.

Handles API key and JWT authentication.
"""

import hashlib
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from mass.core.config import get_settings


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware for authentication processing.

    This middleware extracts authentication information from requests
    and adds it to the request state for use by dependencies.
    """

    # Paths that don't require authentication
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/api/v1/openapi.json",
    }

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process the request for authentication."""
        # Skip auth for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        # Extract API key from headers
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]

        # Store extracted key in request state for dependency injection
        request.state.api_key = api_key
        request.state.authenticated = api_key is not None

        return await call_next(request)


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage.

    Uses SHA-256 with a salt from settings.
    """
    settings = get_settings()
    salt = settings.auth.api_key_salt.encode()
    key_bytes = api_key.encode()
    return hashlib.sha256(salt + key_bytes).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (full_key, key_hash).
    """
    import secrets

    # Generate a secure random key
    key_bytes = secrets.token_bytes(32)
    full_key = f"mass_{key_bytes.hex()}"

    # Hash for storage
    key_hash = hash_api_key(full_key)

    return full_key, key_hash


def get_key_prefix(api_key: str) -> str:
    """Get the prefix of an API key for lookup.

    The prefix is used for quick lookup without storing the full key.
    """
    # Format: mass_<first 8 chars>
    if api_key.startswith("mass_"):
        return api_key[:13]  # "mass_" + 8 chars
    return api_key[:8]
