"""Exception handlers for the API.

Converts exceptions to proper HTTP responses.
"""

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from mass.core.exceptions import (
    MassError,
    ValidationError as MassValidationError,
    NotFoundError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ConfigurationError,
    ScanError,
    AnalysisError,
    StorageError,
)

logger = logging.getLogger("mass.api")


def error_response(
    status_code: int,
    error: str,
    message: str,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    """Create a standardized error response."""
    content: dict[str, Any] = {
        "error": error,
        "message": message,
    }
    if details:
        content["details"] = details
    if request_id:
        content["request_id"] = request_id

    return JSONResponse(status_code=status_code, content=content)


def setup_exception_handlers(app: FastAPI) -> None:
    """Set up exception handlers for the application."""

    @app.exception_handler(MassValidationError)
    async def mass_validation_error_handler(
        request: Request, exc: MassValidationError
    ) -> JSONResponse:
        """Handle MASS validation errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="validation_error",
            message=str(exc),
            details=exc.details if hasattr(exc, "details") else None,
            request_id=request_id,
        )

    @app.exception_handler(NotFoundError)
    async def not_found_error_handler(
        request: Request, exc: NotFoundError
    ) -> JSONResponse:
        """Handle not found errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            error="not_found",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(
        request: Request, exc: AuthenticationError
    ) -> JSONResponse:
        """Handle authentication errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="authentication_error",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(
        request: Request, exc: AuthorizationError
    ) -> JSONResponse:
        """Handle authorization errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            error="authorization_error",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(RateLimitError)
    async def rate_limit_error_handler(
        request: Request, exc: RateLimitError
    ) -> JSONResponse:
        """Handle rate limit errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error="rate_limit_exceeded",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(ConfigurationError)
    async def configuration_error_handler(
        request: Request, exc: ConfigurationError
    ) -> JSONResponse:
        """Handle configuration errors."""
        request_id = getattr(request.state, "request_id", None)
        logger.error(f"Configuration error: {exc}")
        return error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="configuration_error",
            message="Service configuration error",
            request_id=request_id,
        )

    @app.exception_handler(ScanError)
    async def scan_error_handler(
        request: Request, exc: ScanError
    ) -> JSONResponse:
        """Handle scan errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="scan_error",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(AnalysisError)
    async def analysis_error_handler(
        request: Request, exc: AnalysisError
    ) -> JSONResponse:
        """Handle analysis errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="analysis_error",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(StorageError)
    async def storage_error_handler(
        request: Request, exc: StorageError
    ) -> JSONResponse:
        """Handle storage errors."""
        request_id = getattr(request.state, "request_id", None)
        logger.error(f"Storage error: {exc}")
        return error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="storage_error",
            message="Storage operation failed",
            request_id=request_id,
        )

    @app.exception_handler(MassError)
    async def mass_error_handler(
        request: Request, exc: MassError
    ) -> JSONResponse:
        """Handle generic MASS errors."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="internal_error",
            message=str(exc),
            request_id=request_id,
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle FastAPI request validation errors."""
        request_id = getattr(request.state, "request_id", None)
        errors = []
        for error in exc.errors():
            loc = " -> ".join(str(x) for x in error["loc"])
            errors.append({"field": loc, "message": error["msg"]})

        return error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error="validation_error",
            message="Request validation failed",
            details={"errors": errors},
            request_id=request_id,
        )

    @app.exception_handler(ValidationError)
    async def pydantic_validation_error_handler(
        request: Request, exc: ValidationError
    ) -> JSONResponse:
        """Handle Pydantic validation errors."""
        request_id = getattr(request.state, "request_id", None)
        errors = []
        for error in exc.errors():
            loc = " -> ".join(str(x) for x in error["loc"])
            errors.append({"field": loc, "message": error["msg"]})

        return error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error="validation_error",
            message="Data validation failed",
            details={"errors": errors},
            request_id=request_id,
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unexpected exceptions."""
        request_id = getattr(request.state, "request_id", None)
        logger.exception(f"Unhandled exception: {exc}")
        return error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="internal_error",
            message="An unexpected error occurred",
            request_id=request_id,
        )
